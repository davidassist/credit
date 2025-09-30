from __future__ import annotations

import asyncio
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, optional_session, require_session
from app.core.rate_limiter import limiter
from app.core.security import generate_csrf_token, hash_password, now_utc, verify_password
from app.db import models
from app.schemas import auth as schemas
from app.services import audit, lockout, session as session_service, token as token_service
from app.services import totp as totp_service
from app.services import webauthn as webauthn_service
from app.services.challenges import create_challenge, delete_challenge, get_challenge
from app.services.email import email_service
from app.utils.cookies import clear_session_cookie, set_csrf_cookie, set_session_cookie
from app.middleware.csrf import enforce_csrf

router = APIRouter()


@router.post("/register", response_model=schemas.RegisterResponse)
@limiter.limit("5/minute")
async def register(
    payload: schemas.RegisterRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> schemas.RegisterResponse:
    existing = await db.execute(select(models.User).where(models.User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "email_in_use"})

    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "weak_password"}) from exc

    user = models.User(email=payload.email, password_hash=password_hash)
    db.add(user)
    await db.flush()

    verify = await token_service.create_email_verification_token(db, user.id)

    verification_link = f"{request.url.scheme}://{request.url.netloc}/auth/verify-email?token={verify.token}"
    background_tasks.add_task(
        email_service.send_email,
        subject="Verify your email",
        recipient=user.email,
        body=f"Click to verify your email: {verification_link}",
    )

    await audit.log_event(
        db,
        event_type="register",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    await db.commit()
    return schemas.RegisterResponse(id=user.id, email=user.email)


@router.post("/verify-email", response_model=schemas.VerifyEmailResponse)
@limiter.limit("10/minute")
async def verify_email(
    payload: schemas.VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> schemas.VerifyEmailResponse:
    token = await token_service.verify_email_token(db, payload.token)
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_token"})

    user = await db.get(models.User, token.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "user_missing"})

    user.email_verified_at = now_utc()
    await token_service.delete_email_token(db, payload.token)

    await audit.log_event(
        db,
        event_type="email.verified",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    await db.commit()
    return schemas.VerifyEmailResponse()


@router.post("/login", response_model=schemas.LoginResponse)
@limiter.limit("10/minute")
async def login(
    payload: schemas.LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> schemas.LoginResponse:
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent")

    if await lockout.is_locked(payload.email, client_ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": "account_locked"})

    result = await db.execute(select(models.User).where(models.User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.password_hash):
        attempts = await lockout.register_failure(payload.email, client_ip)
        await audit.log_event(
            db,
            event_type="login.failed",
            user_id=str(user.id) if user else None,
            ip=client_ip,
            user_agent=user_agent,
            meta={"reason": "invalid_credentials"},
        )
        await db.commit()
        await asyncio.sleep(lockout.calculate_backoff(attempts))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "invalid_credentials"})

    await lockout.clear_failures(payload.email, client_ip)

    methods: list[str] = []
    if user.totp_enabled:
        methods.append("totp")
    webauthn_credentials = await db.execute(
        select(models.WebAuthnCredential).where(models.WebAuthnCredential.user_id == user.id)
    )
    has_webauthn = bool(webauthn_credentials.scalars().all())
    if has_webauthn:
        methods.append("webauthn")

    if methods:
        webauthn_data = None
        if "webauthn" in methods:
            try:
                options = await webauthn_service.start_login(db, user)
                webauthn_data = schemas.WebAuthnStartResponse(**options)
            except ValueError:
                methods.remove("webauthn")
        challenge_id = await create_challenge(
            {
                "type": "mfa_login",
                "user_id": str(user.id),
                "methods": methods,
                "ip": client_ip,
                "user_agent": user_agent,
            }
        )
        await audit.log_event(
            db,
            event_type="login.mfa_required",
            user_id=str(user.id),
            ip=client_ip,
            user_agent=user_agent,
            meta={"methods": methods},
        )
        await db.commit()
        return schemas.LoginResponse(mfa_required=True, methods=methods, challenge_id=challenge_id, webauthn=webauthn_data)

    session_obj = await session_service.create_session(
        db,
        user_id=user.id,
        ip=client_ip,
        user_agent=user_agent,
        mark_mfa=False,
    )
    set_session_cookie(response, str(session_obj.id))
    set_csrf_cookie(response, session_obj.csrf_token)

    await audit.log_event(
        db,
        event_type="login.success",
        user_id=str(user.id),
        ip=client_ip,
        user_agent=user_agent,
    )
    await db.commit()
    return schemas.LoginResponse()


@router.get("/me", response_model=schemas.UserResponse)
async def me(current: tuple[models.User, models.Session] = Depends(require_session)) -> schemas.UserResponse:
    user, _ = current
    return schemas.UserResponse(
        id=user.id,
        email=user.email,
        email_verified=bool(user.email_verified_at),
        role=user.role,
        totp_enabled=user.totp_enabled,
    )


@router.get("/csrf", response_model=schemas.CSRFTokenResponse)
async def csrf_token(
    response: Response,
    current: tuple[models.User, models.Session] = Depends(require_session),
) -> schemas.CSRFTokenResponse:
    _, session_obj = current
    token = session_obj.csrf_token or generate_csrf_token()
    session_obj.csrf_token = token
    set_csrf_cookie(response, token)
    return schemas.CSRFTokenResponse(csrf_token=token)


@router.post("/mfa/totp/setup", response_model=schemas.TOTPSetupResponse)
async def setup_totp(
    request: Request,
    response: Response,
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(enforce_csrf),
) -> schemas.TOTPSetupResponse:
    user, session_obj = current
    secret = totp_service.generate_totp_secret()
    await totp_service.set_user_totp_secret(db, user.id, secret)
    provisioning_uri = totp_service.build_totp_uri(secret, user.email, issuer="SecureAuthService")
    await audit.log_event(
        db,
        event_type="mfa.totp.setup",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        meta={"action": "setup"},
    )
    await db.commit()
    return schemas.TOTPSetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/mfa/totp/verify", response_model=schemas.MFACompletionResponse)
async def verify_totp(
    payload: schemas.TOTPVerifyRequest,
    response: Response,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: Optional[tuple[models.User, models.Session]] = Depends(optional_session),
) -> schemas.MFACompletionResponse:
    user = None
    session_obj = None
    challenge_data = None

    if payload.challenge_id:
        challenge_data = await get_challenge(payload.challenge_id)
        if not challenge_data or challenge_data.get("type") not in {"mfa_login"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_challenge"})
        user = await db.get(models.User, uuid.UUID(challenge_data["user_id"]))
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "user_missing"})
    elif current:
        user, session_obj = current
        await enforce_csrf(request)
    elif payload.email:
        result = await db.execute(select(models.User).where(models.User.email == payload.email))
        user = result.scalar_one_or_none()
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "user_unknown"})

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "user_missing"})

    secret = await totp_service.get_user_totp_secret(db, user.id)
    if not secret or not totp_service.verify_totp(secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_code"})

    if payload.challenge_id:
        await delete_challenge(payload.challenge_id)
        session_obj = await session_service.create_session(
            db,
            user_id=user.id,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            mark_mfa=True,
        )
        set_session_cookie(response, str(session_obj.id))
        set_csrf_cookie(response, session_obj.csrf_token)
    elif session_obj:
        user.totp_enabled = True
        await session_service.mark_mfa(session_obj)

    await audit.log_event(
        db,
        event_type="mfa.totp.verified",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await db.commit()
    return schemas.MFACompletionResponse(success=True)


@router.post("/mfa/totp/disable", response_model=schemas.MFACompletionResponse)
async def disable_totp(
    request: Request,
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(enforce_csrf),
) -> schemas.MFACompletionResponse:
    user, session_obj = current
    await audit.log_event(
        db,
        event_type="mfa.totp.disabled",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await db.execute(models.TotpSecret.__table__.delete().where(models.TotpSecret.user_id == user.id))
    await db.flush()
    user.totp_enabled = False
    await session_service.mark_mfa(session_obj)
    await db.commit()
    return schemas.MFACompletionResponse(success=True)


@router.post("/webauthn/register/start", response_model=schemas.WebAuthnStartResponse)
async def webauthn_register_start(
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(enforce_csrf),
) -> schemas.WebAuthnStartResponse:
    user, _ = current
    data = await webauthn_service.start_registration(db, user)
    return schemas.WebAuthnStartResponse(**data)


@router.post("/webauthn/register/finish", response_model=schemas.MFACompletionResponse)
async def webauthn_register_finish(
    payload: schemas.WebAuthnRegisterFinishRequest,
    request: Request,
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(enforce_csrf),
) -> schemas.MFACompletionResponse:
    user, session_obj = current
    try:
        await webauthn_service.finish_registration(
            db,
            challenge_id=payload.challenge_id,
            client_data_json=payload.client_data_json,
            attestation_object=payload.attestation_object,
            transports=payload.transports,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_challenge"}) from exc

    await audit.log_event(
        db,
        event_type="mfa.webauthn.registered",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await session_service.mark_mfa(session_obj)
    await db.commit()
    return schemas.MFACompletionResponse(success=True)


@router.post("/webauthn/login/start", response_model=schemas.WebAuthnStartResponse)
@limiter.limit("10/minute")
async def webauthn_login_start(
    payload: schemas.WebAuthnLoginStartRequest,
    db: AsyncSession = Depends(get_db),
) -> schemas.WebAuthnStartResponse:
    result = await db.execute(select(models.User).where(models.User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "user_missing"})
    data = await webauthn_service.start_login(db, user)
    return schemas.WebAuthnStartResponse(**data)


@router.post("/webauthn/login/finish", response_model=schemas.MFACompletionResponse)
@limiter.limit("10/minute")
async def webauthn_login_finish(
    payload: schemas.WebAuthnLoginFinishRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> schemas.MFACompletionResponse:
    try:
        credential = await webauthn_service.finish_login(
            db,
            challenge_id=payload.challenge_id,
            credential_id=payload.credential_id,
            client_data_json=payload.client_data_json,
            authenticator_data=payload.authenticator_data,
            signature=payload.signature,
            user_handle=payload.user_handle,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_challenge"}) from exc

    session_obj = await session_service.create_session(
        db,
        user_id=credential.user_id,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        mark_mfa=True,
    )
    set_session_cookie(response, str(session_obj.id))
    set_csrf_cookie(response, session_obj.csrf_token)
    await audit.log_event(
        db,
        event_type="login.success",
        user_id=str(credential.user_id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        meta={"method": "webauthn"},
    )
    await db.commit()
    return schemas.MFACompletionResponse(success=True)


@router.post("/password/reset/request", response_model=schemas.SimpleResponse)
@limiter.limit("5/minute")
async def password_reset_request(
    payload: schemas.PasswordResetRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> schemas.SimpleResponse:
    result = await db.execute(select(models.User).where(models.User.email == payload.email))
    user = result.scalar_one_or_none()
    if user:
        token = await token_service.create_password_reset_token(db, user.id)
        reset_link = f"{request.url.scheme}://{request.url.netloc}/reset?token={token.token}"
        background_tasks.add_task(
            email_service.send_email,
            subject="Password reset",
            recipient=user.email,
            body=f"Reset your password: {reset_link}",
        )
        await audit.log_event(
            db,
            event_type="password.reset.request",
            user_id=str(user.id),
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    await db.commit()
    return schemas.SimpleResponse(ok=True)


@router.post("/password/reset/confirm", response_model=schemas.SimpleResponse)
@limiter.limit("5/minute")
async def password_reset_confirm(
    payload: schemas.PasswordResetConfirmRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> schemas.SimpleResponse:
    token = await token_service.verify_password_reset_token(db, payload.token)
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_token"})

    user = await db.get(models.User, token.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "user_missing"})

    try:
        user.password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "weak_password"}) from exc

    await token_service.mark_password_reset_used(db, token)
    await db.execute(
        models.Session.__table__.delete().where(models.Session.user_id == user.id)
    )
    await audit.log_event(
        db,
        event_type="password.reset.confirm",
        user_id=str(user.id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    await db.commit()
    return schemas.SimpleResponse(ok=True)


@router.get("/sessions", response_model=schemas.SessionsResponse)
async def list_sessions(
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> schemas.SessionsResponse:
    user, session_obj = current
    sessions = await session_service.list_user_sessions(db, user.id)
    return schemas.SessionsResponse(
        sessions=[
            schemas.SessionInfo(
                id=s.id,
                created_at=s.created_at,
                last_used_at=s.last_used_at,
                ip=s.ip,
                user_agent=s.user_agent,
                current=s.id == session_obj.id,
            )
            for s in sessions
        ]
    )


@router.post("/logout", response_model=schemas.SimpleResponse)
async def logout(
    response: Response,
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(enforce_csrf),
) -> schemas.SimpleResponse:
    user, session_obj = current
    await session_service.revoke_session(db, session_obj)
    clear_session_cookie(response)
    await audit.log_event(
        db,
        event_type="logout",
        user_id=str(user.id),
        ip=None,
        user_agent=None,
    )
    await db.commit()
    return schemas.SimpleResponse(ok=True)


@router.post("/sessions/revoke-others", response_model=schemas.SimpleResponse)
async def revoke_other_sessions(
    response: Response,
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(enforce_csrf),
) -> schemas.SimpleResponse:
    user, session_obj = current
    await session_service.revoke_other_sessions(db, user.id, session_obj.id)
    set_session_cookie(response, str(session_obj.id))
    await audit.log_event(
        db,
        event_type="sessions.revoked",
        user_id=str(user.id),
        ip=None,
        user_agent=None,
    )
    await db.commit()
    return schemas.SimpleResponse(ok=True)


@router.post("/step-up/check", response_model=schemas.StepUpCheckResponse)
async def step_up_check(
    current: tuple[models.User, models.Session] = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> schemas.StepUpCheckResponse:
    user, session_obj = current
    requires = True
    methods: list[str] = []
    if session_obj.last_mfa_at and (now_utc() - session_obj.last_mfa_at).total_seconds() < 300:
        requires = False
    else:
        if user.totp_enabled:
            methods.append("totp")
        credentials = await db.execute(
            select(models.WebAuthnCredential.id).where(models.WebAuthnCredential.user_id == user.id)
        )
        if credentials.first():
            methods.append("webauthn")
    return schemas.StepUpCheckResponse(requires_mfa=requires, methods=methods)

