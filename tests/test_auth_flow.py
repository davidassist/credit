from __future__ import annotations

import base64
from pathlib import Path

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select

if not Path("/var/run/docker.sock").exists():
    pytestmark = pytest.mark.skip(reason="Docker is required for integration tests")


@pytest.mark.anyio
async def test_basic_flow(client: AsyncClient, models_module, session_factory):
    models = models_module
    response = await client.post("/auth/register", json={"email": "user@example.com", "password": "Str0ngPassw0rd!"})
    assert response.status_code == 200

    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()

    verify = await client.post("/auth/verify-email", json={"token": token.token})
    assert verify.status_code == 200

    login = await client.post("/auth/login", json={"email": "user@example.com", "password": "Str0ngPassw0rd!"})
    assert login.status_code == 200
    assert login.json()["mfa_required"] is False

    csrf = await client.get("/auth/csrf")
    assert csrf.status_code == 200
    csrf_token = csrf.json()["csrf_token"]

    me = await client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "user@example.com"

    logout = await client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout.status_code == 200


@pytest.mark.anyio
async def test_totp_flow(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "totp@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
    await client.post("/auth/verify-email", json={"token": token.token})
    login = await client.post("/auth/login", json={"email": "totp@example.com", "password": "Str0ngPassw0rd!"})
    assert login.status_code == 200

    csrf = await client.get("/auth/csrf")
    csrf_token = csrf.json()["csrf_token"]

    setup = await client.post("/auth/mfa/totp/setup", headers={"X-CSRF-Token": csrf_token})
    secret = setup.json()["secret"]

    code = pyotp.TOTP(secret).now()
    verify = await client.post("/auth/mfa/totp/verify", json={"code": code}, headers={"X-CSRF-Token": csrf_token})
    assert verify.status_code == 200

    await client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})

    mfa_login = await client.post("/auth/login", json={"email": "totp@example.com", "password": "Str0ngPassw0rd!"})
    data = mfa_login.json()
    assert data["mfa_required"] is True
    challenge_id = data["challenge_id"]

    code = pyotp.TOTP(secret).now()
    finish = await client.post("/auth/mfa/totp/verify", json={"code": code, "challenge_id": challenge_id})
    assert finish.status_code == 200

    me = await client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["totp_enabled"] is True


@pytest.mark.anyio
async def test_webauthn_flow(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "webauthn@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
    await client.post("/auth/verify-email", json={"token": token.token})
    login = await client.post("/auth/login", json={"email": "webauthn@example.com", "password": "Str0ngPassw0rd!"})
    assert login.status_code == 200

    csrf = await client.get("/auth/csrf")
    csrf_token = csrf.json()["csrf_token"]

    start = await client.post("/auth/webauthn/register/start", headers={"X-CSRF-Token": csrf_token})
    challenge_id = start.json()["challenge_id"]

    finish = await client.post(
        "/auth/webauthn/register/finish",
        json={
            "challenge_id": challenge_id,
            "client_data_json": base64.b64encode(b"client").decode(),
            "attestation_object": base64.b64encode(b"attest").decode(),
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert finish.status_code == 200

    await client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})

    start_login = await client.post("/auth/webauthn/login/start", json={"email": "webauthn@example.com"})
    login_challenge = start_login.json()["challenge_id"]
    allow_credentials = start_login.json()["publicKey"]["allowCredentials"][0]["id"]

    finish_login = await client.post(
        "/auth/webauthn/login/finish",
        json={
            "challenge_id": login_challenge,
            "credential_id": allow_credentials,
            "client_data_json": base64.b64encode(b"client").decode(),
            "authenticator_data": base64.b64encode(b"auth").decode(),
            "signature": base64.b64encode(b"sig").decode(),
        },
    )
    assert finish_login.status_code == 200

    me = await client.get("/auth/me")
    assert me.status_code == 200


@pytest.mark.anyio
async def test_password_reset_flow(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "reset@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
    await client.post("/auth/verify-email", json={"token": token.token})

    await client.post("/auth/password/reset/request", json={"email": "reset@example.com"})
    async with session_factory() as session:
        reset = (await session.execute(select(models.PasswordResetToken))).scalar_one()

    await client.post(
        "/auth/password/reset/confirm",
        json={"token": reset.token, "new_password": "An0therStr0ng!"},
    )

    login = await client.post("/auth/login", json={"email": "reset@example.com", "password": "An0therStr0ng!"})
    assert login.status_code == 200


@pytest.mark.anyio
async def test_csrf_enforcement(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "csrf@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
    await client.post("/auth/verify-email", json={"token": token.token})
    await client.post("/auth/login", json={"email": "csrf@example.com", "password": "Str0ngPassw0rd!"})

    response = await client.post("/auth/logout")
    assert response.status_code == 403

    csrf = await client.get("/auth/csrf")
    csrf_token = csrf.json()["csrf_token"]
    ok = await client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert ok.status_code == 200


@pytest.mark.anyio
async def test_rate_limit_and_lockout(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "rate@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
    await client.post("/auth/verify-email", json={"token": token.token})

    for _ in range(10):
        await client.post("/auth/login", json={"email": "rate@example.com", "password": "wrongpass!!!"})

    locked = await client.post("/auth/login", json={"email": "rate@example.com", "password": "wrongpass!!!"})
    assert locked.status_code == 429


@pytest.mark.anyio
async def test_role_guard(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "admincheck@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
        user = await session.get(models.User, token.user_id)
        user.role = "user"
        await session.commit()
    await client.post("/auth/verify-email", json={"token": token.token})
    await client.post("/auth/login", json={"email": "admincheck@example.com", "password": "Str0ngPassw0rd!"})

    response = await client.get("/admin/status")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_step_up_challenge(client: AsyncClient, models_module, session_factory):
    models = models_module
    await client.post("/auth/register", json={"email": "stepup@example.com", "password": "Str0ngPassw0rd!"})
    async with session_factory() as session:
        token = (await session.execute(select(models.EmailVerifyToken))).scalar_one()
    await client.post("/auth/verify-email", json={"token": token.token})
    await client.post("/auth/login", json={"email": "stepup@example.com", "password": "Str0ngPassw0rd!"})

    resp = await client.post("/auth/step-up/check")
    assert resp.status_code == 200
    data = resp.json()
    assert data["requires_mfa"] is True
