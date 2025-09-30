from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models
from app.db.session import get_session
from app.services import session as session_service
from app.utils.cookies import SESSION_COOKIE_NAME, set_csrf_cookie, set_session_cookie


async def get_db() -> AsyncSession:
    async with get_session() as session:
        yield session


async def require_session(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> tuple[models.User, models.Session]:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "session_missing"})
    try:
        session_id = uuid.UUID(sid)
    except ValueError as exc:  # noqa: ASYNC109
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "session_invalid"}) from exc

    session_obj = await session_service.get_session(db, session_id)
    if not session_obj or not session_obj.user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "session_invalid"})

    if not session_service.is_session_active(session_obj):
        await session_service.revoke_session(db, session_obj)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "session_expired"})

    await session_service.touch_session(session_obj)
    set_session_cookie(response, str(session_obj.id))
    if session_obj.csrf_token:
        set_csrf_cookie(response, session_obj.csrf_token)

    return session_obj.user, session_obj


def require_role(required_role: str):
    role_hierarchy = {"user": 1, "staff": 2, "admin": 3}

    async def dependency(
        current: tuple[models.User, models.Session] = Depends(require_session),
    ) -> tuple[models.User, models.Session]:
        user, session_obj = current
        if role_hierarchy.get(user.role, 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "insufficient_role"})
        return user, session_obj

    return dependency


async def optional_session(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> tuple[models.User, models.Session] | None:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
        return None
    try:
        session_id = uuid.UUID(sid)
    except ValueError:
        return None
    session_obj = await session_service.get_session(db, session_id)
    if not session_obj or not session_service.is_session_active(session_obj):
        return None
    await session_service.touch_session(session_obj)
    set_session_cookie(response, str(session_obj.id))
    if session_obj.csrf_token:
        set_csrf_cookie(response, session_obj.csrf_token)
    return session_obj.user, session_obj

