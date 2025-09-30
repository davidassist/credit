from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import generate_csrf_token, now_utc, validate_sliding_timeout
from app.db import models


async def create_session(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    ip: Optional[str],
    user_agent: Optional[str],
    mark_mfa: bool = False,
) -> models.Session:
    session = models.Session(
        user_id=user_id,
        ip=ip,
        user_agent=user_agent,
        csrf_token=generate_csrf_token(),
        last_mfa_at=now_utc() if mark_mfa else None,
    )
    db.add(session)
    await db.flush()
    return session


async def get_session(db: AsyncSession, session_id: uuid.UUID) -> Optional[models.Session]:
    result = await db.execute(
        select(models.Session)
        .where(models.Session.id == session_id)
        .options(selectinload(models.Session.user))
    )
    return result.scalar_one_or_none()


async def touch_session(session_obj: models.Session) -> None:
    session_obj.last_used_at = now_utc()


async def revoke_session(db: AsyncSession, session_obj: models.Session) -> None:
    await db.delete(session_obj)


async def revoke_other_sessions(db: AsyncSession, user_id: uuid.UUID, exclude: uuid.UUID) -> None:
    await db.execute(
        models.Session.__table__.delete().where(
            models.Session.user_id == user_id, models.Session.id != exclude
        )
    )


async def list_user_sessions(db: AsyncSession, user_id: uuid.UUID) -> list[models.Session]:
    result = await db.execute(
        select(models.Session).where(models.Session.user_id == user_id).order_by(models.Session.created_at.desc())
    )
    return result.scalars().all()


def is_session_active(session_obj: models.Session) -> bool:
    return validate_sliding_timeout(session_obj.last_used_at, settings.session_idle_timeout_seconds)


async def mark_mfa(session_obj: models.Session) -> None:
    session_obj.last_mfa_at = now_utc()

