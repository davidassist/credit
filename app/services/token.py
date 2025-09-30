from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_expiry, generate_token, now_utc
from app.db import models


async def create_email_verification_token(db: AsyncSession, user_id: uuid.UUID) -> models.EmailVerifyToken:
    token = generate_token(16)
    entity = models.EmailVerifyToken(token=token, user_id=user_id, expires_at=generate_expiry(24))
    db.add(entity)
    await db.flush()
    return entity


async def verify_email_token(db: AsyncSession, token: str) -> models.EmailVerifyToken | None:
    result = await db.execute(select(models.EmailVerifyToken).where(models.EmailVerifyToken.token == token))
    entity = result.scalar_one_or_none()
    if not entity:
        return None
    if entity.expires_at < now_utc():
        return None
    return entity


async def delete_email_token(db: AsyncSession, token: str) -> None:
    await db.execute(models.EmailVerifyToken.__table__.delete().where(models.EmailVerifyToken.token == token))


async def create_password_reset_token(db: AsyncSession, user_id: uuid.UUID, expires_minutes: int = 30) -> models.PasswordResetToken:
    token = generate_token(16)
    entity = models.PasswordResetToken(
        token=token,
        user_id=user_id,
        expires_at=now_utc() + timedelta(minutes=expires_minutes),
    )
    db.add(entity)
    await db.flush()
    return entity


async def verify_password_reset_token(db: AsyncSession, token: str) -> models.PasswordResetToken | None:
    result = await db.execute(select(models.PasswordResetToken).where(models.PasswordResetToken.token == token))
    entity = result.scalar_one_or_none()
    if not entity:
        return None
    if entity.used_at is not None:
        return None
    if entity.expires_at < now_utc():
        return None
    return entity


async def mark_password_reset_used(db: AsyncSession, token: models.PasswordResetToken) -> None:
    token.used_at = now_utc()
    await db.flush()

