from __future__ import annotations

import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_totp_secret, encrypt_totp_secret
from app.db import models


async def get_user_totp_secret(db: AsyncSession, user_id) -> str | None:
    result = await db.execute(select(models.TotpSecret).where(models.TotpSecret.user_id == user_id))
    totp = result.scalar_one_or_none()
    if totp:
        return decrypt_totp_secret(totp.secret_encrypted)
    return None


async def set_user_totp_secret(db: AsyncSession, user_id, secret: str) -> None:
    encrypted = encrypt_totp_secret(secret)
    existing = await db.get(models.TotpSecret, user_id)
    if existing:
        existing.secret_encrypted = encrypted
    else:
        db.add(models.TotpSecret(user_id=user_id, secret_encrypted=encrypted))
    await db.flush()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_totp_uri(secret: str, email: str, issuer: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

