from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

from app.core.config import settings

_PASSWORD_BLACKLIST_PATH = Path(__file__).resolve().parent.parent.parent / "resources" / "password_blacklist.txt"


def _load_blacklist() -> set[str]:
    if not _PASSWORD_BLACKLIST_PATH.exists():
        return set()
    return {line.strip() for line in _PASSWORD_BLACKLIST_PATH.read_text(encoding="utf-8").splitlines() if line.strip()}


PASSWORD_BLACKLIST = _load_blacklist()
password_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
    hash_len=32,
    salt_len=16,
)


def is_password_allowed(password: str) -> bool:
    if len(password) < 10:
        return False
    return password.lower() not in PASSWORD_BLACKLIST


def hash_password(password: str) -> str:
    if not is_password_allowed(password):
        raise ValueError("Password is too weak or disallowed")
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        password_hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False


fernet = Fernet(base64.urlsafe_b64encode(settings.totp_encryption_key.encode("utf-8")))


def encrypt_totp_secret(secret: str) -> bytes:
    return fernet.encrypt(secret.encode("utf-8"))


def decrypt_totp_secret(secret_encrypted: bytes) -> str:
    return fernet.decrypt(secret_encrypted).decode("utf-8")


def generate_token(length: int = 32) -> str:
    return secrets.token_hex(length)


def generate_expiry(hours: int = 24) -> datetime:
    return datetime.utcnow() + timedelta(hours=hours)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def now_utc() -> datetime:
    return datetime.utcnow()


def validate_sliding_timeout(last_used: datetime, timeout_seconds: int) -> bool:
    return (now_utc() - last_used).total_seconds() <= timeout_seconds

