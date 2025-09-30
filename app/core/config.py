from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseSettings, EmailStr, Field, PostgresDsn, validator


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR.parent / ".env")


class Settings(BaseSettings):
    app_name: str = "SecureAuthService"
    environment: str = Field("development", env="ENVIRONMENT")
    secret_key: str
    csrf_secret: str
    frontend_origin: str = "http://localhost:3000"

    database_url: PostgresDsn
    redis_url: str = "redis://redis:6379/0"

    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: EmailStr = EmailStr("no-reply@example.com")

    rate_limit_requests: int = 50
    rate_limit_window_seconds: int = 600

    session_idle_timeout_seconds: int = 900

    argon2_time_cost: int = 3
    argon2_memory_cost: int = 19456
    argon2_parallelism: int = 2

    totp_encryption_key: str
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "SecureAuthService"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

    @validator("frontend_origin")
    def strip_trailing_slash(cls, value: str) -> str:  # noqa: N805
        return value.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
