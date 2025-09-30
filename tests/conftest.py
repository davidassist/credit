from __future__ import annotations

import asyncio
import base64
import os
import sys
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from alembic import command
from alembic.config import Config
from httpx import AsyncClient
from sqlalchemy import text

from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def postgres_container():
    with PostgresContainer("postgres:15-alpine") as pg:
        pg.start()
        yield pg


@pytest.fixture(scope="session")
def redis_container():
    with RedisContainer("redis:7-alpine") as rd:
        rd.start()
        yield rd


@pytest.fixture(scope="session", autouse=True)
def configure_environment(postgres_container, redis_container):
    async_dsn = postgres_container.get_connection_url().replace("postgresql://", "postgresql+asyncpg://")
    redis_url = redis_container.get_connection_url()

    os.environ.setdefault("SECRET_KEY", "testsecretkey12345678901234567890")
    os.environ.setdefault("CSRF_SECRET", "csrfsecretkey12345678901234567890")
    os.environ.setdefault("TOTP_ENCRYPTION_KEY", "totpencryptionkey1234567890123456")
    os.environ.setdefault("DATABASE_URL", async_dsn)
    os.environ.setdefault("REDIS_URL", redis_url)
    os.environ.setdefault("SMTP_HOST", "localhost")
    os.environ.setdefault("SMTP_PORT", "1025")
    os.environ.setdefault("SMTP_FROM_EMAIL", "no-reply@example.com")
    os.environ.setdefault("FRONTEND_ORIGIN", "http://localhost:3000")
    os.environ.setdefault("ENVIRONMENT", "test")

    from app.core.config import settings  # noqa: WPS433

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")

    yield

    command.downgrade(cfg, "base")


@pytest.fixture(autouse=True)
def patch_email(monkeypatch):
    from app.services.email import email_service  # noqa: WPS433

    async def fake_send_email(*args, **kwargs):  # noqa: WPS430
        return None

    monkeypatch.setattr(email_service, "send_email", fake_send_email)


@pytest.fixture(autouse=True)
def patch_webauthn(monkeypatch):
    from app.db import models  # noqa: WPS433
    from app.services import webauthn as webauthn_service  # noqa: WPS433

    challenge_state: dict[str, dict[str, str]] = {}

    async def fake_start_registration(db, user):
        challenge_id = f"register:{user.id}"
        challenge_state[challenge_id] = {"user_id": str(user.id)}
        return {"challenge_id": challenge_id, "publicKey": {"challenge": "dummy"}}

    async def fake_finish_registration(db, challenge_id, **kwargs):
        data = challenge_state.pop(challenge_id)
        credential_id = uuid.uuid4().bytes
        credential = models.WebAuthnCredential(
            id=credential_id,
            user_id=uuid.UUID(data["user_id"]),
            public_key=b"fake-public-key",
            sign_count=0,
            transports="internal",
        )
        db.add(credential)
        await db.flush()
        return credential

    async def fake_start_login(db, user):
        result = await db.execute(
            models.WebAuthnCredential.__table__.select().where(models.WebAuthnCredential.user_id == user.id)
        )
        row = result.first()
        if not row:
            raise ValueError("No credentials available")
        credential_id = row.id
        challenge_id = f"login:{credential_id.hex()}"
        challenge_state[challenge_id] = {"credential_id": credential_id.hex()}
        credential_b64 = base64.urlsafe_b64encode(credential_id).decode("utf-8").rstrip("=")
        return {"challenge_id": challenge_id, "publicKey": {"allowCredentials": [{"id": credential_b64}]}}

    async def fake_finish_login(db, challenge_id, credential_id, **kwargs):
        data = challenge_state.pop(challenge_id)
        stored_id = bytes.fromhex(data["credential_id"])
        credential = await db.get(models.WebAuthnCredential, stored_id)
        if not credential:
            raise ValueError("Unknown credential")
        return credential

    monkeypatch.setattr(webauthn_service, "start_registration", fake_start_registration)
    monkeypatch.setattr(webauthn_service, "finish_registration", fake_finish_registration)
    monkeypatch.setattr(webauthn_service, "start_login", fake_start_login)
    monkeypatch.setattr(webauthn_service, "finish_login", fake_finish_login)


@pytest.fixture(autouse=True)
async def clear_state():
    from app.db.session import async_session_factory  # noqa: WPS433
    from app.utils.redis import redis_client  # noqa: WPS433

    yield

    async with async_session_factory() as session:
        await session.execute(text(
            "TRUNCATE TABLE audit_logs, webauthn_credentials, totp_secrets, password_reset_tokens, "
            "email_verify_tokens, sessions, users RESTART IDENTITY CASCADE"
        ))
        await session.commit()
    await redis_client.flushall()


@pytest.fixture
async def client(configure_environment):
    from app.main import app  # noqa: WPS433

    async with AsyncClient(app=app, base_url="http://testserver") as async_client:
        yield async_client


@pytest.fixture
def models_module(configure_environment):
    from app.db import models  # noqa: WPS433

    return models


@pytest.fixture
def session_factory(configure_environment):
    from app.db.session import async_session_factory  # noqa: WPS433

    return async_session_factory

