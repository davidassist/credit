from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings


def get_engine():
    return create_async_engine(settings.database_url, future=True, echo=False, pool_pre_ping=True)


engine = get_engine()
async_session_factory = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    async with async_session_factory() as session:
        yield session
