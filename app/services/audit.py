from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import now_utc
from app.db import models


async def log_event(
    session: AsyncSession,
    *,
    event_type: str,
    user_id: Optional[str],
    ip: Optional[str],
    user_agent: Optional[str],
    meta: Optional[dict[str, Any]] = None,
) -> None:
    audit = models.AuditLog(
        user_id=user_id,
        type=event_type,
        ip=ip,
        user_agent=user_agent,
        created_at=now_utc(),
        meta=meta or {},
    )
    session.add(audit)
    await session.flush()
