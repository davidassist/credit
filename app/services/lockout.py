from __future__ import annotations

import math

from app.utils.redis import redis_client

LOCKOUT_THRESHOLD = 10
LOCKOUT_WINDOW_SECONDS = 900


def _key(user_identifier: str, ip: str) -> str:
    return f"auth:lockout:{user_identifier}:{ip}"


async def register_failure(user_identifier: str, ip: str) -> int:
    key = _key(user_identifier, ip)
    count = await redis_client.incr(key)
    if count == 1:
        await redis_client.expire(key, LOCKOUT_WINDOW_SECONDS)
    return count


async def clear_failures(user_identifier: str, ip: str) -> None:
    await redis_client.delete(_key(user_identifier, ip))


async def is_locked(user_identifier: str, ip: str) -> bool:
    count = await redis_client.get(_key(user_identifier, ip))
    if count is None:
        return False
    return int(count) >= LOCKOUT_THRESHOLD


def calculate_backoff(count: int) -> float:
    return min(5.0, math.pow(2, max(0, count - 1)) * 0.5)
