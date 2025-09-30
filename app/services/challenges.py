from __future__ import annotations

import json
from typing import Any

from app.core.security import generate_token
from app.utils.redis import redis_client

CHALLENGE_PREFIX = "auth:challenge:"
CHALLENGE_TTL_SECONDS = 300


async def create_challenge(data: dict[str, Any]) -> str:
    challenge_id = generate_token(8)
    key = CHALLENGE_PREFIX + challenge_id
    payload = json.dumps(data)
    await redis_client.set(key, payload, ex=CHALLENGE_TTL_SECONDS)
    return challenge_id


async def get_challenge(challenge_id: str) -> dict[str, Any] | None:
    payload = await redis_client.get(CHALLENGE_PREFIX + challenge_id)
    if not payload:
        return None
    return json.loads(payload)


async def delete_challenge(challenge_id: str) -> None:
    await redis_client.delete(CHALLENGE_PREFIX + challenge_id)

