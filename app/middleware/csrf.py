from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from app.utils.cookies import CSRF_COOKIE_NAME


async def enforce_csrf(request: Request) -> None:
    header_token = request.headers.get("X-CSRF-Token")
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not header_token or not cookie_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "csrf_missing"})
    if not hmac.compare_digest(header_token, cookie_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "csrf_mismatch"})

