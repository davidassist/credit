from __future__ import annotations

from fastapi import Response

from app.core.config import settings

SESSION_COOKIE_NAME = "sid"
CSRF_COOKIE_NAME = "csrf_token"


def set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=settings.session_idle_timeout_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, httponly=True, secure=True, samesite="strict")


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=settings.session_idle_timeout_seconds,
        httponly=False,
        secure=True,
        samesite="strict",
    )

