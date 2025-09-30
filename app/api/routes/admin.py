from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import require_role
from app.schemas.auth import SimpleResponse

router = APIRouter()


@router.get("/status", response_model=SimpleResponse)
async def admin_status(_: tuple = Depends(require_role("admin"))) -> SimpleResponse:
    return SimpleResponse(ok=True)

