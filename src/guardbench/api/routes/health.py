"""Unauthenticated liveness/readiness endpoint used by container health checks."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text

from guardbench import __version__
from guardbench.api.dependencies import SessionDep, SettingsDep

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Health payload. Deliberately reveals nothing beyond coarse status."""

    status: Literal["ok", "degraded"]
    database: Literal["ok", "unavailable"]
    version: str
    dev_mode: bool
    notice: str = "Local security lab. No external server is scanned."


@router.get("/health", response_model=HealthResponse)
def health(session: SessionDep, settings: SettingsDep) -> HealthResponse:
    """Report service and database health."""
    try:
        session.execute(text("SELECT 1"))
        database: Literal["ok", "unavailable"] = "ok"
    except Exception:
        database = "unavailable"
    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        database=database,
        version=__version__,
        dev_mode=settings.dev_mode,
    )
