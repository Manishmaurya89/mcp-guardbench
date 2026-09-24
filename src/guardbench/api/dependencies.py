"""FastAPI dependencies: settings, database session, and API-key authentication."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from guardbench.config import Settings
from guardbench.runtime.redaction import Redactor


def get_settings(request: Request) -> Settings:
    """Settings attached to the running app (overridable in tests)."""
    settings: Settings = request.app.state.settings
    return settings


def get_session(request: Request) -> Iterator[Session]:
    """A database session per request.

    Routes commit explicitly through the service layer; this dependency only guarantees
    rollback-and-close, so a client never observes a response before its data is durable.
    """
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def get_redactor(request: Request) -> Redactor:
    """The redactor applied to everything the API returns."""
    redactor: Redactor = request.app.state.redactor
    return redactor


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """Enforce the API key unless dev mode is on. Fails closed when no key is configured."""
    if settings.dev_mode:
        return
    expected = settings.api_key_value
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "API key not configured. Set GUARDBENCH_API_KEY, or GUARDBENCH_DEV_MODE=true for local use."
            ),
        )
    if x_api_key is None or not secrets.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid X-API-Key.")


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
RedactorDep = Annotated[Redactor, Depends(get_redactor)]
AuthDep = Depends(require_api_key)
