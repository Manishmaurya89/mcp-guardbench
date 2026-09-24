"""Shared pytest fixtures.

The suite runs with outbound networking disabled: any attempt to open a socket
connection raises immediately, which enforces the lab's "no external network" rule.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from guardbench.api.main import create_app
from guardbench.config import Settings
from guardbench.db.base import Base
from guardbench.db.session import create_all_tables, create_db_engine, create_session_factory

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_CASES_DIR = REPO_ROOT / "test_cases"


class NetworkAccessError(RuntimeError):
    """Raised when code under test tries to use the network."""


@pytest.fixture
def network_error() -> type[Exception]:
    """The exception raised on network access (a fixture avoids importing conftest twice)."""
    return NetworkAccessError


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly on any outbound connection attempt."""

    def _deny(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkAccessError("network access is forbidden in the GuardBench test suite")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


def make_settings(tmp_path: Path | None = None, **overrides: Any) -> Settings:
    """Settings for tests: in-memory SQLite, dev mode on, ``.env`` ignored."""
    values: dict[str, Any] = {
        "dev_mode": True,
        "database_url": "sqlite:///:memory:",
        "log_json": False,
        "log_level": "WARNING",
        "test_cases_dir": TEST_CASES_DIR,
        "reports_dir": (tmp_path or Path("reports")),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Default test settings."""
    return make_settings(tmp_path)


@pytest.fixture
def engine() -> Iterator[Engine]:
    """A fresh database with the full schema.

    In-memory SQLite by default. Set ``GUARDBENCH_TEST_DATABASE_URL`` (for example through
    ``scripts/test_postgres.py``) to run the same tests against a real PostgreSQL instead; the
    schema is dropped and recreated for every test.
    """
    url = os.environ.get("GUARDBENCH_TEST_DATABASE_URL")
    eng = create_db_engine(url or "sqlite:///:memory:")
    if url:
        Base.metadata.drop_all(eng)
    create_all_tables(eng)
    yield eng
    if url:
        Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Session factory bound to the test engine."""
    return create_session_factory(engine)


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """One session for a test; rolled back and closed afterwards."""
    s = session_factory()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture
def app_factory(engine: Engine, tmp_path: Path) -> Callable[..., Any]:
    """Build an app on the shared test engine with overridable settings."""

    def build(**overrides: Any) -> Any:
        return create_app(make_settings(tmp_path, **overrides), engine=engine)

    return build


@pytest.fixture
def client(app_factory: Callable[..., Any]) -> Iterator[TestClient]:
    """API test client in dev mode (lifespan runs, so tables exist)."""
    with TestClient(app_factory()) as c:
        yield c
