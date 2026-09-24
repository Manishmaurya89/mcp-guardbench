"""Settings defaults and database model behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from guardbench.config import Settings
from guardbench.db import models
from guardbench.db.session import create_db_engine, normalize_database_url, session_scope


def test_defaults_are_secure(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("GUARDBENCH_DEV_MODE", "GUARDBENCH_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    s = Settings(_env_file=None)
    assert s.dev_mode is False
    assert s.api_key_value is None
    assert s.api_host == "127.0.0.1"  # loopback by default, never 0.0.0.0


def test_environment_overrides_and_secret_is_not_repr_leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDBENCH_API_KEY", "k-local-lab-value")
    monkeypatch.setenv("GUARDBENCH_MAX_CALLS_PER_TRACE", "3")
    s = Settings(_env_file=None)
    assert s.api_key_value == "k-local-lab-value"
    assert "k-local-lab-value" not in repr(s)
    assert s.max_calls_per_trace == 3


def test_invalid_settings_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, log_level="LOUD")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, max_response_bytes=10)


def test_database_url_normalization() -> None:
    assert normalize_database_url("postgresql://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("sqlite:///x.db") == "sqlite:///x.db"


def test_sqlite_file_database_creates_parent_directory(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "gb.db"
    engine = create_db_engine(f"sqlite:///{target}")
    engine.connect().close()
    assert target.parent.is_dir()


def test_timestamps_round_trip_as_aware_utc(session: Session) -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    project = models.Project(name="p1", description="", created_at=datetime(2026, 1, 1, 12, 0, tzinfo=ist))
    session.add(project)
    session.commit()
    session.expire_all()
    loaded = session.get(models.Project, project.id)
    assert loaded is not None
    assert loaded.created_at.tzinfo is not None
    assert loaded.created_at == datetime(2026, 1, 1, 6, 30, tzinfo=UTC)


def test_naive_datetimes_are_treated_as_utc(session: Session) -> None:
    project = models.Project(name="p2", description="", created_at=datetime(2026, 5, 5, 1, 2, 3))
    session.add(project)
    session.commit()
    session.expire_all()
    loaded = session.get(models.Project, project.id)
    assert loaded is not None
    assert loaded.created_at == datetime(2026, 5, 5, 1, 2, 3, tzinfo=UTC)


def test_json_columns_round_trip_nested_structures(session: Session) -> None:
    project = models.Project(name="p3", description="")
    server = models.MCPServer(
        project=project,
        name="s",
        transport="in_memory",
        endpoint="fixture://clean_server",
        source_type="local_fixture",
    )
    tool = models.ToolDefinition(
        server=server,
        name="t",
        input_schema={"type": "object", "properties": {"a": {"enum": ["x", "y"]}}},
        annotations={"readOnlyHint": True},
        capabilities=["read"],
        definition_hash="0" * 64,
    )
    session.add_all([project, server, tool])
    session.commit()
    session.expire_all()
    loaded = session.scalars(select(models.ToolDefinition)).one()
    assert loaded.input_schema["properties"]["a"]["enum"] == ["x", "y"]
    assert loaded.capabilities == ["read"]
    assert loaded.approval_status == "pending"


def test_unique_project_names_and_cascade_delete(session: Session) -> None:
    project = models.Project(name="dup", description="")
    session.add(project)
    server = models.MCPServer(
        project=project, name="s", transport="in_memory", endpoint="fixture://x", source_type="local_fixture"
    )
    session.add(server)
    session.commit()

    session.add(models.Project(name="dup", description=""))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    session.delete(project)
    session.commit()
    assert session.scalars(select(models.MCPServer)).all() == []


def test_session_scope_rolls_back_on_error(session_factory: sessionmaker[Session]) -> None:
    def failing_unit_of_work() -> None:
        with session_scope(session_factory) as s:
            s.add(models.Project(name="ghost", description=""))
            s.flush()
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        failing_unit_of_work()
    with session_scope(session_factory) as s:
        assert s.scalars(select(models.Project).where(models.Project.name == "ghost")).first() is None
