"""Alembic migrations must match the ORM models and work on both supported dialects."""

from __future__ import annotations

import io
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect

from guardbench.db import models  # noqa: F401  (registers tables)
from guardbench.db.base import Base
from guardbench.db.migrate import alembic_config, upgrade_to_head
from guardbench.db.session import create_db_engine


def test_upgrade_creates_every_model_table_and_matches_metadata(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    upgrade_to_head(url)

    engine = create_db_engine(url)
    tables = set(inspect(engine).get_table_names())
    assert tables == set(Base.metadata.tables) | {"alembic_version"}

    with engine.connect() as connection:
        diffs = compare_metadata(
            MigrationContext.configure(connection, opts={"compare_type": True}), Base.metadata
        )
    assert diffs == [], f"migration and models have drifted apart: {diffs}"


def test_required_indexes_exist_after_migration(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'idx.db'}"
    upgrade_to_head(url)
    inspector = inspect(create_db_engine(url))

    def indexed_columns(table: str) -> set[str]:
        return {c for idx in inspector.get_indexes(table) for c in idx["column_names"]}

    assert {"run_id", "trace_id", "event_type", "timestamp"} <= indexed_columns("events")
    assert {"run_id", "severity", "created_at", "server_id"} <= indexed_columns("findings")
    assert "server_id" in indexed_columns("tool_definitions")
    assert "server_id" in indexed_columns("tool_snapshots")


def test_downgrade_removes_all_tables(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'down.db'}"
    upgrade_to_head(url)
    command.downgrade(alembic_config(url), "base")
    assert set(inspect(create_db_engine(url)).get_table_names()) <= {"alembic_version"}


def test_postgres_ddl_renders_native_types_in_offline_mode() -> None:
    config = alembic_config("postgresql://guardbench:x@localhost/guardbench")
    config.output_buffer = io.StringIO()
    command.upgrade(config, "head", sql=True)
    ddl = config.output_buffer.getvalue()
    assert "JSONB" in ddl
    assert "UUID" in ddl
    assert "TIMESTAMP WITH TIME ZONE" in ddl
    assert "CREATE TABLE events" in ddl


def test_running_migrations_in_process_keeps_the_redacting_log_handler(tmp_path: Path) -> None:
    """Alembic's default logging setup replaces root handlers; GuardBench's redaction must survive it."""
    import logging

    from guardbench.logging_config import RedactingFilter, configure_logging

    configure_logging("WARNING")
    try:
        upgrade_to_head(f"sqlite:///{tmp_path / 'log.db'}")
        ours = [h for h in logging.getLogger().handlers if getattr(h, "_guardbench", False)]
        assert len(ours) == 1
        assert any(isinstance(f, RedactingFilter) for f in ours[0].filters)
    finally:
        for h in list(logging.getLogger().handlers):
            if getattr(h, "_guardbench", False):
                logging.getLogger().removeHandler(h)
