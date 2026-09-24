"""Programmatic Alembic access for the CLI and container start-up."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from guardbench.db.session import ensure_sqlite_directory
from guardbench.domain.errors import GuardBenchError


def find_alembic_ini(explicit: Path | None = None) -> Path:
    """Locate ``alembic.ini``: explicit path, then the working directory, then the repo checkout."""
    candidates = [explicit] if explicit else []
    candidates += [Path.cwd() / "alembic.ini", Path(__file__).resolve().parents[3] / "alembic.ini"]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise GuardBenchError(
        "alembic.ini not found. Run from the repository root or set GUARDBENCH_ALEMBIC_INI."
    )


def alembic_config(database_url: str, alembic_ini: Path | None = None) -> Config:
    """Build an Alembic config pointing at ``database_url`` with an absolute script location."""
    ini = find_alembic_ini(alembic_ini)
    config = Config(str(ini))
    config.set_main_option("script_location", str(ini.parent / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["configure_logger"] = False  # keep GuardBench's redacting log handler intact
    return config


def upgrade_to_head(database_url: str, alembic_ini: Path | None = None) -> None:
    """Apply all pending migrations (creating the SQLite directory first if needed)."""
    ensure_sqlite_directory(database_url)
    command.upgrade(alembic_config(database_url, alembic_ini), "head")
