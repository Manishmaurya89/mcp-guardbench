"""Alembic environment: online and offline migrations against the GuardBench metadata."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from guardbench.config import load_settings
from guardbench.db import models  # noqa: F401  (registers tables on Base.metadata)
from guardbench.db.base import Base
from guardbench.db.session import normalize_database_url

config = context.config
# `fileConfig` replaces the root logger's handlers. When GuardBench runs migrations in-process it has
# already installed its redacting handler and must keep it, so the caller opts out via this attribute.
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    """URL from the programmatic caller if given, else from GUARDBENCH_DATABASE_URL."""
    explicit = config.get_main_option("sqlalchemy.url")
    return normalize_database_url(explicit or load_settings().database_url)


def run_migrations_offline() -> None:
    """Emit SQL without connecting (``alembic upgrade head --sql``)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations over a real connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url().replace("%", "%%")
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
