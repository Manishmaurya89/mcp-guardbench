"""Engine and session construction. No module-level engine: callers own their lifecycle."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from guardbench.db.base import Base


def normalize_database_url(url: str) -> str:
    """Map bare ``postgresql://`` URLs onto the installed psycopg (v3) driver."""
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    return url


def ensure_sqlite_directory(url: str) -> None:
    """Create the parent directory of a file-based SQLite database (no-op for other databases)."""
    parsed = make_url(normalize_database_url(url))
    if parsed.get_backend_name() == "sqlite" and parsed.database not in (None, "", ":memory:"):
        Path(parsed.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def create_db_engine(url: str) -> Engine:
    """Create an engine for PostgreSQL or SQLite.

    SQLite gets foreign-key enforcement, thread sharing (FastAPI runs sync routes in a
    thread pool), and a single shared connection for ``:memory:`` databases.
    """
    url = normalize_database_url(url)
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)

    kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
    if parsed.database in (None, "", ":memory:"):
        kwargs["poolclass"] = StaticPool
    else:
        ensure_sqlite_directory(url)
    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """A session factory that keeps loaded objects usable after commit."""
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Commit on success, roll back on any error, always close."""
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def create_all_tables(engine: Engine) -> None:
    """Create tables directly from metadata (dev mode and tests; production uses Alembic)."""
    from guardbench.db import models  # noqa: F401  (register tables on Base.metadata)

    Base.metadata.create_all(engine)
