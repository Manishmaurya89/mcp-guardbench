"""UTC time helpers. All timestamps in GuardBench are timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as aware UTC; naive values are assumed to already be UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class Clock(Protocol):
    """Injectable time source so tests and benchmarks can be deterministic."""

    def now(self) -> datetime:
        """Return the current UTC time."""
        ...


class SystemClock:
    """Real wall-clock time."""

    def now(self) -> datetime:
        """Return the current UTC time."""
        return utc_now()
