"""OpenTelemetry-compatible trace identifiers and an ambient trace context.

IDs use the W3C trace-context shapes: 32 hex chars for traces, 16 for spans. A
deterministic source lets benchmark runs reproduce identical IDs from a seed.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Protocol


class IdSource(Protocol):
    """Produces trace and span IDs."""

    def new_trace_id(self) -> str:
        """Return a new 32-hex-character trace id."""
        ...

    def new_span_id(self) -> str:
        """Return a new 16-hex-character span id."""
        ...


class RandomIdSource:
    """Cryptographically random IDs, for interactive use."""

    def new_trace_id(self) -> str:
        """Return a random 32-hex-character trace id."""
        return secrets.token_hex(16)

    def new_span_id(self) -> str:
        """Return a random 16-hex-character span id."""
        return secrets.token_hex(8)


class DeterministicIdSource:
    """Seed-derived IDs so identical benchmark runs produce identical traces."""

    def __init__(self, seed: str) -> None:
        self._seed = seed
        self._counter = 0

    def _next(self, kind: str, length: int) -> str:
        self._counter += 1
        digest = hashlib.sha256(f"{self._seed}:{kind}:{self._counter}".encode()).hexdigest()
        return digest[:length]

    def new_trace_id(self) -> str:
        """Return the next deterministic trace id."""
        return self._next("trace", 32)

    def new_span_id(self) -> str:
        """Return the next deterministic span id."""
        return self._next("span", 16)


@dataclass(frozen=True, slots=True)
class TraceContext:
    """Identifies where an event sits in a trace. Immutable."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    run_id: str | None = None

    def child(self, ids: IdSource) -> TraceContext:
        """Start a child span within the same trace."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=ids.new_span_id(),
            parent_span_id=self.span_id,
            run_id=self.run_id,
        )

    @classmethod
    def new_root(cls, ids: IdSource, *, run_id: str | None = None) -> TraceContext:
        """Start a new trace."""
        return cls(trace_id=ids.new_trace_id(), span_id=ids.new_span_id(), run_id=run_id)


_current: ContextVar[TraceContext | None] = ContextVar("guardbench_trace", default=None)


def current_trace() -> TraceContext | None:
    """The trace context active in this task/thread, if any."""
    return _current.get()


@contextmanager
def use_trace(context: TraceContext) -> Iterator[TraceContext]:
    """Make ``context`` the ambient trace for the enclosed block (used to tag logs)."""
    token = _current.set(context)
    try:
        yield context
    finally:
        _current.reset(token)
