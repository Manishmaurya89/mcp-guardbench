"""The evidence recorder: normalizes, redacts, orders, and stores events.

Every event passes through here. The recorder guarantees that

* real-credential shapes are scrubbed from the stored (raw) payload;
* synthetic marker values are replaced in the *redacted* payload, which is the only form that
  is ever logged, returned by the API, or shown on the dashboard;
* events carry a strictly increasing per-run sequence number and parent links;
* oversized payload strings are bounded, so a hostile tool cannot bloat the evidence store.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID, uuid4

from guardbench.domain.clock import Clock, SystemClock
from guardbench.domain.enums import EventType, PolicyDecisionType
from guardbench.domain.schemas import Event
from guardbench.logging_config import get_logger
from guardbench.runtime.event_bus import EventBus
from guardbench.runtime.redaction import Redactor
from guardbench.runtime.trace_context import IdSource, RandomIdSource, TraceContext

log = get_logger("recorder")

MAX_PAYLOAD_STRING = 8192
TRUNCATION_NOTE = "...[truncated {n} chars]"


def bound_strings(value: Any, limit: int = MAX_PAYLOAD_STRING, _depth: int = 0) -> Any:
    """Deep-copy ``value`` with every string capped at ``limit`` characters."""
    if _depth > 16:
        return "[TRUNCATED:max_depth]"
    if isinstance(value, str):
        if len(value) <= limit:
            return value
        return value[:limit] + TRUNCATION_NOTE.format(n=len(value) - limit)
    if isinstance(value, dict):
        return {str(k): bound_strings(v, limit, _depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [bound_strings(v, limit, _depth + 1) for v in value]
    return value


class Recorder:
    """Builds and stores events for one run. Instance-scoped; holds no global state."""

    def __init__(
        self,
        *,
        run_id: UUID | None = None,
        redactor: Redactor | None = None,
        bus: EventBus | None = None,
        clock: Clock | None = None,
        ids: IdSource | None = None,
    ) -> None:
        self.run_id = run_id
        self._redactor = redactor or Redactor()
        self._bus = bus or EventBus()
        self._clock = clock or SystemClock()
        self.ids: IdSource = ids or RandomIdSource()
        self._events: list[Event] = []
        self._sequence = 0

    @property
    def events(self) -> tuple[Event, ...]:
        """All recorded events, in order."""
        return tuple(self._events)

    @property
    def bus(self) -> EventBus:
        """The bus events are published to after being stored."""
        return self._bus

    def new_trace(self) -> TraceContext:
        """Start a new root trace for this recorder's run."""
        return TraceContext.new_root(self.ids, run_id=str(self.run_id) if self.run_id else None)

    def record(
        self,
        trace: TraceContext,
        event_type: EventType | str,
        source: str,
        *,
        payload: dict[str, Any] | None = None,
        server_name: str | None = None,
        tool_name: str | None = None,
        risk_tags: Iterable[str] = (),
        decision: PolicyDecisionType | None = None,
        parent_event_id: UUID | None = None,
    ) -> Event:
        """Create, store, and publish one event. Returns the stored event."""
        self._sequence += 1
        bounded = bound_strings(payload or {})
        stored_payload = self._redactor.scrub_credentials(bounded)
        event = Event(
            id=uuid4(),
            run_id=self.run_id,
            trace_id=trace.trace_id,
            span_id=trace.span_id,
            parent_event_id=parent_event_id,
            sequence=self._sequence,
            timestamp=self._clock.now(),
            event_type=event_type.value if isinstance(event_type, EventType) else event_type,
            source=source,
            server_name=server_name,
            tool_name=tool_name,
            payload_json=stored_payload,
            redacted_payload_json=self._redactor.redact(stored_payload),
            risk_tags=sorted(set(risk_tags)),
            decision=decision,
        )
        self._events.append(event)
        self._log(event)
        self._bus.publish(event)
        return event

    def events_for_trace(self, trace_id: str) -> list[Event]:
        """Events belonging to one trace, in order."""
        return [e for e in self._events if e.trace_id == trace_id]

    def _log(self, event: Event) -> None:
        # Only redacted content is ever logged.
        log.debug(
            "event_recorded",
            extra={
                "event_type": event.event_type,
                "sequence": event.sequence,
                "tool_name": event.tool_name,
                "decision": event.decision.value if event.decision else None,
                "payload": event.redacted_payload_json,
            },
        )
