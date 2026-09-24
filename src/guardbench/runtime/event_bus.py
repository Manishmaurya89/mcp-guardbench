"""A minimal synchronous in-process event bus.

Components publish structured :class:`Event` objects; subscribers (the recorder, tests,
optional exporters) receive them in publication order. The bus is instance-scoped, never a
module-level singleton, so parallel runs cannot see each other's events.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from guardbench.domain.schemas import Event
from guardbench.logging_config import get_logger

log = get_logger("event_bus")

Subscriber = Callable[[Event], None]


class EventSink(Protocol):
    """Anything that can receive events."""

    def handle(self, event: Event) -> None:
        """Consume one event."""
        ...


class EventBus:
    """Fan-out of events to subscribers. A failing subscriber never blocks the others."""

    def __init__(self) -> None:
        self._subscribers: list[Subscriber] = []
        self.subscriber_errors = 0

    def subscribe(self, subscriber: Subscriber) -> None:
        """Register ``subscriber``; it will receive every later event."""
        self._subscribers.append(subscriber)

    def publish(self, event: Event) -> None:
        """Deliver ``event`` to every subscriber, recording (not hiding) subscriber failures."""
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception:
                # Evidence collection must not take the system down, but the failure is counted
                # and logged (with traceback) rather than silently dropped.
                self.subscriber_errors += 1
                log.exception("event_subscriber_failed", extra={"event_type": event.event_type})
