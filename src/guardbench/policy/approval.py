"""Approval workflow.

There is no automatic bypass. A ``require_approval`` decision creates a *pending* request; the
guarded action stays blocked until the request is explicitly resolved by a named actor.

For tests and the dashboard demo, :class:`SimulatedOperator` can resolve requests, but every
resolution it produces is permanently labelled ``simulated=True`` and attributed to the
``simulated-operator`` actor, so a simulated approval can never be mistaken for a human one.
Unattended benchmark runs never call it: pending requests simply stay pending.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from guardbench.domain.clock import Clock, SystemClock
from guardbench.domain.errors import ConflictError, NotFoundError, ValidationFailure

SIMULATED_ACTOR = "simulated-operator"


class ApprovalState(StrEnum):
    """Lifecycle of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(slots=True)
class ApprovalRequest:
    """One request for a human decision about a specific tool call."""

    id: UUID
    trace_id: str
    server_name: str
    tool_name: str
    arguments_digest: str
    reason: str
    requested_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    simulated: bool = False

    def to_payload(self) -> dict[str, Any]:
        """Redaction-safe view for events and the API (arguments are represented by a digest only)."""
        return {
            "approval_id": str(self.id),
            "trace_id": self.trace_id,
            "server": self.server_name,
            "tool": self.tool_name,
            "arguments_digest": self.arguments_digest,
            "reason": self.reason,
            "state": self.state.value,
            "resolved_by": self.resolved_by,
            "simulated": self.simulated,
        }


def digest_arguments(arguments: dict[str, Any]) -> str:
    """Stable digest of call arguments, so an approval covers exactly one specific call."""
    blob = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass(slots=True)
class ApprovalService:
    """In-memory approval registry for one run. It records decisions; it never makes them."""

    clock: Clock = field(default_factory=SystemClock)
    _requests: dict[UUID, ApprovalRequest] = field(default_factory=dict)

    def request(
        self, trace_id: str, server_name: str, tool_name: str, arguments: dict[str, Any], reason: str
    ) -> ApprovalRequest:
        """Open a pending request (idempotent for the same trace, tool, and arguments)."""
        digest = digest_arguments(arguments)
        for existing in self._requests.values():
            if (existing.trace_id, existing.server_name, existing.tool_name, existing.arguments_digest) == (
                trace_id,
                server_name,
                tool_name,
                digest,
            ):
                return existing
        created = ApprovalRequest(
            id=uuid4(),
            trace_id=trace_id,
            server_name=server_name,
            tool_name=tool_name,
            arguments_digest=digest,
            reason=reason,
            requested_at=self.clock.now(),
        )
        self._requests[created.id] = created
        return created

    def get(self, request_id: UUID) -> ApprovalRequest:
        """Fetch a request or raise :class:`NotFoundError`."""
        try:
            return self._requests[request_id]
        except KeyError as exc:
            raise NotFoundError(f"approval request {request_id} not found") from exc

    def pending(self) -> list[ApprovalRequest]:
        """Requests still waiting for a decision."""
        return [r for r in self._requests.values() if r.state is ApprovalState.PENDING]

    def all(self) -> list[ApprovalRequest]:
        """Every request, oldest first."""
        return sorted(self._requests.values(), key=lambda r: r.requested_at)

    def resolve(self, request_id: UUID, *, approve: bool, actor: str, simulated: bool) -> ApprovalRequest:
        """Record a decision. ``actor`` and ``simulated`` are mandatory and explicit."""
        if not actor.strip():
            raise ValidationFailure("an approval must name the actor who made the decision")
        if simulated != (actor == SIMULATED_ACTOR):
            raise ValidationFailure(
                f"simulated approvals must be attributed to '{SIMULATED_ACTOR}' and vice versa"
            )
        request = self.get(request_id)
        if request.state is not ApprovalState.PENDING:
            raise ConflictError(f"approval request {request_id} is already {request.state.value}")
        request.state = ApprovalState.APPROVED if approve else ApprovalState.DENIED
        request.resolved_at = self.clock.now()
        request.resolved_by = actor
        request.simulated = simulated
        return request

    def is_approved(self, request_id: UUID) -> bool:
        """Whether the request has been explicitly approved."""
        return self.get(request_id).state is ApprovalState.APPROVED


class SimulatedOperator:
    """A clearly labelled stand-in for a human, for tests and dashboard demos only.

    It approves a request only if ``rule`` says so, and every resolution is marked simulated.
    """

    def __init__(self, service: ApprovalService, rule: Callable[[ApprovalRequest], bool]) -> None:
        self._service = service
        self._rule = rule

    def review_pending(self) -> list[ApprovalRequest]:
        """Resolve every pending request according to ``rule``. Returns the resolved requests."""
        resolved = []
        for request in self._service.pending():
            resolved.append(
                self._service.resolve(
                    request.id, approve=self._rule(request), actor=SIMULATED_ACTOR, simulated=True
                )
            )
        return resolved
