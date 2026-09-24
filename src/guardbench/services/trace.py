"""Read one recorded trace back out of the evidence store, for display.

Only the *redacted* payload of an event is ever read here. The raw payload column exists for the
benchmark's own scoring and is never shown.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardbench.db import models
from guardbench.domain.errors import GuardBenchError

DETAIL_WIDTH = 72


@dataclass(frozen=True, slots=True)
class TraceRow:
    """One event of a trace, flattened for a table."""

    position: int
    event_type: str
    tool: str
    decision: str
    rule: str
    detail: str


@dataclass(frozen=True, slots=True)
class Trace:
    """The recorded trace of one test case under one adapter."""

    trace_id: str
    rows: list[TraceRow]
    #: Full synthetic data-flow paths (marker ids and tool names only), one block of lines per flow.
    flows: list[list[str]]


def find_trace_id(run: models.BenchmarkRun, adapter: str, case_id: str) -> str:
    """The trace id the run recorded for ``adapter`` on ``case_id``."""
    traces = (run.summary_json or {}).get("traces", [])
    for trace in traces:
        if trace["adapter"] == adapter and trace["test_case_id"] == case_id:
            return str(trace["trace_id"])
    available = ", ".join(sorted(f"{t['adapter']}/{t['test_case_id']}" for t in traces)) or "none"
    raise GuardBenchError(f"this run has no trace for {adapter}/{case_id}; available: {available}")


def load_trace(session: Session, run: models.BenchmarkRun, adapter: str, case_id: str) -> Trace:
    """The events of one test case under one adapter, in the order they happened."""
    trace_id = find_trace_id(run, adapter, case_id)
    events = session.scalars(
        select(models.Event)
        .where(models.Event.run_id == run.id, models.Event.trace_id == trace_id)
        .order_by(models.Event.sequence)
    ).all()
    rows = [
        TraceRow(
            position=index,
            event_type=event.event_type,
            tool=event.tool_name or "",
            decision=event.decision or "",
            rule=str(event.redacted_payload_json.get("matched_rule", "")),
            detail=describe_event(event.event_type, event.redacted_payload_json),
        )
        for index, event in enumerate(events, start=1)
    ]
    flows = [describe_flow(e.redacted_payload_json) for e in events if e.event_type == "data_flow"]
    return Trace(trace_id, rows, flows)


def describe_event(event_type: str, payload: dict[str, Any]) -> str:
    """A short, single-line, already-redacted summary of an event payload."""
    if event_type in {"policy_decision", "tool_call_blocked"}:
        text = str(payload.get("reason", ""))
    elif event_type == "tools_listed":
        text = f"{_count(payload.get('tools'))} tools; snapshot {str(payload.get('snapshot_hash', ''))[:12]}"
    elif event_type == "tool_call_requested":
        text = "args " + json.dumps(payload.get("arguments", {}), sort_keys=True)
    elif event_type == "tool_response":
        text = f"{payload.get('bytes', 0)} bytes: {payload.get('text', '')}"
    elif event_type == "model_context_update":
        text = _describe_context_update(payload)
    elif event_type == "data_flow":
        text = f"{payload.get('marker_id')} {payload.get('decision')}; full path listed below"
    elif event_type == "approval_requested":
        text = f"{payload.get('state')} (resolved by {payload.get('resolved_by') or 'nobody'})"
    else:
        text = ", ".join(sorted(payload))
    return _one_line(text)


def describe_flow(payload: dict[str, Any]) -> list[str]:
    """One data-flow event as a header line followed by one line per hop."""
    header = f"{payload.get('marker_id')} ({payload.get('decision')}):"
    hops = [str(hop) for hop in payload.get("propagation_path", [])]
    return [header, *[f"  {'-> ' if index else '   '}{hop}" for index, hop in enumerate(hops)]]


def _describe_context_update(payload: dict[str, Any]) -> str:
    if "exposed_tools" in payload:
        withheld = payload.get("withheld_tools", [])
        return f"exposed {_count(payload['exposed_tools'])}, withheld {_count(withheld)} {list(withheld)}"
    verb = "withheld from the model" if payload.get("withheld") else "added to context"
    return f"{payload.get('bytes', 0)} bytes {verb}"


def _count(value: Any) -> int:
    return len(value) if isinstance(value, list | tuple | dict) else 0


def _one_line(text: str) -> str:
    """Collapse whitespace and cap the length so a table row never wraps."""
    flat = " ".join(text.split())
    return flat if len(flat) <= DETAIL_WIDTH else flat[: DETAIL_WIDTH - 3] + "..."
