"""Event recording and synthetic data-flow tracking."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from guardbench.domain.enums import EventType, PolicyDecisionType, Severity
from guardbench.domain.markers import (
    SIMULATED_EXTERNAL_DESTINATION,
    TEST_SECRET,
    SyntheticMarker,
    marker_for_value,
)
from guardbench.runtime.data_flow import DataFlowTracker, FlowLocation, flow_finding
from guardbench.runtime.event_bus import EventBus
from guardbench.runtime.recorder import MAX_PAYLOAD_STRING, Recorder, bound_strings
from guardbench.runtime.trace_context import DeterministicIdSource


def _secret() -> SyntheticMarker:
    marker = marker_for_value(TEST_SECRET)
    assert marker is not None
    return marker


SECRET = _secret()


class FixedClock:
    def __init__(self) -> None:
        self.ticks = 0

    def now(self) -> datetime:
        self.ticks += 1
        return datetime(2026, 1, 1, 0, 0, self.ticks, tzinfo=UTC)


def make_recorder(**kw: object) -> Recorder:
    return Recorder(ids=DeterministicIdSource("rec"), clock=FixedClock(), **kw)


# ---------------------------------------------------------------- recorder


def test_events_get_strictly_increasing_sequence_numbers_and_utc_timestamps() -> None:
    rec = make_recorder()
    trace = rec.new_trace()
    events = [rec.record(trace, EventType.TOOLS_LISTED, "test") for _ in range(4)]
    assert [e.sequence for e in events] == [1, 2, 3, 4]
    assert all(e.timestamp.tzinfo is UTC for e in events)
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)


def test_raw_payload_keeps_markers_but_redacted_payload_never_does() -> None:
    rec = make_recorder()
    event = rec.record(rec.new_trace(), EventType.TOOL_CALL_REQUESTED, "guard", payload={"body": TEST_SECRET})
    assert event.payload_json == {"body": TEST_SECRET}
    assert event.redacted_payload_json == {"body": "[REDACTED:synthetic_secret_1]"}
    assert TEST_SECRET not in json.dumps(event.redacted_payload_json)


def test_real_credential_shapes_are_scrubbed_from_the_raw_payload_too() -> None:
    rec = make_recorder()
    leaked = "AKIA" + "ABCDEFGHIJKLMNOP"
    event = rec.record(rec.new_trace(), EventType.ERROR, "guard", payload={"note": f"key {leaked}"})
    assert leaked not in json.dumps(event.payload_json)
    assert leaked not in json.dumps(event.redacted_payload_json)
    assert "REDACTED:credential" in event.payload_json["note"]


def test_oversized_strings_are_bounded_in_stored_payloads() -> None:
    rec = make_recorder()
    huge = "A" * (MAX_PAYLOAD_STRING * 5)
    event = rec.record(rec.new_trace(), EventType.TOOL_RESPONSE, "guard", payload={"text": huge, "n": [huge]})
    assert len(event.payload_json["text"]) < MAX_PAYLOAD_STRING + 50
    assert "truncated" in event.payload_json["text"]
    assert len(json.dumps(event.payload_json)) < 3 * MAX_PAYLOAD_STRING


def test_bound_strings_leaves_small_values_alone() -> None:
    value = {"a": "short", "b": [1, 2, {"c": "x"}], "d": None}
    assert bound_strings(value) == value


def test_events_carry_trace_span_parent_and_tags() -> None:
    rec = make_recorder()
    trace = rec.new_trace()
    parent = rec.record(trace, EventType.TOOL_CALL_REQUESTED, "guard", tool_name="t", server_name="s")
    child = rec.record(
        trace.child(rec.ids),
        EventType.POLICY_DECISION,
        "policy",
        decision=PolicyDecisionType.DENY,
        risk_tags=["b_tag", "a_tag", "a_tag"],
        parent_event_id=parent.id,
    )
    assert child.trace_id == parent.trace_id
    assert child.span_id != parent.span_id
    assert child.parent_event_id == parent.id
    assert child.risk_tags == ["a_tag", "b_tag"]
    assert child.decision is PolicyDecisionType.DENY
    assert child.to_otel_attributes()["guardbench.policy.decision"] == "deny"


def test_recorder_is_reproducible_with_a_deterministic_id_source() -> None:
    a, b = make_recorder(), make_recorder()
    assert a.new_trace().trace_id == b.new_trace().trace_id


def test_events_can_be_filtered_by_trace() -> None:
    rec = make_recorder()
    t1, t2 = rec.new_trace(), rec.new_trace()
    rec.record(t1, EventType.TOOLS_LISTED, "x")
    rec.record(t2, EventType.TOOLS_LISTED, "x")
    rec.record(t1, EventType.TOOL_RESPONSE, "x")
    assert [e.event_type for e in rec.events_for_trace(t1.trace_id)] == ["tools_listed", "tool_response"]
    assert len(rec.events) == 3


def test_bus_delivers_in_order_and_isolates_failing_subscribers() -> None:
    seen: list[int] = []
    bus = EventBus()

    def broken(_event: object) -> None:
        raise RuntimeError("subscriber bug")

    bus.subscribe(broken)
    bus.subscribe(lambda e: seen.append(e.sequence))
    rec = make_recorder(bus=bus)
    trace = rec.new_trace()
    for _ in range(3):
        rec.record(trace, EventType.TOOLS_LISTED, "x")
    assert seen == [1, 2, 3], "a failing subscriber must not block later subscribers"
    assert bus.subscriber_errors == 3, "failures are counted, not silently swallowed"


def test_the_recorder_holds_no_global_state() -> None:
    a, b = make_recorder(), make_recorder()
    a.record(a.new_trace(), EventType.TOOLS_LISTED, "x")
    assert b.events == ()


def test_run_id_is_stamped_on_events() -> None:
    run_id = uuid4()
    rec = make_recorder(run_id=run_id)
    assert rec.record(rec.new_trace(), EventType.RUN_STARTED, "x").run_id == run_id


# ---------------------------------------------------------------- data flow


def test_a_marker_flow_records_source_hops_and_destination() -> None:
    tracker = DataFlowTracker()
    src, ctx, dest = uuid4(), uuid4(), uuid4()
    tracker.observe(
        "t" * 32, FlowLocation.FIXTURE_SOURCE, "read_private_record.result", "x " + TEST_SECRET, src
    )
    tracker.observe("t" * 32, FlowLocation.MODEL_CONTEXT, "tool_result", TEST_SECRET, ctx)
    tracker.observe(
        "t" * 32, FlowLocation.TOOL_ARGUMENT, "send_notification.body", {"body": TEST_SECRET}, dest
    )
    flow = tracker.record_flow(
        "t" * 32, SECRET, destination_label="send_notification", destination_event_id=dest, blocked=True
    )
    assert flow.source_event_id == src
    assert flow.destination_event_id == dest
    assert flow.propagation_path == [
        "fixture_source:read_private_record.result",
        "model_context:tool_result",
        "tool_argument:send_notification.body",
        "outbound_request:send_notification",
    ]
    assert flow.blocked


def test_flow_evidence_uses_marker_ids_never_values() -> None:
    tracker = DataFlowTracker()
    tracker.observe("t" * 32, FlowLocation.TOOL_RESULT, "r", TEST_SECRET)
    flow = tracker.record_flow(
        "t" * 32, SECRET, destination_label="send", destination_event_id=None, blocked=False
    )
    evidence = json.dumps(flow.to_evidence())
    assert TEST_SECRET not in evidence
    assert "synthetic_secret_1" in evidence
    assert flow.to_evidence()["decision"] == "allowed"


def test_flow_findings_distinguish_blocked_from_leaked() -> None:
    tracker = DataFlowTracker()
    tracker.observe("t" * 32, FlowLocation.TOOL_RESULT, "r", TEST_SECRET)
    blocked = tracker.record_flow(
        "t" * 32, SECRET, destination_label="d", destination_event_id=None, blocked=True
    )
    leaked = tracker.record_flow(
        "t" * 32, SECRET, destination_label="d", destination_event_id=None, blocked=False
    )
    good = flow_finding(blocked, server_name="s", tool_name="send")
    bad = flow_finding(leaked, server_name="s", tool_name="send")
    assert (good.rule_id, good.severity) == ("DF-001", Severity.HIGH)
    assert (bad.rule_id, bad.severity) == ("DF-002", Severity.CRITICAL)
    assert good.evidence["propagation_path"] and TEST_SECRET not in json.dumps(good.model_dump(mode="json"))


def test_consecutive_duplicate_observations_do_not_bloat_the_path() -> None:
    tracker = DataFlowTracker()
    for _ in range(5):
        tracker.observe("t" * 32, FlowLocation.MODEL_CONTEXT, "ctx", TEST_SECRET)
    flow = tracker.record_flow(
        "t" * 32, SECRET, destination_label="d", destination_event_id=None, blocked=True
    )
    assert len(flow.path) == 2  # one context hop plus the destination


def test_traces_are_isolated_from_each_other() -> None:
    tracker = DataFlowTracker()
    tracker.observe("a" * 32, FlowLocation.MODEL_CONTEXT, "ctx", TEST_SECRET)
    assert tracker.tainted_markers("a" * 32) == {"synthetic_secret_1"}
    assert tracker.tainted_markers("b" * 32) == set()
    assert tracker.in_model_context("a" * 32, "synthetic_secret_1")
    assert not tracker.in_model_context("b" * 32, "synthetic_secret_1")


def test_observe_reports_which_markers_it_saw_and_ignores_clean_values() -> None:
    tracker = DataFlowTracker()
    assert tracker.observe("t" * 32, FlowLocation.TOOL_ARGUMENT, "a", {"x": "nothing"}) == []
    found = tracker.observe("t" * 32, FlowLocation.TOOL_ARGUMENT, "a", {"d": SIMULATED_EXTERNAL_DESTINATION})
    assert [m.marker_id for m in found] == ["synthetic_destination_1"]
    assert tracker.flows() == []


def test_flows_can_be_listed_per_trace() -> None:
    tracker = DataFlowTracker()
    for trace in ("a" * 32, "b" * 32):
        tracker.observe(trace, FlowLocation.TOOL_RESULT, "r", TEST_SECRET)
        tracker.record_flow(trace, SECRET, destination_label="d", destination_event_id=None, blocked=True)
    assert len(tracker.flows()) == 2
    assert len(tracker.flows("a" * 32)) == 1
