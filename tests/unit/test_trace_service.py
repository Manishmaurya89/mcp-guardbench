"""``guardbench.services.trace``: one-line, redacted summaries of recorded events."""

from __future__ import annotations

from typing import Any

import pytest

from guardbench.domain.errors import GuardBenchError
from guardbench.services.trace import DETAIL_WIDTH, describe_event, describe_flow, find_trace_id


@pytest.mark.parametrize(
    ("event_type", "payload", "expected"),
    [
        ("policy_decision", {"reason": "tool is not registered", "matched_rule": "POL-001"}, "tool is not"),
        ("tool_call_blocked", {"reason": "synthetic secret in an outbound argument"}, "synthetic secret"),
        ("tools_listed", {"tools": ["a", "b"], "snapshot_hash": "f" * 64}, "2 tools; snapshot ffffffffffff"),
        ("tool_call_requested", {"arguments": {"b": 2, "a": 1}}, 'args {"a": 1, "b": 2}'),
        ("tool_response", {"bytes": 12, "text": "hello world"}, "12 bytes: hello world"),
        (
            "model_context_update",
            {"exposed_tools": ["a", "b"], "withheld_tools": ["c"]},
            "exposed 2, withheld 1 ['c']",
        ),
        ("model_context_update", {"bytes": 64, "withheld": False}, "64 bytes added to context"),
        ("model_context_update", {"bytes": 64, "withheld": True}, "64 bytes withheld from the model"),
        (
            "data_flow",
            {"marker_id": "synthetic_secret_1", "decision": "blocked", "propagation_path": ["a:b", "c:d"]},
            "synthetic_secret_1 blocked; full path listed below",
        ),
        ("approval_requested", {"state": "pending", "resolved_by": None}, "pending (resolved by nobody)"),
        (
            "approval_requested",
            {"state": "approved", "resolved_by": "simulated-operator"},
            "simulated-operator",
        ),
        ("some_future_event", {"b": 1, "a": 2}, "a, b"),
    ],
)
def test_events_are_summarised_in_one_readable_line(
    event_type: str, payload: dict[str, Any], expected: str
) -> None:
    assert expected in describe_event(event_type, payload)


def test_missing_payload_fields_never_raise() -> None:
    for event_type in ("policy_decision", "tools_listed", "tool_response", "data_flow", "approval_requested"):
        assert isinstance(describe_event(event_type, {}), str)


def test_summaries_are_single_line_and_bounded() -> None:
    text = describe_event("tool_response", {"bytes": 1, "text": "line one\nline two\t" + "x" * 500})
    assert "\n" not in text and "\t" not in text
    assert len(text) == DETAIL_WIDTH and text.endswith("...")


def test_short_summaries_are_left_alone() -> None:
    assert describe_event("tool_call_blocked", {"reason": "short"}) == "short"


class FakeRun:
    def __init__(self, traces: list[dict[str, str]] | None) -> None:
        self.summary_json: dict[str, Any] | None = {"traces": traces} if traces is not None else None


def test_the_trace_id_is_found_by_adapter_and_case() -> None:
    run = FakeRun(
        [
            {"adapter": "a", "test_case_id": "TP-001", "trace_id": "1" * 32},
            {"adapter": "b", "test_case_id": "TP-001", "trace_id": "2" * 32},
        ]
    )
    assert find_trace_id(run, "b", "TP-001") == "2" * 32  # type: ignore[arg-type]


def test_an_unknown_trace_lists_what_is_available() -> None:
    run = FakeRun([{"adapter": "a", "test_case_id": "TP-001", "trace_id": "1" * 32}])
    with pytest.raises(GuardBenchError, match=r"no trace for a/ZZ-999; available: a/TP-001"):
        find_trace_id(run, "a", "ZZ-999")  # type: ignore[arg-type]


def test_a_run_without_traces_says_none_are_available() -> None:
    with pytest.raises(GuardBenchError, match="available: none"):
        find_trace_id(FakeRun(None), "a", "TP-001")  # type: ignore[arg-type]


def test_a_data_flow_is_listed_one_hop_per_line() -> None:
    lines = describe_flow(
        {"marker_id": "synthetic_secret_1", "decision": "blocked", "propagation_path": ["a:b", "c:d", "e:f"]}
    )
    assert lines == ["synthetic_secret_1 (blocked):", "     a:b", "  -> c:d", "  -> e:f"]


def test_a_data_flow_without_a_path_still_renders() -> None:
    assert describe_flow({"marker_id": "m", "decision": "allowed"}) == ["m (allowed):"]
