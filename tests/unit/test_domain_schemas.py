"""Domain model behavior: ordering, validation, and safe defaults."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from guardbench.domain.enums import Capability, PolicyDecisionType, Severity
from guardbench.domain.markers import (
    MARKER_VALUES,
    SIMULATED_EXTERNAL_DESTINATION,
    TEST_PRIVATE_RECORD,
    TEST_SECRET,
    find_credential_shapes,
    marker_for_id,
    marker_for_value,
)
from guardbench.domain.schemas import (
    CAPABILITIES_META_KEY,
    DriftReport,
    Event,
    Finding,
    PolicyDecision,
    ProjectCreate,
    ServerCreate,
    ToolDefinitionData,
)

TRACE = "a" * 32


def test_severity_orders_by_rank_not_alphabetically() -> None:
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.INFO.rank == 0
    assert Severity.CRITICAL >= Severity.CRITICAL
    assert max([Severity.LOW, Severity.CRITICAL, Severity.HIGH]) is Severity.CRITICAL
    # alphabetical order would put "high" before "low"; rank order must not
    assert Severity.HIGH > Severity.LOW


def test_only_blocking_decisions_prevent_execution() -> None:
    assert not PolicyDecisionType.ALLOW.prevents_execution
    assert not PolicyDecisionType.ALLOW_WITH_WARNING.prevents_execution
    for decision in (
        PolicyDecisionType.DENY,
        PolicyDecisionType.REQUIRE_APPROVAL,
        PolicyDecisionType.QUARANTINE,
    ):
        assert decision.prevents_execution


def test_marker_registry_is_exactly_the_three_synthetic_values() -> None:
    assert {TEST_SECRET, TEST_PRIVATE_RECORD, SIMULATED_EXTERNAL_DESTINATION} == MARKER_VALUES
    marker = marker_for_value(TEST_SECRET)
    assert marker is not None
    assert marker.marker_id == "synthetic_secret_1"
    assert marker.redaction_token == "[REDACTED:synthetic_secret_1]"
    assert marker_for_id("synthetic_secret_1") == marker
    assert marker_for_value("not-a-marker") is None


@pytest.mark.parametrize(
    ("text", "shape"),
    [
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key_block"),
        ("AKIAABCDEFGHIJKLMNOP", "aws_access_key_id"),
        ("password = hunter2hunter2", "password_assignment"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwx", "bearer_token"),
    ],
)
def test_credential_shapes_are_detected(text: str, shape: str) -> None:
    assert shape in find_credential_shapes({"nested": [text]})


def test_synthetic_markers_are_not_credential_shapes() -> None:
    assert find_credential_shapes({"a": TEST_SECRET, "b": SIMULATED_EXTERNAL_DESTINATION}) == []


def test_event_requires_otel_shaped_ids() -> None:
    Event(trace_id=TRACE, span_id="b" * 16, event_type="x", source="t")
    with pytest.raises(ValidationError):
        Event(trace_id="short", event_type="x", source="t")
    with pytest.raises(ValidationError):
        Event(trace_id=TRACE, span_id="ZZ", event_type="x", source="t")


def test_event_otel_attributes_use_semantic_names() -> None:
    event = Event(
        trace_id=TRACE,
        event_type="policy_decision",
        source="policy",
        server_name="srv",
        tool_name="tool",
        decision=PolicyDecisionType.DENY,
        risk_tags=["unknown_tool"],
    )
    attrs = event.to_otel_attributes()
    assert attrs["mcp.tool.name"] == "tool"
    assert attrs["guardbench.policy.decision"] == "deny"
    assert attrs["guardbench.risk_tags"] == ["unknown_tool"]


def test_policy_decision_validates_trace_id() -> None:
    with pytest.raises(ValidationError):
        PolicyDecision(
            policy_id="p", decision=PolicyDecisionType.ALLOW, reason="r", matched_rule="m", trace_id="x"
        )


def test_finding_confidence_is_bounded_and_evidence_is_detected() -> None:
    kwargs = {"rule_id": "R", "title": "t", "category": "tool_poisoning", "severity": "high"}
    with pytest.raises(ValidationError):
        Finding(confidence=1.5, **kwargs)  # type: ignore[arg-type]
    assert not Finding(confidence=0.5, **kwargs).has_evidence  # type: ignore[arg-type]
    assert Finding(confidence=0.5, matched_evidence="x", **kwargs).has_evidence  # type: ignore[arg-type]


def test_declared_capabilities_ignore_unknown_and_malformed_values() -> None:
    tool = ToolDefinitionData(name="t", meta={CAPABILITIES_META_KEY: ["write", "bogus", 7, "read"]})
    assert tool.declared_capabilities == [Capability.READ, Capability.WRITE]
    assert ToolDefinitionData(name="t", meta={CAPABILITIES_META_KEY: "write"}).declared_capabilities == []
    assert ToolDefinitionData(name="t").declared_capabilities == []


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolDefinitionData(name="t", surprise=True)  # type: ignore[call-arg]


def test_server_create_rejects_urls_and_paths_as_fixture_names_is_left_to_allowlist() -> None:
    # Structural validation only; the allowlist is enforced by the fixture registry.
    with pytest.raises(ValidationError):
        ServerCreate(name="../evil", fixture="clean_server")
    with pytest.raises(ValidationError):
        ProjectCreate(name="  ")


def test_drift_report_defaults_are_conservative() -> None:
    report = DriftReport(server_name="s", drifted=False, old_hash="a", new_hash="a")
    assert report.severity is Severity.INFO
    assert report.recommended_action == "none"
    assert not report.requires_review
