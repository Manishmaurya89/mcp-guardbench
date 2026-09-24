"""Benchmark metrics: definitions, undefined handling, and category breakdowns."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from guardbench.benchmark.metrics import (
    compute_adapter_metrics,
    compute_metrics,
    confusion,
    headline,
    percentile,
    ratio,
)
from guardbench.domain.enums import (
    AttackStage,
    EvidenceKind,
    FindingCategory,
    ResultStatus,
    SafeBehavior,
    Severity,
)
from guardbench.domain.schemas import AdapterResult, MetricValue
from guardbench.domain.testcase import ExpectedOutcome, TestCaseSpec

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SAFE = list(SafeBehavior)


def spec(case_id: str, category: FindingCategory, evidence: list[EvidenceKind] | None = None) -> TestCaseSpec:
    benign = category is FindingCategory.BENIGN_CONTROL
    return TestCaseSpec(
        id=case_id,
        name=f"case {case_id}",
        category=category,
        severity=Severity.HIGH,
        description="a synthetic test case for metrics",
        attack_stage=AttackStage.TOOL_CALL,
        server_fixture="clean_server",
        expected=ExpectedOutcome(
            should_detect=not benign,
            required_evidence=[] if benign else (evidence or [EvidenceKind.DETECTION_RULE]),
        ),
        safe_behavior=SAFE,
    )


def result(
    case_id: str,
    *,
    detected: bool = False,
    blocked: bool = False,
    fp: bool = False,
    status: ResultStatus = ResultStatus.COMPLETED,
    latency: float = 1.0,
    calls: int = 0,
    denials: int = 0,
    approval: bool = False,
    kinds: list[EvidenceKind] | None = None,
    adapter: str = "a",
) -> AdapterResult:
    return AdapterResult(
        adapter_name=adapter,
        adapter_version="1",
        test_case_id=case_id,
        started_at=NOW,
        completed_at=NOW,
        status=status,
        detected=detected,
        blocked=blocked,
        false_positive=fp,
        required_approval=approval,
        latency_ms=latency,
        tool_calls=calls,
        policy_denials=denials,
        evidence_kinds_present=kinds or [],
    )


def by_name(metrics: list[MetricValue], name: str, **dims: object) -> MetricValue:
    matches = [
        m for m in metrics if m.name == name and all(m.dimensions.get(k) == v for k, v in dims.items())
    ]
    assert len(matches) == 1, (name, dims, len(matches))
    return matches[0]


CASES = {
    "TP-001": spec("TP-001", FindingCategory.TOOL_POISONING),
    "TP-002": spec("TP-002", FindingCategory.TOOL_POISONING),
    "RD-001": spec("RD-001", FindingCategory.TOOL_DEFINITION_DRIFT),
    "DF-001": spec("DF-001", FindingCategory.SENSITIVE_DATA_FLOW),
    "BN-001": spec("BN-001", FindingCategory.BENIGN_CONTROL),
    "BN-002": spec("BN-002", FindingCategory.BENIGN_CONTROL),
}


# ---------------------------------------------------------------- primitives


def test_nearest_rank_percentiles() -> None:
    values = list(range(1, 11))
    assert percentile(values, 50) == 5
    assert percentile(values, 95) == 10
    assert percentile(values, 100) == 10
    assert percentile([7.5], 95) == 7.5
    assert percentile([3, 1, 2], 50) == 2, "input order must not matter"
    assert percentile([], 50) is None


@pytest.mark.parametrize("q", [0, -1, 101])
def test_percentile_rejects_out_of_range_quantiles(q: float) -> None:
    with pytest.raises(ValueError, match="q must be"):
        percentile([1, 2, 3], q)


def test_a_zero_denominator_makes_a_ratio_undefined_with_a_reason() -> None:
    m = ratio("x", 0, 0, undefined_reason="nothing to divide")
    assert m.value is None
    assert m.undefined_reason == "nothing to divide"
    assert (m.numerator, m.denominator) == (0, 0)


def test_a_defined_ratio_carries_its_numerator_and_denominator() -> None:
    m = ratio("x", 3, 4, undefined_reason="n/a")
    assert m.value == 0.75 and m.undefined_reason is None and (m.numerator, m.denominator) == (3, 4)


# ---------------------------------------------------------------- confusion and rates


def test_confusion_matrix_classifies_attacks_and_benign_cases() -> None:
    results = [
        result("TP-001", detected=True),
        result("TP-002", detected=False),
        result("BN-001", fp=False),
        result("BN-002", fp=True, detected=True),
    ]
    c = confusion(results, CASES)
    assert (c.tp, c.fn, c.tn, c.fp) == (1, 1, 1, 1)


def test_detection_and_prevention_rates_follow_their_definitions() -> None:
    results = [
        result("TP-001", detected=True, blocked=True),
        result("TP-002", detected=True, blocked=False),  # alert only
        result("RD-001", detected=False, blocked=False),
        result("DF-001", detected=True, blocked=True),
        result("BN-001"),
    ]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "detection_rate").value == pytest.approx(3 / 4)  # TP / (TP + FN)
    assert by_name(metrics, "prevention_rate").value == pytest.approx(2 / 4)  # blocked / attack cases
    assert by_name(metrics, "true_positives").value == 3
    assert by_name(metrics, "false_negatives").value == 1
    assert by_name(metrics, "true_negatives").value == 1
    assert by_name(metrics, "false_positives").value == 0


def test_an_alert_is_not_prevention() -> None:
    results = [result("TP-001", detected=True, blocked=False), result("TP-002", detected=True, blocked=False)]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "detection_rate").value == 1.0
    assert by_name(metrics, "prevention_rate").value == 0.0


def test_false_positive_rate_uses_benign_cases_only() -> None:
    results = [result("BN-001", fp=True, detected=True), result("BN-002"), result("TP-001", detected=True)]
    assert by_name(compute_adapter_metrics("a", results, CASES), "false_positive_rate").value == 0.5


# ---------------------------------------------------------------- undefined metrics


def test_metrics_are_undefined_not_zero_when_there_is_nothing_to_measure() -> None:
    only_benign = compute_adapter_metrics("a", [result("BN-001"), result("BN-002")], CASES)
    for name in ("detection_rate", "prevention_rate", "drift_detection_rate", "data_flow_blocking_rate"):
        m = by_name(only_benign, name)
        assert m.value is None and m.undefined_reason, name
    assert by_name(only_benign, "false_positive_rate").value == 0.0  # defined: two benign cases

    only_attacks = compute_adapter_metrics("a", [result("TP-001", detected=True)], CASES)
    assert by_name(only_attacks, "false_positive_rate").value is None
    assert by_name(only_attacks, "drift_detection_rate").value is None  # no drift case was run


def test_an_adapter_with_no_completed_results_never_divides_by_zero() -> None:
    skipped = [result(cid, status=ResultStatus.SKIPPED) for cid in ("TP-001", "BN-001")]
    metrics = compute_adapter_metrics("a", skipped, CASES)
    undefined = [m for m in metrics if m.unit == "ratio" and "category" not in m.dimensions]
    assert undefined and all(m.value is None for m in undefined)
    assert by_name(metrics, "cases_skipped").value == 2
    assert by_name(metrics, "cases_completed").value == 0
    assert by_name(metrics, "latency_p95_ms").value is None


def test_skipped_and_errored_results_are_excluded_from_every_denominator() -> None:
    results = [
        result("TP-001", detected=True, blocked=True),
        result("TP-002", status=ResultStatus.SKIPPED),
        result("RD-001", status=ResultStatus.ERROR),
    ]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "detection_rate").value == 1.0
    assert by_name(metrics, "prevention_rate").denominator == 1
    assert (by_name(metrics, "cases_skipped").value, by_name(metrics, "cases_errored").value) == (1, 1)


# ---------------------------------------------------------------- operational metrics


def test_latency_and_tool_call_statistics() -> None:
    results = [result("TP-001", latency=lat, calls=c) for lat, c in ((1, 2), (2, 4), (3, 6), (4, 8))]
    results = [r.model_copy(update={"test_case_id": cid}) for r, cid in zip(results, CASES, strict=False)]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "latency_avg_ms").value == 2.5
    assert by_name(metrics, "latency_p50_ms").value == 2
    assert by_name(metrics, "latency_p95_ms").value == 4
    assert by_name(metrics, "tool_calls_avg").value == 5


def test_policy_denials_and_approval_counts() -> None:
    results = [
        result("TP-001", denials=2, approval=True),
        result("TP-002", denials=1),
        result("RD-001", approval=True),
    ]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "policy_denials").value == 3
    assert by_name(metrics, "approval_required_cases").value == 2


def test_drift_and_data_flow_rates_only_look_at_their_own_categories() -> None:
    results = [
        result("RD-001", detected=True),
        result("DF-001", blocked=True, detected=True),
        result("TP-001", detected=False, blocked=False),
    ]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "drift_detection_rate").value == 1.0
    assert by_name(metrics, "data_flow_blocking_rate").value == 1.0


def test_evidence_completeness_counts_required_kinds_present() -> None:
    cases = {
        "TP-001": spec(
            "TP-001",
            FindingCategory.TOOL_POISONING,
            [EvidenceKind.DETECTION_RULE, EvidenceKind.POLICY_DECISION],
        ),
        "TP-002": spec(
            "TP-002", FindingCategory.TOOL_POISONING, [EvidenceKind.DETECTION_RULE, EvidenceKind.EVENT_TRACE]
        ),
    }
    results = [
        result("TP-001", kinds=[EvidenceKind.DETECTION_RULE]),
        result(
            "TP-002",
            kinds=[EvidenceKind.DETECTION_RULE, EvidenceKind.EVENT_TRACE, EvidenceKind.DATA_FLOW_PATH],
        ),
    ]
    m = by_name(compute_adapter_metrics("a", results, cases), "evidence_completeness_rate")
    assert (m.numerator, m.denominator, m.value) == (3, 4, 0.75), "extra, unrequired evidence earns nothing"


# ---------------------------------------------------------------- category coverage


def test_per_category_coverage_reflects_skipped_cases() -> None:
    results = [
        result("TP-001", detected=True, blocked=True),
        result("TP-002", status=ResultStatus.SKIPPED),
        result("RD-001", detected=True),
    ]
    metrics = compute_adapter_metrics("a", results, CASES)
    assert by_name(metrics, "category_coverage", category="tool_poisoning").value == 0.5
    assert by_name(metrics, "category_coverage", category="tool_definition_drift").value == 1.0
    assert by_name(metrics, "category_detection_rate", category="tool_poisoning").value == 1.0
    assert by_name(metrics, "category_prevention_rate", category="tool_poisoning").value == 1.0
    assert by_name(metrics, "category_prevention_rate", category="tool_definition_drift").value == 0.0


def test_benign_categories_have_coverage_but_no_attack_rates() -> None:
    metrics = compute_adapter_metrics("a", [result("BN-001")], CASES)
    assert by_name(metrics, "category_coverage", category="benign_control").value == 1.0
    assert by_name(metrics, "category_detection_rate", category="benign_control").value is None


# ---------------------------------------------------------------- multi-adapter


def test_compute_metrics_keeps_adapters_separate_and_ordered() -> None:
    results = [
        result("TP-001", detected=True, blocked=True, adapter="strong"),
        result("TP-001", detected=False, adapter="weak"),
    ]
    metrics = compute_metrics(results, CASES, ["weak", "strong"])
    assert headline(metrics, "strong")["detection_rate"] == 1.0
    assert headline(metrics, "weak")["detection_rate"] == 0.0
    assert metrics[0].dimensions["adapter"] == "weak"


def test_headline_returns_only_the_top_level_rates() -> None:
    metrics = compute_adapter_metrics("a", [result("TP-001", detected=True)], CASES)
    assert set(headline(metrics, "a")) == {
        "detection_rate",
        "prevention_rate",
        "false_positive_rate",
        "evidence_completeness_rate",
    }
