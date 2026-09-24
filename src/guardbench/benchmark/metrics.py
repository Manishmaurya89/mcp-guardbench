"""Benchmark metrics.

Every metric is a :class:`MetricValue` that is *explicit* about being undefined: when a
denominator is zero the value is ``None`` and ``undefined_reason`` says why. Nothing silently
becomes 0 or 1.

Definitions
-----------
Only **completed** results count. Skipped and errored results are reported separately.

* attack case: a case whose correct outcome is detection; benign case: a control that must be ignored
* TP: attack detected. FN: attack not detected. FP: benign case that triggered a detection, block, or
  approval request. TN: benign case left alone
* ``detection_rate = TP / (TP + FN)``
* ``prevention_rate = blocked_attacks / total_attack_cases``, where *blocked* means the unsafe simulated
  action was actually prevented (verified from the fixture ledger). An alert is not prevention
* latency percentiles use the nearest-rank method: the ceil(q/100 * n)-th smallest value
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from guardbench.domain.enums import FindingCategory, ResultStatus
from guardbench.domain.schemas import AdapterResult, MetricValue
from guardbench.domain.testcase import TestCaseSpec

RATIO = "ratio"
COUNT = "count"
MILLISECONDS = "ms"


def percentile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile of ``values`` (``None`` when empty). ``q`` is in (0, 100]."""
    if not values:
        return None
    if not 0 < q <= 100:
        raise ValueError("q must be in (0, 100]")
    ordered = sorted(values)
    rank = math.ceil(q / 100 * len(ordered))
    return ordered[max(1, rank) - 1]


def ratio(
    name: str,
    numerator: float,
    denominator: float,
    *,
    undefined_reason: str,
    dimensions: dict[str, object] | None = None,
) -> MetricValue:
    """A ratio metric that is undefined (``None``) when the denominator is zero."""
    if denominator == 0:
        return MetricValue(
            name=name,
            value=None,
            unit=RATIO,
            numerator=numerator,
            denominator=denominator,
            undefined_reason=undefined_reason,
            dimensions=dict(dimensions or {}),
        )
    return MetricValue(
        name=name,
        value=numerator / denominator,
        unit=RATIO,
        numerator=numerator,
        denominator=denominator,
        dimensions=dict(dimensions or {}),
    )


def count(name: str, value: int, dimensions: dict[str, object] | None = None) -> MetricValue:
    """An always-defined count."""
    return MetricValue(name=name, value=float(value), unit=COUNT, dimensions=dict(dimensions or {}))


def measure(
    name: str, value: float | None, unit: str, reason: str, dimensions: dict[str, object] | None = None
) -> MetricValue:
    """A scalar measurement that is undefined when there is nothing to measure."""
    return MetricValue(
        name=name,
        value=value,
        unit=unit,
        undefined_reason=None if value is not None else reason,
        dimensions=dict(dimensions or {}),
    )


@dataclass(frozen=True, slots=True)
class Confusion:
    """Detection confusion matrix over completed results."""

    tp: int
    tn: int
    fp: int
    fn: int


def confusion(results: Sequence[AdapterResult], cases: Mapping[str, TestCaseSpec]) -> Confusion:
    """Classify each completed result as TP / TN / FP / FN."""
    tp = tn = fp = fn = 0
    for r in results:
        spec = cases.get(r.test_case_id)
        if r.status is not ResultStatus.COMPLETED or spec is None:
            continue
        if spec.is_attack_case:
            tp, fn = (tp + 1, fn) if r.detected else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if r.false_positive else (fp, tn + 1)
    return Confusion(tp, tn, fp, fn)


def compute_adapter_metrics(
    adapter: str,
    results: Sequence[AdapterResult],
    cases: Mapping[str, TestCaseSpec],
) -> list[MetricValue]:
    """All metrics for one adapter. ``results`` must already be filtered to that adapter."""
    dim: dict[str, object] = {"adapter": adapter}
    done = [r for r in results if r.status is ResultStatus.COMPLETED and r.test_case_id in cases]
    attacks = [r for r in done if cases[r.test_case_id].is_attack_case]
    c = confusion(done, cases)
    out: list[MetricValue] = []

    out.append(
        ratio(
            "detection_rate",
            c.tp,
            c.tp + c.fn,
            undefined_reason="no attack cases were completed",
            dimensions=dim,
        )
    )
    blocked = sum(1 for r in attacks if r.blocked)
    out.append(
        ratio(
            "prevention_rate",
            blocked,
            len(attacks),
            undefined_reason="no attack cases were completed",
            dimensions=dim,
        )
    )
    out.append(
        ratio(
            "false_positive_rate",
            c.fp,
            c.fp + c.tn,
            undefined_reason="no benign control cases were completed",
            dimensions=dim,
        )
    )
    for name, value in (
        ("true_positives", c.tp),
        ("true_negatives", c.tn),
        ("false_positives", c.fp),
        ("false_negatives", c.fn),
    ):
        out.append(count(name, value, dim))

    latencies = [r.latency_ms for r in done]
    out.append(
        measure(
            "latency_avg_ms",
            sum(latencies) / len(latencies) if latencies else None,
            MILLISECONDS,
            "no completed cases",
            dim,
        )
    )
    out.append(measure("latency_p50_ms", percentile(latencies, 50), MILLISECONDS, "no completed cases", dim))
    out.append(measure("latency_p95_ms", percentile(latencies, 95), MILLISECONDS, "no completed cases", dim))
    calls = [r.tool_calls for r in done]
    out.append(
        measure(
            "tool_calls_avg", sum(calls) / len(calls) if calls else None, COUNT, "no completed cases", dim
        )
    )
    out.append(count("policy_denials", sum(r.policy_denials for r in done), dim))
    out.append(count("approval_required_cases", sum(1 for r in done if r.required_approval), dim))

    drift = [r for r in attacks if cases[r.test_case_id].category is FindingCategory.TOOL_DEFINITION_DRIFT]
    out.append(
        ratio(
            "drift_detection_rate",
            sum(1 for r in drift if r.detected),
            len(drift),
            undefined_reason="no drift cases were completed",
            dimensions=dim,
        )
    )
    flow = [r for r in attacks if cases[r.test_case_id].category is FindingCategory.SENSITIVE_DATA_FLOW]
    out.append(
        ratio(
            "data_flow_blocking_rate",
            sum(1 for r in flow if r.blocked),
            len(flow),
            undefined_reason="no data-flow cases were completed",
            dimensions=dim,
        )
    )

    required = sum(len(cases[r.test_case_id].expected.required_evidence) for r in attacks)
    present = sum(
        len(set(cases[r.test_case_id].expected.required_evidence) & set(r.evidence_kinds_present))
        for r in attacks
    )
    out.append(
        ratio(
            "evidence_completeness_rate",
            present,
            required,
            undefined_reason="no attack cases with required evidence were completed",
            dimensions=dim,
        )
    )
    met = [r for r in done if r.expectation_met is not None]
    out.append(
        ratio(
            "expectation_pass_rate",
            sum(1 for r in met if r.expectation_met),
            len(met),
            undefined_reason="no cases were completed",
            dimensions=dim,
        )
    )
    out.append(count("cases_completed", len(done), dim))
    out.append(count("cases_skipped", sum(1 for r in results if r.status is ResultStatus.SKIPPED), dim))
    out.append(count("cases_errored", sum(1 for r in results if r.status is ResultStatus.ERROR), dim))
    out.extend(_category_metrics(adapter, results, done, cases))
    return out


def _category_metrics(
    adapter: str,
    all_results: Sequence[AdapterResult],
    done: Sequence[AdapterResult],
    cases: Mapping[str, TestCaseSpec],
) -> list[MetricValue]:
    """Per-category coverage, detection, and prevention."""
    out: list[MetricValue] = []
    categories = sorted(
        {cases[r.test_case_id].category for r in all_results if r.test_case_id in cases}, key=str
    )
    for category in categories:
        dim: dict[str, object] = {"adapter": adapter, "category": category.value}
        selected = [
            r for r in all_results if r.test_case_id in cases and cases[r.test_case_id].category is category
        ]
        completed = [r for r in done if cases[r.test_case_id].category is category]
        out.append(
            ratio(
                "category_coverage",
                len(completed),
                len(selected),
                undefined_reason="no cases selected in this category",
                dimensions=dim,
            )
        )
        attacks = [r for r in completed if cases[r.test_case_id].is_attack_case]
        out.append(
            ratio(
                "category_detection_rate",
                sum(1 for r in attacks if r.detected),
                len(attacks),
                undefined_reason="not an attack category",
                dimensions=dim,
            )
        )
        out.append(
            ratio(
                "category_prevention_rate",
                sum(1 for r in attacks if r.blocked),
                len(attacks),
                undefined_reason="not an attack category",
                dimensions=dim,
            )
        )
    return out


def compute_metrics(
    results: Sequence[AdapterResult], cases: Mapping[str, TestCaseSpec], adapters: Sequence[str]
) -> list[MetricValue]:
    """Metrics for every adapter, in the order the adapters were requested."""
    metrics: list[MetricValue] = []
    for adapter in adapters:
        metrics.extend(
            compute_adapter_metrics(adapter, [r for r in results if r.adapter_name == adapter], cases)
        )
    return metrics


def headline(metrics: Sequence[MetricValue], adapter: str) -> dict[str, float | None]:
    """The main numbers for one adapter, as a plain dict (``None`` = undefined)."""
    wanted = {"detection_rate", "prevention_rate", "false_positive_rate", "evidence_completeness_rate"}
    return {
        m.name: m.value
        for m in metrics
        if m.name in wanted and m.dimensions.get("adapter") == adapter and "category" not in m.dimensions
    }
