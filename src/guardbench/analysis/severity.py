"""Deterministic severity calibration and aggregation.

Rules author a *base* severity. Confidence and corroboration then adjust it, so a weak,
single-signal match cannot masquerade as a critical finding and independent signals on
the same tool reinforce each other.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from guardbench.domain.enums import Severity
from guardbench.domain.schemas import Finding

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

#: Below this confidence a finding is downgraded one level; below the second, two levels.
LOW_CONFIDENCE = 0.5
VERY_LOW_CONFIDENCE = 0.3


def shift(severity: Severity, steps: int) -> Severity:
    """Move ``severity`` up (positive) or down (negative), clamped to the valid range."""
    index = max(0, min(len(_ORDER) - 1, severity.rank + steps))
    return _ORDER[index]


def calibrate(base: Severity, confidence: float) -> Severity:
    """Downgrade a base severity when the rule's confidence is low.

    >>> calibrate(Severity.HIGH, 0.9)
    <Severity.HIGH: 'high'>
    >>> calibrate(Severity.HIGH, 0.4)
    <Severity.MEDIUM: 'medium'>
    """
    if confidence < VERY_LOW_CONFIDENCE:
        return shift(base, -2)
    if confidence < LOW_CONFIDENCE:
        return shift(base, -1)
    return base


def max_severity(severities: Iterable[Severity], default: Severity = Severity.INFO) -> Severity:
    """The highest severity in ``severities`` (``default`` when empty)."""
    return max(severities, default=default)


def aggregate(findings: Sequence[Finding]) -> Severity:
    """Overall severity for a set of findings about one subject.

    Takes the maximum, then escalates one level when two or more *distinct categories*
    each reach at least ``medium``: independent signals corroborate one another.
    """
    if not findings:
        return Severity.INFO
    top = max_severity(f.severity for f in findings)
    strong_categories = {f.category for f in findings if f.severity >= Severity.MEDIUM}
    if len(strong_categories) >= 2 and top < Severity.CRITICAL:
        return shift(top, 1)
    return top


def is_actionable(severity: Severity, threshold: Severity = Severity.MEDIUM) -> bool:
    """Whether ``severity`` meets the threshold at which a finding counts as a detection."""
    return severity >= threshold
