"""Compare a current tool snapshot against an approved one.

A hash match only says the definitions are *unchanged since approval*; it says nothing about
whether the approved definitions were trustworthy to begin with. Conversely, a mismatch is a
signal to review, not proof of malice.

Severity policy (defaults)
--------------------------
* Any change to a trusted tool requires review.
* Permission, destructive-capability, or capability-escalation changes are HIGH.
* Tool removal is MEDIUM. A new tool is MEDIUM (HIGH if it is high-risk or suspicious).
* Description-only changes are MEDIUM, unless the change *introduces* suspicious content, in
  which case they are HIGH (CRITICAL when several independent poisoning rules fire).
* A change of server name is HIGH; a version-only change is LOW.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from guardbench.analysis.capabilities import profile_tool
from guardbench.analysis.metadata_analyzer import STRONG_POISONING_RULES, analyze_tool
from guardbench.analysis.severity import max_severity
from guardbench.domain.enums import Capability, FindingCategory, Severity
from guardbench.domain.schemas import (
    CAPABILITIES_META_KEY,
    DriftReport,
    FieldChange,
    Finding,
    ToolDefinitionData,
    ToolSnapshotData,
)

MAX_TEXT_IN_REPORT = 2000
#: Gaining any of these on an existing tool is a permission escalation.
_ESCALATION_CAPS = frozenset({Capability.WRITE, Capability.DELETE, Capability.SEND, Capability.EXECUTE})
#: A brand-new tool is HIGH only if it can do real damage; a new write tool is merely MEDIUM.
_DANGEROUS_CAPS = frozenset({Capability.DELETE, Capability.SEND, Capability.EXECUTE})
#: Annotation hints where moving in this direction widens what the tool may do.
_WIDENING_HINTS: dict[str, bool] = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}
#: Finding categories that describe metadata *content* rather than capability or schema shape.
_CONTENT_CATEGORIES = frozenset(
    {FindingCategory.TOOL_POISONING, FindingCategory.CROSS_TOOL_REFERENCE, FindingCategory.PURPOSE_MISMATCH}
)
ACTION_NONE = "none"
ACTION_REVIEW = "review"
ACTION_BLOCK = "block_until_reviewed"
ACTION_QUARANTINE = "quarantine"


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_TEXT_IN_REPORT:
        return value[:MAX_TEXT_IN_REPORT] + "...[truncated]"
    return value


def _change(
    tool: str, field: str, old: Any, new: Any, old_hash: str | None, new_hash: str | None
) -> FieldChange:
    return FieldChange(
        tool_name=tool,
        field=field,
        old_value=_clip(old),
        new_value=_clip(new),
        old_hash=old_hash,
        new_hash=new_hash,
    )


def _as_definition(normalized: dict[str, Any]) -> ToolDefinitionData:
    """Rebuild an analyzable definition from a stored normalized tool."""
    return ToolDefinitionData(
        name=normalized["name"],
        title=normalized.get("title"),
        description=normalized.get("description"),
        input_schema=normalized.get("input_schema") or {"type": "object"},
        output_schema=normalized.get("output_schema"),
        annotations=normalized.get("annotations") or {},
        meta=normalized.get("meta") or {},
    )


def _declared_capabilities(normalized: dict[str, Any]) -> list[str]:
    raw = (normalized.get("meta") or {}).get(CAPABILITIES_META_KEY, [])
    return sorted(c for c in raw if isinstance(c, str)) if isinstance(raw, list) else []


def _finding_keys(findings: list[Finding]) -> set[tuple[str, str | None]]:
    return {(f.rule_id, f.location) for f in findings if f.severity >= Severity.MEDIUM}


def _introduced_findings(
    old: dict[str, Any] | None, new: dict[str, Any], siblings: list[ToolDefinitionData]
) -> list[Finding]:
    """Findings at MEDIUM or above that the *new* definition has and the old one did not."""
    new_def = _as_definition(new)
    new_findings = analyze_tool(new_def, sibling_tools=siblings)
    if old is None:
        return [f for f in new_findings if f.severity >= Severity.MEDIUM]
    seen = _finding_keys(analyze_tool(_as_definition(old), sibling_tools=siblings))
    return [f for f in new_findings if f.severity >= Severity.MEDIUM and (f.rule_id, f.location) not in seen]


def _content_findings(findings: list[Finding]) -> list[Finding]:
    """Findings about what the metadata *says* (poisoning), as opposed to what the tool can do."""
    return [f for f in findings if f.category in _CONTENT_CATEGORIES]


def _suspicion_severity(findings: list[Finding]) -> Severity:
    """Severity of poisoned content that a change introduced: HIGH, CRITICAL for several rules."""
    content = _content_findings(findings)
    poisoning = {f.rule_id for f in content if f.rule_id in STRONG_POISONING_RULES | {"MA-090"}}
    if "MA-090" in poisoning or len(poisoning) >= 3:
        return Severity.CRITICAL
    return Severity.HIGH if content else Severity.INFO


def _introduced_severity(findings: list[Finding]) -> Severity:
    """Severity of everything a change introduced: poisoned content, or other new risk (capped at HIGH)."""
    other = [f.severity for f in findings if f.category not in _CONTENT_CATEGORIES]
    capped = max_severity((min(sev, Severity.HIGH) for sev in other), default=Severity.INFO)
    return max_severity([_suspicion_severity(findings), capped])


def _introduced_reason(findings: list[Finding]) -> str:
    """Accurate wording: content suspicion and capability or schema risk are different things."""
    if _content_findings(findings):
        return "introduces suspicious content"
    return "introduces new risk findings " + str(sorted({f.rule_id for f in findings}))


def _hint_widening(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Annotation hints that moved in a permission-widening direction."""
    widened = []
    for hint, widening_value in _WIDENING_HINTS.items():
        before, after = old.get(hint), new.get(hint)
        if before != after and after == widening_value and before != widening_value:
            widened.append(f"{hint}: {before!r} -> {after!r}")
    return widened


def compare_snapshots(
    approved: ToolSnapshotData,
    current: ToolSnapshotData,
    *,
    trusted_tools: Collection[str] | None = None,
) -> DriftReport:
    """Compare ``current`` against the ``approved`` baseline and grade the difference."""
    trusted = set(trusted_tools) if trusted_tools is not None else set(approved.normalized_tools)
    report = DriftReport(
        server_name=current.server_name,
        drifted=False,
        old_hash=approved.snapshot_hash,
        new_hash=current.snapshot_hash,
    )
    severities: list[Severity] = []
    reasons: list[str] = []
    suspicious: list[Finding] = []

    old_tools, new_tools = approved.normalized_tools, current.normalized_tools
    siblings = [_as_definition(t) for t in new_tools.values()]

    report.added_tools = sorted(set(new_tools) - set(old_tools))
    report.removed_tools = sorted(set(old_tools) - set(new_tools))

    for name in report.added_tools:
        introduced = _introduced_findings(None, new_tools[name], siblings)
        caps = profile_tool(_as_definition(new_tools[name])).effective
        if introduced:
            sev, why = (
                _introduced_severity(introduced),
                _introduced_reason(introduced).replace("introduces", "carries"),
            )
        elif caps & _DANGEROUS_CAPS:
            sev, why = Severity.HIGH, f"declares {sorted(c.value for c in caps & _DANGEROUS_CAPS)}"
        else:
            sev, why = Severity.MEDIUM, "was not part of the approved snapshot"
        suspicious.extend(introduced)
        severities.append(sev)
        reasons.append(f"tool '{name}' was added and {why} ({sev.value})")

    for name in report.removed_tools:
        severities.append(Severity.MEDIUM)
        reasons.append(f"tool '{name}' was removed (medium)")

    for name in sorted(set(old_tools) & set(new_tools)):
        if approved.tool_hashes.get(name) == current.tool_hashes.get(name):
            continue
        sev_tool = _compare_tool(name, old_tools[name], new_tools[name], approved, current, report, reasons)
        introduced = _introduced_findings(old_tools[name], new_tools[name], siblings)
        if introduced:
            suspicious.extend(introduced)
            sev_tool = max_severity([sev_tool, _introduced_severity(introduced)])
            reasons.append(f"tool '{name}': the change {_introduced_reason(introduced)} ({sev_tool.value})")
        if name not in trusted:
            reasons.append(f"tool '{name}' was not trusted; reported for visibility")
        severities.append(sev_tool)

    old_id, new_id = approved.identity, current.identity
    for field, before, after, sev in (
        ("identity.name", old_id.name, new_id.name, Severity.HIGH),
        ("identity.version", old_id.version, new_id.version, Severity.LOW),
        ("identity.protocol_version", old_id.protocol_version, new_id.protocol_version, Severity.LOW),
    ):
        if before != after:
            report.changed_identity.append(_change(current.server_name, field, before, after, None, None))
            severities.append(sev)
            reasons.append(f"server {field.split('.')[1]} changed: {before!r} -> {after!r} ({sev.value})")

    report.drifted = bool(severities)
    report.suspicious_findings = suspicious
    report.reasons = reasons
    if report.drifted:
        report.severity = max_severity(severities)
        report.requires_review = True  # any change to a trusted baseline needs a human decision
        report.recommended_action = _action_for(report.severity)
    return report


def _compare_tool(
    name: str,
    old: dict[str, Any],
    new: dict[str, Any],
    approved: ToolSnapshotData,
    current: ToolSnapshotData,
    report: DriftReport,
    reasons: list[str],
) -> Severity:
    """Record every field-level change for one tool and return its severity."""
    oh, nh = approved.tool_hashes.get(name), current.tool_hashes.get(name)
    severities: list[Severity] = []

    for prose in ("description", "title"):
        if old.get(prose) != new.get(prose):
            report.changed_descriptions.append(_change(name, prose, old.get(prose), new.get(prose), oh, nh))
            severities.append(Severity.MEDIUM)
            reasons.append(f"tool '{name}' {prose} changed (medium)")

    if old.get("input_schema") != new.get("input_schema"):
        report.changed_input_schemas.append(
            _change(name, "input_schema", old.get("input_schema"), new.get("input_schema"), oh, nh)
        )
        severities.append(Severity.MEDIUM)
        reasons.append(f"tool '{name}' input schema changed (medium)")
        old_req = set((old.get("input_schema") or {}).get("required", []))
        new_req = set((new.get("input_schema") or {}).get("required", []))
        if old_req != new_req:
            report.changed_input_schemas.append(
                _change(name, "input_schema.required", sorted(old_req), sorted(new_req), oh, nh)
            )
            added, dropped = sorted(new_req - old_req), sorted(old_req - new_req)
            reasons.append(f"tool '{name}' required fields changed: +{added} -{dropped}")

    if old.get("output_schema") != new.get("output_schema"):
        report.changed_output_schemas.append(
            _change(name, "output_schema", old.get("output_schema"), new.get("output_schema"), oh, nh)
        )
        severities.append(Severity.MEDIUM)
        reasons.append(f"tool '{name}' output schema changed (medium)")

    old_ann, new_ann = old.get("annotations") or {}, new.get("annotations") or {}
    if old_ann != new_ann:
        report.changed_annotations.append(_change(name, "annotations", old_ann, new_ann, oh, nh))
        widened = _hint_widening(old_ann, new_ann)
        severities.append(Severity.HIGH if widened else Severity.LOW)
        reasons.append(
            f"tool '{name}' permission hints widened: {widened} (high)"
            if widened
            else f"tool '{name}' annotations changed (low)"
        )

    old_caps, new_caps = _declared_capabilities(old), _declared_capabilities(new)
    if old_caps != new_caps:
        report.changed_capabilities.append(_change(name, "capabilities", old_caps, new_caps, oh, nh))
        gained = set(new_caps) - set(old_caps)
        escalated = bool(gained & {c.value for c in _ESCALATION_CAPS})
        severities.append(Severity.HIGH if escalated else Severity.LOW)
        reasons.append(
            f"tool '{name}' capabilities escalated: +{sorted(gained)} (high)"
            if escalated
            else f"tool '{name}' capabilities changed (low)"
        )

    old_meta = {k: v for k, v in (old.get("meta") or {}).items() if k != CAPABILITIES_META_KEY}
    new_meta = {k: v for k, v in (new.get("meta") or {}).items() if k != CAPABILITIES_META_KEY}
    if old_meta != new_meta:
        report.changed_annotations.append(_change(name, "meta", old_meta, new_meta, oh, nh))
        severities.append(Severity.LOW)
        reasons.append(f"tool '{name}' metadata changed (low)")

    return max_severity(severities, default=Severity.LOW)


def _action_for(severity: Severity) -> str:
    if severity is Severity.CRITICAL:
        return ACTION_QUARANTINE
    if severity is Severity.HIGH:
        return ACTION_BLOCK
    return ACTION_REVIEW


def drift_finding(report: DriftReport, server_name: str, *, detected_by: str) -> Finding:
    """Turn a drift report into an explainable finding (deterministic: a hash mismatch is a fact)."""
    return Finding(
        rule_id="DR-001",
        title="Tool definitions changed since the approved baseline",
        category=FindingCategory.TOOL_DEFINITION_DRIFT,
        severity=report.severity,
        confidence=1.0,
        description="; ".join(report.reasons) or "The tool set no longer matches the approved snapshot.",
        location="tool snapshot",
        matched_evidence=f"{report.old_hash[:12]} -> {report.new_hash[:12]}",
        remediation="Review each change against the approved baseline before trusting the server again. "
        "A hash match only proves the definitions are unchanged, not that they were ever safe.",
        deterministic=True,
        server_name=server_name,
        evidence={
            "old_hash": report.old_hash,
            "new_hash": report.new_hash,
            "recommended_action": report.recommended_action,
            "changed_tools": sorted(
                {
                    c.tool_name
                    for c in report.changed_descriptions
                    + report.changed_input_schemas
                    + report.changed_annotations
                    + report.changed_capabilities
                }
            ),
        },
        detected_by=detected_by,
    )
