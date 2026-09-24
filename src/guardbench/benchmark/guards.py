"""The two reference security controls, expressed as guards for the scenario runner.

* :class:`StaticAnalyzerGuard` inspects tool metadata and definition drift and **alerts**. It sits
  outside the call path, so it can never prevent anything. This is deliberate: it makes the
  difference between *detection* and *prevention* visible in the metrics.
* :class:`RuntimePolicyGuard` sits in the call path. It registers tools, quarantines poisoned
  or drifted ones, evaluates every call against the deterministic policy, and bounds and
  inspects every response before it reaches the model.
"""

from __future__ import annotations

from typing import Any

from guardbench.analysis.capabilities import effective_capabilities
from guardbench.analysis.drift_detector import compare_snapshots, drift_finding
from guardbench.analysis.metadata_analyzer import analyze_server
from guardbench.benchmark.runner import CallVerdict, ResponseInspection, ScenarioRun
from guardbench.domain.enums import EventType, FindingCategory, PolicyDecisionType, Severity
from guardbench.domain.schemas import Finding, PolicyDecision, ServerIdentity, ToolDefinitionData
from guardbench.mcp_lab.base import ToolCallResult
from guardbench.policy.engine import CallRequest, PolicyEngine
from guardbench.policy.models import ToolTrust, TrustStore
from guardbench.runtime.data_flow import flow_finding

D = PolicyDecisionType
POISONING_CATEGORIES = frozenset({FindingCategory.TOOL_POISONING, FindingCategory.CROSS_TOOL_REFERENCE})
_EXCERPT_CHARS = 160

#: Which finding category a policy rule maps to when it blocks something.
_RULE_CATEGORY: dict[str, FindingCategory] = {
    "POL-001": FindingCategory.POLICY_VIOLATION,
    "POL-002": FindingCategory.POLICY_VIOLATION,
    "POL-004": FindingCategory.EXCESSIVE_PERMISSION,
    "POL-005": FindingCategory.EXCESSIVE_PERMISSION,
    "POL-006": FindingCategory.EXCESSIVE_PERMISSION,
    "POL-007": FindingCategory.SENSITIVE_DATA_FLOW,
    "POL-008": FindingCategory.TOOL_POISONING,
    "POL-009": FindingCategory.TOOL_DEFINITION_DRIFT,
    "POL-010": FindingCategory.POLICY_VIOLATION,
    "POL-011": FindingCategory.EXCESSIVE_PERMISSION,
    "POL-012": FindingCategory.POLICY_VIOLATION,
    "POL-013": FindingCategory.OVERSIZED_RESPONSE,
    "POL-014": FindingCategory.RESPONSE_INJECTION,
}
#: Rules that enforce a tool's capability class (their evidence is the tool's own metadata).
_CAPABILITY_RULES = frozenset({"POL-004", "POL-005", "POL-006", "POL-011"})
_DECISION_SEVERITY = {D.DENY: Severity.HIGH, D.QUARANTINE: Severity.HIGH, D.REQUIRE_APPROVAL: Severity.MEDIUM}


def _excerpt(text: str) -> str:
    collapsed = " ".join(text.split())
    return collapsed[:_EXCERPT_CHARS] + ("..." if len(collapsed) > _EXCERPT_CHARS else "")


def _claim(finding: Finding, guard_name: str, run: ScenarioRun, event_ids: list[str]) -> Finding:
    """Attribute a finding to the control that produced it and link the evidence events."""
    return finding.model_copy(
        update={
            "detected_by": guard_name,
            "evidence_event_ids": [*finding.evidence_event_ids, *event_ids],
            "server_name": finding.server_name or run.server_name,
        }
    )


class StaticAnalyzerGuard:
    """Alert-only metadata and drift analysis. Never withholds a tool, never blocks a call."""

    name = "reference-static"

    def on_tools_listed(
        self,
        run: ScenarioRun,
        tools: list[ToolDefinitionData],
        identity: ServerIdentity,
        *,
        pin_baseline: bool,
    ) -> frozenset[str]:
        """Analyze the listing and record findings; withhold nothing."""
        for finding in analyze_server(run.server_name, tools):
            if finding.severity < Severity.LOW:
                continue
            event = run.emit(
                EventType.STATIC_FINDING,
                self.name,
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "location": finding.location,
                    "matched": finding.matched_evidence,
                },
                tool_name=finding.tool_name,
                risk_tags=(finding.category.value,),
            )
            run.findings.append(_claim(finding, self.name, run, [str(event.id)]))

        if run.baseline is not None and run.current_snapshot is not None and not pin_baseline:
            report = compare_snapshots(run.baseline, run.current_snapshot)
            if report.drifted:
                event = run.emit(
                    EventType.DRIFT_DETECTED,
                    self.name,
                    {"drift_report": report.model_dump(mode="json", exclude={"suspicious_findings"})},
                    risk_tags=("tool_definition_drift",),
                )
                run.findings.append(
                    _claim(
                        drift_finding(report, run.server_name, detected_by=self.name),
                        self.name,
                        run,
                        [str(event.id)],
                    )
                )
        return frozenset()

    def before_call(self, run: ScenarioRun, tool_name: str, arguments: dict[str, Any]) -> CallVerdict:
        """A scanner cannot stop calls."""
        return CallVerdict()

    def inspect_response(
        self, run: ScenarioRun, tool_name: str, result: ToolCallResult
    ) -> ResponseInspection:
        """A scanner does not see responses."""
        return ResponseInspection()


class RuntimePolicyGuard:
    """In-path enforcement: tool registration, per-call policy, and response inspection."""

    name = "reference-runtime"

    def __init__(self) -> None:
        self._trust = TrustStore()
        self._engine: PolicyEngine | None = None

    def _policy(self, run: ScenarioRun) -> PolicyEngine:
        if self._engine is None:
            self._engine = PolicyEngine(run.policy_config, self._trust, mode=run.mode)
        return self._engine

    # ------------------------------------------------------------------ registration

    def on_tools_listed(
        self,
        run: ScenarioRun,
        tools: list[ToolDefinitionData],
        identity: ServerIdentity,
        *,
        pin_baseline: bool,
    ) -> frozenset[str]:
        """Register tools; quarantine poisoned or drifted ones and withhold them from the model."""
        engine = self._policy(run)
        assert run.current_snapshot is not None
        snapshot = run.current_snapshot

        poisoned = self._poisoned(run, tools)
        drift_severity, drift_tools = self._drift(run, pin_baseline)

        withheld: set[str] = set()
        for tool in tools:
            name = tool.name
            baseline_hash = run.baseline.tool_hashes.get(name) if run.baseline is not None else None
            reason = None
            if name in poisoned:
                reason = "tool metadata matched poisoning rules: " + ", ".join(
                    sorted({f.rule_id for f in poisoned[name]})
                )
            self._trust.register(
                ToolTrust(
                    server_name=run.server_name,
                    tool_name=name,
                    capabilities=effective_capabilities(tool),
                    approved=baseline_hash is not None,
                    approved_hash=baseline_hash,
                    current_hash=snapshot.tool_hashes[name],
                    quarantined=name in poisoned,
                    quarantine_reason=reason,
                    drift_severity=drift_severity if name in drift_tools else None,
                )
            )
            if name in poisoned:
                withheld.add(name)
                self._registration_decision(
                    run, engine, name, D.QUARANTINE, "POL-008", reason or "", poisoned[name]
                )
            elif name in drift_tools:
                decision = (
                    engine.config.drift.on_high_severity
                    if (drift_severity or Severity.HIGH) >= engine.config.drift.quarantine_at
                    else engine.config.drift.on_low_severity
                )
                withheld.add(name)
                self._registration_decision(
                    run, engine, name, decision, "POL-009", "definition drifted from the approved hash", []
                )
        return frozenset(withheld)

    def _poisoned(self, run: ScenarioRun, tools: list[ToolDefinitionData]) -> dict[str, list[Finding]]:
        strong: dict[str, list[Finding]] = {}
        for finding in analyze_server(run.server_name, tools):
            if (
                finding.category in POISONING_CATEGORIES
                and finding.severity >= Severity.HIGH
                and finding.tool_name
            ):
                strong.setdefault(finding.tool_name, []).append(finding)
        return strong

    def _drift(self, run: ScenarioRun, pin_baseline: bool) -> tuple[Severity | None, set[str]]:
        if run.baseline is None or run.current_snapshot is None or pin_baseline:
            return None, set()
        report = compare_snapshots(run.baseline, run.current_snapshot)
        if not report.drifted:
            return None, set()
        event = run.emit(
            EventType.DRIFT_DETECTED,
            self.name,
            {"drift_report": report.model_dump(mode="json", exclude={"suspicious_findings"})},
            risk_tags=("tool_definition_drift",),
        )
        run.findings.append(
            _claim(
                drift_finding(report, run.server_name, detected_by=self.name), self.name, run, [str(event.id)]
            )
        )
        changed = {
            c.tool_name
            for group in (
                report.changed_descriptions,
                report.changed_input_schemas,
                report.changed_output_schemas,
                report.changed_annotations,
                report.changed_capabilities,
            )
            for c in group
        } | set(report.added_tools)
        return report.severity, changed

    def _registration_decision(
        self,
        run: ScenarioRun,
        engine: PolicyEngine,
        tool_name: str,
        decision: PolicyDecisionType,
        rule: str,
        reason: str,
        findings: list[Finding],
    ) -> None:
        verdict = PolicyDecision(
            policy_id=engine.config.policy_id,
            decision=decision,
            reason=reason,
            matched_rule=rule,
            evidence={"tool": tool_name, "server": run.server_name, "stage": "registration"},
            trace_id=run.trace.trace_id,
        )
        event = run.emit(
            EventType.POLICY_DECISION,
            self.name,
            {"matched_rule": rule, "reason": reason, "evidence": verdict.evidence, "stage": "registration"},
            tool_name=tool_name,
            decision=decision,
            risk_tags=(rule,),
        )
        run.denials += 1
        for finding in findings:
            run.findings.append(_claim(finding, self.name, run, [str(event.id)]))

    # ------------------------------------------------------------------ calls

    def before_call(self, run: ScenarioRun, tool_name: str, arguments: dict[str, Any]) -> CallVerdict:
        """Evaluate the call against the policy; open (never grant) an approval request if needed."""
        engine = self._policy(run)
        decision = engine.evaluate_call(
            CallRequest(
                trace_id=run.trace.trace_id,
                server_name=run.server_name,
                tool_name=tool_name,
                arguments=arguments,
                destructive_simulation_expected=run.allow_simulated_destructive,
            )
        )
        event = run.emit(
            EventType.POLICY_DECISION,
            self.name,
            {"matched_rule": decision.matched_rule, "reason": decision.reason, "evidence": decision.evidence},
            tool_name=tool_name,
            decision=decision.decision,
            risk_tags=(decision.matched_rule,),
        )
        if not decision.decision.prevents_execution:
            return CallVerdict(True, decision)

        event_ids = [str(event.id)]
        if decision.decision is D.REQUIRE_APPROVAL:
            request = run.approvals.request(
                run.trace.trace_id, run.server_name, tool_name, arguments, decision.reason
            )
            run.approvals_requested += 1
            approval_event = run.emit(
                EventType.APPROVAL_REQUESTED, self.name, request.to_payload(), tool_name=tool_name
            )
            event_ids.append(str(approval_event.id))
            if run.approvals.is_approved(request.id):  # only an explicit, recorded decision can lift the hold
                return CallVerdict(True, decision)
        else:
            run.denials += 1

        run.findings.append(self._policy_finding(run, decision, tool_name, event_ids))
        if decision.matched_rule == "POL-007":
            self._record_flows(run, decision, tool_name, arguments, event.id, event_ids)
        return CallVerdict(False, decision)

    def _policy_finding(
        self, run: ScenarioRun, decision: PolicyDecision, tool_name: str, event_ids: list[str]
    ) -> Finding:
        category = _RULE_CATEGORY.get(decision.matched_rule, FindingCategory.POLICY_VIOLATION)
        location, matched, tool_evidence = f"tools/call {tool_name}", decision.reason, {}
        tool = run.observed.get(tool_name)
        if tool is not None and decision.matched_rule in _CAPABILITY_RULES:
            # Cite the metadata that drove the decision: the tool's own declared capabilities.
            declared = sorted(c.value for c in tool.declared_capabilities)
            location = "_meta['guardbench/capabilities']" if declared else "name"
            matched = f"{tool_name}: {decision.reason}; declared capabilities={declared or 'none (inferred)'}"
            tool_evidence = {"declared_capabilities": declared, "annotations": tool.annotations}
        return Finding(
            rule_id=decision.matched_rule,
            title=f"Policy {decision.decision.value.replace('_', ' ')}: {decision.reason}",
            category=category,
            severity=_DECISION_SEVERITY.get(decision.decision, Severity.LOW),
            confidence=1.0,
            description=(
                f"Call to '{tool_name}' was {decision.decision.value} by policy {decision.policy_id}."
            ),
            location=location,
            matched_evidence=matched,
            remediation="Review the tool's capability and approval state, or adjust the policy deliberately.",
            deterministic=True,
            server_name=run.server_name,
            tool_name=tool_name,
            evidence={
                "policy_id": decision.policy_id,
                "matched_rule": decision.matched_rule,
                "decision": decision.decision.value,
                **decision.evidence,
                **tool_evidence,
            },
            evidence_event_ids=event_ids,
            detected_by=self.name,
        )

    def _record_flows(
        self,
        run: ScenarioRun,
        decision: PolicyDecision,
        tool_name: str,
        arguments: dict[str, Any],
        event_id: Any,
        event_ids: list[str],
    ) -> None:
        for marker in run.tracker.markers_in(arguments):
            if marker.marker_class.value not in run.policy_config.secrets.sensitive_classes:
                continue
            flow = run.tracker.record_flow(
                run.trace.trace_id,
                marker,
                destination_label=tool_name,
                destination_event_id=event_id,
                blocked=True,
            )
            flow_event = run.emit(
                EventType.DATA_FLOW,
                self.name,
                flow.to_evidence(),
                tool_name=tool_name,
                risk_tags=("sensitive_data_flow",),
            )
            run.findings.append(
                _claim(
                    flow_finding(flow, server_name=run.server_name, tool_name=tool_name),
                    self.name,
                    run,
                    [*event_ids, str(flow_event.id)],
                )
            )

    # ------------------------------------------------------------------ responses

    def inspect_response(
        self, run: ScenarioRun, tool_name: str, result: ToolCallResult
    ) -> ResponseInspection:
        """Bound the response, and withhold it entirely if it carries instruction-like content."""
        engine = self._policy(run)
        verdict = engine.check_response(run.trace.trace_id, run.server_name, tool_name, result.text)
        if verdict.decision is D.ALLOW:
            return ResponseInspection()

        decision_event = run.emit(
            EventType.POLICY_DECISION,
            self.name,
            {"matched_rule": verdict.rule, "reason": verdict.reason, "stage": "response"},
            tool_name=tool_name,
            decision=verdict.decision,
            risk_tags=(verdict.rule,),
        )
        if verdict.quarantined:
            run.denials += 1
            event = run.emit(
                EventType.RESPONSE_QUARANTINED,
                self.name,
                {
                    "rule": verdict.rule,
                    "excerpt": _excerpt(result.text),
                    "original_bytes": verdict.original_bytes,
                },
                tool_name=tool_name,
                risk_tags=("response_injection",),
            )
            for finding in verdict.findings:
                run.findings.append(_claim(finding, self.name, run, [str(decision_event.id), str(event.id)]))
            return ResponseInspection(verdict.text_for_model, withheld=True)

        event = run.emit(
            EventType.RESPONSE_TRUNCATED,
            self.name,
            {
                "original_bytes": verdict.original_bytes,
                "limit_bytes": run.max_response_bytes,
                "excerpt": _excerpt(verdict.text_for_model),
            },
            tool_name=tool_name,
            risk_tags=("oversized_response",),
        )
        run.findings.append(
            Finding(
                rule_id="RS-001",
                title="Oversized tool response was truncated before reaching the model",
                category=FindingCategory.OVERSIZED_RESPONSE,
                severity=Severity.MEDIUM,
                confidence=1.0,
                description=verdict.reason,
                location=f"tools/call {tool_name} result",
                matched_evidence=f"{verdict.original_bytes} bytes > {run.max_response_bytes} byte limit",
                remediation="Bound tool responses at the gateway; never pass unlimited content to the model.",
                deterministic=True,
                server_name=run.server_name,
                tool_name=tool_name,
                evidence={
                    "original_bytes": verdict.original_bytes,
                    "limit_bytes": run.max_response_bytes,
                    "excerpt": _excerpt(verdict.text_for_model),
                },
                evidence_event_ids=[str(decision_event.id), str(event.id)],
                detected_by=self.name,
            )
        )
        return ResponseInspection(verdict.text_for_model, withheld=False)
