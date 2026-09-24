"""The deterministic runtime policy engine.

Given the same policy, trust store, and request, :meth:`PolicyEngine.evaluate_call` always
returns the same decision. Rules run in a fixed order; the strictest applicable decision
wins, and every decision records which rule produced it, why, and the evidence it used.

The engine never executes anything and never approves anything. ``require_approval`` means
the guarded action must not run until a human (or an explicitly labelled *simulated*
operator) resolves an approval request.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from guardbench.analysis.metadata_analyzer import analyze_text
from guardbench.domain.clock import Clock, SystemClock
from guardbench.domain.enums import Capability, PolicyDecisionType, RunMode, Severity
from guardbench.domain.markers import SyntheticMarker
from guardbench.domain.schemas import Finding, PolicyDecision
from guardbench.policy.models import PolicyConfig, ToolTrust, TrustStore, strictest
from guardbench.runtime.redaction import Redactor

D = PolicyDecisionType

_DESTINATION_KEYS = ("destination", "url", "recipient", "to", "endpoint", "webhook")
QUARANTINE_NOTICE = "[GUARDBENCH: response withheld because it contained instruction-like content]"
TRUNCATION_NOTICE = "\n[GUARDBENCH: response truncated to {limit} bytes; {dropped} bytes withheld]"
_INJECTION_RULES = frozenset({"MA-001", "MA-003", "MA-004", "MA-005", "MA-006", "MA-008", "MA-010"})

_CAPABILITY_RULE_ID = {
    Capability.READ: "POL-003",
    Capability.WRITE: "POL-004",
    Capability.SEND: "POL-005",
    Capability.DELETE: "POL-006",
    Capability.EXECUTE: "POL-011",
}


@dataclass(frozen=True, slots=True)
class CallRequest:
    """A tool call the agent wants to make."""

    trace_id: str
    server_name: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    #: The test case explicitly exercises the simulated-destructive approval path.
    destructive_simulation_expected: bool = False


@dataclass(frozen=True, slots=True)
class ResponseVerdict:
    """What may reach the model from a tool response."""

    text_for_model: str
    decision: D
    rule: str
    reason: str
    original_bytes: int
    truncated: bool = False
    quarantined: bool = False
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Candidate:
    decision: D
    rule: str
    reason: str


class PolicyEngine:
    """Evaluates calls and responses against a :class:`PolicyConfig`."""

    def __init__(
        self,
        config: PolicyConfig,
        trust: TrustStore,
        *,
        mode: RunMode = RunMode.UNATTENDED,
        redactor: Redactor | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.config = config
        self.trust = trust
        self.mode = mode
        self._redactor = redactor or Redactor()
        self._clock = clock or SystemClock()
        self._calls: defaultdict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ calls

    def call_count(self, trace_id: str) -> int:
        """How many calls have been evaluated in this trace."""
        return self._calls[trace_id]

    def evaluate_call(self, request: CallRequest) -> PolicyDecision:
        """Decide whether ``request`` may execute. Deterministic for a given policy and state."""
        self._calls[request.trace_id] += 1
        index = self._calls[request.trace_id]
        tool = self.trust.get(request.server_name, request.tool_name)
        markers = self._redactor.find_markers(request.arguments)
        sensitive = [m for m in markers if m.marker_class.value in self.config.secrets.sensitive_classes]

        base_evidence: dict[str, Any] = {
            "server": request.server_name,
            "tool": request.tool_name,
            "call_index": index,
            "max_calls_per_trace": self.config.max_calls_per_trace,
            "mode": self.mode.value,
            "marker_ids": [m.marker_id for m in markers],
        }

        if index > self.config.max_calls_per_trace:
            return self._decide(
                request,
                _Candidate(
                    D.DENY,
                    "POL-010",
                    f"call {index} exceeds the limit of {self.config.max_calls_per_trace} calls per trace",
                ),
                base_evidence,
            )
        if tool is None:
            return self._decide(
                request,
                _Candidate(self.config.unknown_tool, "POL-001", "tool is not registered by any known server"),
                base_evidence,
            )

        evidence = {
            **base_evidence,
            "capabilities": sorted(c.value for c in tool.capabilities),
            "approved": tool.approved,
        }
        candidates = self._candidates(request, tool, sensitive)
        chosen = self._pick(candidates)
        evidence["rules_considered"] = [c.rule for c in candidates]
        return self._decide(request, chosen, evidence)

    def _candidates(
        self, request: CallRequest, tool: ToolTrust, sensitive: list[SyntheticMarker]
    ) -> list[_Candidate]:
        cfg = self.config
        found: list[_Candidate] = []

        if tool.quarantined:
            found.append(
                _Candidate(D.QUARANTINE, "POL-008", tool.quarantine_reason or "tool metadata was quarantined")
            )
        if tool.drifted:
            severity = tool.drift_severity or Severity.HIGH
            decision = (
                cfg.drift.on_high_severity
                if severity >= cfg.drift.quarantine_at
                else cfg.drift.on_low_severity
            )
            found.append(
                _Candidate(
                    decision,
                    "POL-009",
                    f"definition drifted from the approved hash ({severity.value} severity)",
                )
            )
        if not tool.approved:
            found.append(_Candidate(cfg.unapproved_tool, "POL-002", "tool definition has not been approved"))

        outbound = Capability.SEND in tool.capabilities or not tool.capabilities
        if sensitive and cfg.secrets.block_outbound and outbound:
            ids = ", ".join(m.marker_id for m in sensitive)
            found.append(_Candidate(D.DENY, "POL-007", f"synthetic secret ({ids}) in an outbound argument"))

        if Capability.SEND in tool.capabilities:
            destination = self._destination(request.arguments)
            if destination is None or destination not in cfg.synthetic_destinations:
                found.append(
                    _Candidate(
                        D.DENY, "POL-005", "outbound destination is missing or not on the synthetic allowlist"
                    )
                )

        if not tool.capabilities:
            found.append(
                _Candidate(cfg.unknown_capability, "POL-012", "tool capability could not be established")
            )
        for cap in sorted(tool.capabilities, key=lambda c: c.value):
            found.append(self._capability_candidate(cap, request, tool))

        if not any(c.decision.prevents_execution for c in found) and sensitive:
            found.append(
                _Candidate(
                    D.ALLOW_WITH_WARNING, "POL-007w", "synthetic secret present in a non-outbound argument"
                )
            )
        return found

    def _capability_candidate(self, cap: Capability, request: CallRequest, tool: ToolTrust) -> _Candidate:
        rule_id = _CAPABILITY_RULE_ID[cap]
        mode = self.mode
        if cap is Capability.DELETE and request.destructive_simulation_expected:
            # The test case explicitly exercises simulated deletion, so it may reach the approval step
            # even unattended. It still cannot run without an approval.
            mode = RunMode.INTERACTIVE
        if cap is Capability.WRITE and tool.key in self.config.allow_write_tools:
            return _Candidate(D.ALLOW, rule_id, f"write is explicitly allowed for {tool.key} by policy")
        decision = self.config.rule_for(cap, mode)
        return _Candidate(decision, rule_id, f"'{cap.value}' capability policy: {decision.value}")

    @staticmethod
    def _pick(candidates: list[_Candidate]) -> _Candidate:
        if not candidates:
            return _Candidate(D.ALLOW, "POL-000", "no rule restricts this call")
        best = strictest([c.decision for c in candidates])
        return next(c for c in candidates if c.decision is best)

    @staticmethod
    def _destination(arguments: dict[str, Any]) -> str | None:
        for key in _DESTINATION_KEYS:
            value = arguments.get(key)
            if isinstance(value, str):
                return value
        return None

    def _decide(self, request: CallRequest, chosen: _Candidate, evidence: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision(
            policy_id=self.config.policy_id,
            decision=chosen.decision,
            reason=chosen.reason,
            matched_rule=chosen.rule,
            evidence=evidence,
            timestamp=self._clock.now(),
            trace_id=request.trace_id,
        )

    # -------------------------------------------------------------- responses

    def check_response(self, trace_id: str, server_name: str, tool_name: str, text: str) -> ResponseVerdict:
        """Bound and inspect a tool response before it may enter the model context.

        Oversized responses are truncated (analysis and model context are both bounded). If the
        bounded text contains instruction-like content it is withheld entirely (quarantined).
        """
        cfg = self.config.responses
        raw = text.encode("utf-8")
        original = len(raw)
        truncated = original > cfg.max_bytes
        bounded = raw[: cfg.max_bytes].decode("utf-8", errors="ignore") if truncated else text

        findings: list[Finding] = []
        if cfg.quarantine_on_injection:
            findings = [
                f
                for f in analyze_text(bounded, tool_name=tool_name, server_name=server_name)
                if f.rule_id in _INJECTION_RULES and f.severity >= Severity.MEDIUM
            ]
        if findings:
            return ResponseVerdict(
                QUARANTINE_NOTICE,
                D.QUARANTINE,
                "POL-014",
                "response contains instruction-like content and was withheld from the model",
                original,
                truncated=truncated,
                quarantined=True,
                findings=findings,
            )
        if truncated:
            return ResponseVerdict(
                _fit_within_limit(raw, original, cfg.max_bytes),
                D.ALLOW_WITH_WARNING,
                "POL-013",
                f"response of {original} bytes exceeds the {cfg.max_bytes}-byte limit and was truncated",
                original,
                truncated=True,
            )
        return ResponseVerdict(text, D.ALLOW, "POL-000", "response is within limits", original)


def _fit_within_limit(raw: bytes, original: int, limit: int) -> str:
    """Truncate ``raw`` and append a notice so the *total* is at most ``limit`` bytes.

    The body is trimmed to leave room for the notice (whose length depends on the byte counts it
    reports), and is always cut on a character boundary so the result is valid UTF-8.
    """
    keep = limit
    note = ""
    for _ in range(4):
        body = raw[:keep].decode("utf-8", errors="ignore")
        note = TRUNCATION_NOTICE.format(limit=limit, dropped=original - len(body.encode()))
        total = len(body.encode()) + len(note.encode())
        if total <= limit:
            return body + note
        keep = max(0, keep - (total - limit))
    return note.encode()[:limit].decode("utf-8", errors="ignore")  # unreachable for sane limits
