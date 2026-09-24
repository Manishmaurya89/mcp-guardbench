"""Inspect configured MCP servers: list tools, analyze them, compare against pinned fingerprints.

All analysis is the benchmark's own deterministic code: :func:`analyze_servers` for tool metadata
(including cross-server shadowing), :func:`analyze_text` for server ``instructions``, and
:func:`compare_snapshots` for drift against the pin file. No LLM and no external service is used.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from guardbench import __version__
from guardbench.analysis.drift_detector import compare_snapshots, drift_finding
from guardbench.analysis.fingerprinting import build_snapshot
from guardbench.analysis.metadata_analyzer import analyze_servers, analyze_text
from guardbench.analysis.severity import max_severity
from guardbench.domain.clock import utc_now
from guardbench.domain.enums import FindingCategory, Severity
from guardbench.domain.errors import InspectionError
from guardbench.domain.schemas import (
    DriftReport,
    Finding,
    ServerIdentity,
    ToolDefinitionData,
    ToolSnapshotData,
)
from guardbench.inspection.client import ServerListing
from guardbench.inspection.pins import PinFile

DETECTOR = "guardbench-inspect"
PinStatus = Literal["not_pinned", "matches_pin", "drifted", "not_checked"]


@dataclass(slots=True)
class ServerResult:
    """What was learned about one server."""

    name: str
    source: str
    transport: str
    target: str
    error: str | None = None
    identity: ServerIdentity | None = None
    tools: list[ToolDefinitionData] = field(default_factory=list)
    instructions: str | None = None
    snapshot: ToolSnapshotData | None = None
    drift: DriftReport | None = None
    pin_status: PinStatus = "not_checked"

    @property
    def ok(self) -> bool:
        """Whether the tool list was obtained."""
        return self.error is None


@dataclass(slots=True)
class InspectionReport:
    """Every server's result plus all findings, most severe first."""

    servers: list[ServerResult]
    findings: list[Finding]
    generated_at: datetime = field(default_factory=utc_now)

    @property
    def highest(self) -> Severity | None:
        """The most severe finding, or ``None`` when there are none."""
        return max_severity(f.severity for f in self.findings) if self.findings else None

    def findings_for(self, server: str) -> list[Finding]:
        """Findings attributed to one server."""
        return [f for f in self.findings if f.server_name == server]

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form: what servers advertised, never config env values, headers, or URL secrets."""
        return {
            "tool": "mcp-guardbench inspect",
            "version": __version__,
            "generated_at": self.generated_at.isoformat(),
            "read_only": "Only tools/list was requested; no tool was called.",
            "servers": [
                {
                    "name": s.name,
                    "source": s.source,
                    "transport": s.transport,
                    "target": s.target,
                    "status": "ok" if s.ok else "error",
                    "error": s.error,
                    "identity": s.identity.model_dump(mode="json") if s.identity else None,
                    "tool_count": len(s.tools),
                    "tools": sorted(t.name for t in s.tools),
                    "snapshot_hash": s.snapshot.snapshot_hash if s.snapshot else None,
                    "pin_status": s.pin_status,
                    "drift": (
                        s.drift.model_dump(mode="json", exclude={"suspicious_findings"})
                        if s.drift is not None and s.drift.drifted
                        else None
                    ),
                    "findings": len(self.findings_for(s.name)),
                }
                for s in self.servers
            ],
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "summary": {
                "servers": len(self.servers),
                "servers_failed": sum(1 for s in self.servers if not s.ok),
                "tools": sum(len(s.tools) for s in self.servers),
                "findings": len(self.findings),
                "highest_severity": self.highest.value if self.highest else None,
                "drifted_servers": sorted(s.name for s in self.servers if s.pin_status == "drifted"),
            },
        }


def _instruction_findings(server: str, text: str) -> list[Finding]:
    """Server instructions are metadata the model reads, so hostile content in them is tool poisoning."""
    findings = []
    for f in analyze_text(text, kind="server_instructions", location="instructions", server_name=server):
        category = (
            FindingCategory.TOOL_POISONING if f.category is FindingCategory.RESPONSE_INJECTION else f.category
        )
        findings.append(
            f.model_copy(
                update={
                    "category": category,
                    "tool_name": None,
                    "detected_by": DETECTOR,
                    "description": f"Rule {f.rule_id} matched the server's instructions, which clients pass "
                    "to the model when they connect. Server-supplied text is untrusted, yet models read it "
                    "as if it were instructions.",
                }
            )
        )
    return findings


def build_report(
    servers: Sequence[ServerResult],
    listings: Mapping[str, ServerListing | InspectionError],
    pins: PinFile | None,
) -> InspectionReport:
    """Fill each :class:`ServerResult` from its listing, then analyze all tools and check pins."""
    for result in servers:
        listing = listings.get(result.name)
        if listing is None:
            result.error = result.error or "not inspected"
            continue
        if isinstance(listing, InspectionError):
            result.error = str(listing)
            continue
        result.identity = listing.identity
        result.tools = listing.tools
        result.instructions = listing.instructions
        try:
            result.snapshot = build_snapshot(result.name, listing.tools, listing.identity)
        except ValueError as exc:
            result.error = f"cannot fingerprint the tool list: {exc}"
            continue

    ok = [s for s in servers if s.ok]
    findings = [
        f.model_copy(update={"detected_by": DETECTOR}) for f in analyze_servers({s.name: s.tools for s in ok})
    ]
    for result in ok:
        if result.instructions:
            findings.extend(_instruction_findings(result.name, result.instructions))
        pinned = pins.servers.get(result.name) if pins is not None else None
        if pinned is None or result.snapshot is None:
            result.pin_status = "not_pinned"
            continue
        report = compare_snapshots(pinned.snapshot, result.snapshot)
        result.drift = report
        if report.drifted:
            result.pin_status = "drifted"
            findings.append(drift_finding(report, result.name, detected_by=DETECTOR))
        else:
            result.pin_status = "matches_pin"

    findings.sort(key=lambda f: (-f.severity.rank, f.server_name or "", f.tool_name or "", f.rule_id))
    return InspectionReport(servers=list(servers), findings=findings)
