"""Human-readable output for ``guardbench inspect``.

Everything a server sends is untrusted, including text that ends up on the user's terminal. All
server-supplied strings pass through :func:`printable`, which escapes control, format, and
bidirectional characters so a hostile tool description cannot inject terminal escape sequences
or visually reorder the output.
"""

from __future__ import annotations

from collections.abc import Sequence

from guardbench.domain.enums import Severity
from guardbench.domain.schemas import Finding
from guardbench.inspection.configs import ConfigLoad
from guardbench.inspection.service import InspectionReport
from guardbench.runtime.redaction import Redactor

BANNER = (
    "MCP-GuardBench inspect: read-only. Each server is asked for its tool list (tools/list) and nothing "
    "else; no tool is ever called."
)
#: Findings at or above this severity are always listed one by one; lower ones are grouped by rule.
LIST_INDIVIDUALLY = Severity.HIGH
MAX_CELL = 48
MAX_EVIDENCE = 140
MAX_ERROR = 600
_PIN_LABEL = {
    "not_pinned": "not pinned",
    "matches_pin": "matches pin",
    "drifted": "CHANGED",
    "not_checked": "-",
}
_redactor = Redactor()


def printable(text: str, limit: int | None = None) -> str:
    """Escape non-printable characters; collapse whitespace; optionally truncate."""
    escaped = "".join(
        ch if ch.isprintable() else (" " if ch in "\n\r\t" else f"\\u{ord(ch):04x}") for ch in text
    )
    collapsed = " ".join(escaped.split())
    collapsed = _redactor.scrub_credentials_text(collapsed)
    if limit is not None and len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True))
    body = ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in rows]
    return [line.rstrip(), "  ".join("-" * w for w in widths), *body]


def render_loads(loads: Sequence[ConfigLoad]) -> list[str]:
    """One line per config file read, plus any entries that could not be understood."""
    lines: list[str] = []
    for load in loads:
        lines.append(f"Config: {printable(load.source)} ({load.client}): {len(load.servers)} server(s)")
        lines.extend(f"  ! {printable(problem)}" for problem in load.problems)
    return lines


def render_text(
    report: InspectionReport, *, min_severity: Severity, details: bool = False, suggest_pinning: bool = True
) -> str:
    """The full text report."""
    lines: list[str] = []
    rows = []
    for s in report.servers:
        own = report.findings_for(s.name)
        top = max((f.severity for f in own), default=None, key=lambda sev: sev.rank)
        rows.append(
            [
                printable(s.name, MAX_CELL),
                s.transport,
                "ok" if s.ok else "ERROR",
                str(len(s.tools)) if s.ok else "-",
                str(len(own)) if s.ok else "-",
                top.value if top else "-",
                _PIN_LABEL[s.pin_status] if s.ok else "-",
            ]
        )
    lines.extend(_table(["SERVER", "TRANSPORT", "STATUS", "TOOLS", "FINDINGS", "HIGHEST", "PIN"], rows))

    failed = [s for s in report.servers if not s.ok]
    if failed:
        lines.append("")
        lines.append("Could not inspect:")
        for s in failed:
            target = printable(s.target, 80)
            lines.append(f"  {printable(s.name, MAX_CELL)} ({target}):")
            lines.append(f"      {printable(s.error or '', MAX_ERROR)}")

    shown = [f for f in report.findings if f.severity >= min_severity]
    listed = shown if details else [f for f in shown if f.severity >= LIST_INDIVIDUALLY]
    grouped = [f for f in shown if f not in listed]
    if listed:
        lines.append("")
        floor = min_severity if details else max(min_severity, LIST_INDIVIDUALLY)
        lines.append(f"Findings ({floor.value} and above):")
        for f in listed:
            where = printable(f.tool_name, MAX_CELL) if f.tool_name else f"({f.location or 'server'})"
            server = printable(f.server_name or "-", 32)
            lines.append(f"  {f.severity.value.upper():8} {f.rule_id:7} {server} / {where}")
            lines.append(f"           {f.category.value}: {printable(f.title, 100)}")
            if f.matched_evidence:
                lines.append(f"           evidence: {printable(f.matched_evidence, MAX_EVIDENCE)}")
    if grouped:
        lines.append("")
        lines.append("Lower-severity findings, grouped by rule (--details lists each one):")
        groups: dict[tuple[Severity, str], list[Finding]] = {}
        for f in grouped:
            groups.setdefault((f.severity, f.rule_id), []).append(f)
        for (severity, rule), items in sorted(groups.items(), key=lambda kv: (-kv[0][0].rank, kv[0][1])):
            servers = sorted({printable(f.server_name or "-", 32) for f in items})
            title = printable(items[0].title, 80)
            lines.append(f"  {severity.value.upper():8} {rule:7} {items[0].category.value}: {title}")
            lines.append(f"           {len(items)} finding(s) in {', '.join(servers)}")

    drifted = [s for s in report.servers if s.pin_status == "drifted" and s.drift is not None]
    if drifted:
        lines.append("")
        lines.append("Changed since pinned (possible rug pull):")
        for s in drifted:
            assert s.drift is not None
            lines.append(
                f"  {printable(s.name, MAX_CELL)}: {s.drift.severity.value}, "
                f"recommended action: {s.drift.recommended_action}"
            )
            lines.extend(f"    - {printable(reason, 200)}" for reason in s.drift.reasons[:20])

    hidden = len(report.findings) - len(shown)
    ok = [s for s in report.servers if s.ok]
    lines.append("")
    summary = (
        f"{len(report.findings)} finding(s) across {len(ok)} inspected server(s)"
        + (f" ({hidden} below {min_severity.value} not shown)" if hidden else "")
        + (f"; highest severity: {report.highest.value}." if report.highest else ".")
    )
    lines.append(summary)
    if suggest_pinning and any(s.pin_status == "not_pinned" for s in ok):
        lines.append(
            "Some servers are not pinned. After reviewing them, run again with --update-pins so later "
            "changes to their tools are reported."
        )
    lines.append(
        "Rule-based analysis can miss attacks phrased in ways its rules do not cover: no findings is not a "
        "guarantee of safety."
    )
    return "\n".join(lines)
