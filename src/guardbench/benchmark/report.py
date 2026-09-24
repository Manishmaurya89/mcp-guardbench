"""Report generation: JSON, Markdown, CSV summary, and (optional) self-contained HTML.

Everything that enters a report is redacted first: synthetic marker values become their safe
identifiers (``[REDACTED:synthetic_secret_1]``) and credential-shaped strings are scrubbed. A
report states plainly that its results come from local reference fixtures, that they are
experimental, and that no external server was scanned.
"""

from __future__ import annotations

import csv
import html
import io
import platform
import sys
from collections.abc import Mapping
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from guardbench import __version__
from guardbench.benchmark.orchestrator import BenchmarkOutcome
from guardbench.domain.enums import ResultStatus
from guardbench.domain.schemas import AdapterResult, Event, MetricValue
from guardbench.mcp_lab.fixtures import fixture_names
from guardbench.runtime.redaction import Redactor
from guardbench.safe_paths import confine

SCOPE_NOTICE = (
    "These results were obtained from local reference fixtures shipped with MCP-GuardBench. They are "
    "experimental, describe only the controls and configuration named in this report, and are not a "
    "guarantee of safety. No external or public MCP server was scanned."
)
REPORT_FILES = {"json": "report.json", "markdown": "report.md", "csv": "summary.csv", "html": "report.html"}
_TRACKED_PACKAGES = ("mcp", "pydantic", "sqlalchemy", "fastapi", "pyyaml", "typer", "alembic")


class RunReport(BaseModel):
    """The complete, redacted, serializable record of one benchmark run."""

    schema_version: int = 1
    notice: str = SCOPE_NOTICE
    run_id: str
    generated_at: datetime
    started_at: datetime
    completed_at: datetime
    cancelled: bool
    configuration: dict[str, Any]
    adapters: list[dict[str, Any]]
    test_cases: list[dict[str, Any]]
    results: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    metrics: list[dict[str, Any]]
    failed_tests: list[dict[str, Any]]
    skipped_tests: list[dict[str, Any]]
    errored_tests: list[dict[str, Any]]
    evidence_references: list[dict[str, Any]]
    limitations: dict[str, list[str]]
    reproducibility: dict[str, Any]
    software_versions: dict[str, str]


def software_versions() -> dict[str, str]:
    """Versions of the interpreter and the libraries that influence results."""
    versions = {"mcp-guardbench": __version__, "python": platform.python_version()}
    for package in _TRACKED_PACKAGES:
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = "not installed"
    return versions


def build_report(
    outcome: BenchmarkOutcome, *, generated_at: datetime, redactor: Redactor | None = None
) -> RunReport:
    """Assemble a :class:`RunReport`, redacting every string that goes into it."""
    red = redactor or Redactor()
    results = outcome.results
    case_rows = [
        {
            "id": spec.id,
            "name": spec.name,
            "category": spec.category.value,
            "severity": spec.severity.value,
            "attack_stage": spec.attack_stage.value,
            "fixture": spec.server_fixture,
            "is_attack_case": spec.is_attack_case,
            "expected": spec.expected.model_dump(mode="json"),
        }
        for spec in sorted(outcome.cases.values(), key=lambda s: s.id)
    ]
    result_rows = [_result_row(r) for r in results]
    findings = [
        {"adapter": r.adapter_name, "test_case_id": r.test_case_id, **f.model_dump(mode="json")}
        for r in results
        for f in r.findings
    ]
    completed = [r for r in results if r.status is ResultStatus.COMPLETED]
    failed = [
        {
            "adapter": r.adapter_name,
            "test_case_id": r.test_case_id,
            "detected": r.detected,
            "blocked": r.blocked,
            "required_approval": r.required_approval,
            "unsafe_outcomes": r.unsafe_outcomes,
            "why": _why_failed(r, outcome),
        }
        for r in completed
        if r.expectation_met is False
    ]
    skipped = [
        {"adapter": r.adapter_name, "test_case_id": r.test_case_id, "reason": r.error}
        for r in results
        if r.status is ResultStatus.SKIPPED
    ]
    errored = [
        {"adapter": r.adapter_name, "test_case_id": r.test_case_id, "error": r.error}
        for r in results
        if r.status is ResultStatus.ERROR
    ]
    limitations: dict[str, list[str]] = {}
    for r in results:
        bucket = limitations.setdefault(r.adapter_name, [])
        for text in r.limitations:
            if text not in bucket:
                bucket.append(text)

    report = RunReport(
        run_id=str(outcome.run_id),
        generated_at=generated_at,
        started_at=outcome.started_at,
        completed_at=outcome.completed_at,
        cancelled=outcome.cancelled,
        configuration=outcome.config.to_json(),
        adapters=_adapter_rows(results),
        test_cases=case_rows,
        results=result_rows,
        findings=findings,
        metrics=[_metric_row(m) for m in outcome.metrics],
        failed_tests=failed,
        skipped_tests=skipped,
        errored_tests=errored,
        evidence_references=_evidence_references(outcome.events, outcome),
        limitations=limitations,
        reproducibility={
            "seed": outcome.config.seed,
            "mode": outcome.config.mode.value,
            "policy_id": outcome.policy_id,
            "policy_sha256": outcome.policy_hash,
            "test_corpus_sha256": outcome.corpus_hash,
            "max_response_bytes": outcome.max_response_bytes,
            "fixtures": fixture_names(),
            "python": sys.version.split()[0],
            "note": (
                "Re-running with the same seed, corpus, policy, and versions reproduces every verdict and "
                "trace id. Latency values and timestamps vary between runs."
            ),
        },
        software_versions=software_versions(),
    )
    return RunReport.model_validate(red.redact(report.model_dump(mode="json")))


def _result_row(r: AdapterResult) -> dict[str, Any]:
    return {
        "adapter": r.adapter_name,
        "adapter_version": r.adapter_version,
        "test_case_id": r.test_case_id,
        "status": r.status.value,
        "detected": r.detected,
        "blocked": r.blocked,
        "required_approval": r.required_approval,
        "false_positive": r.false_positive,
        "false_negative": r.false_negative,
        "expectation_met": r.expectation_met,
        "latency_ms": r.latency_ms,
        "tool_calls": r.tool_calls,
        "policy_denials": r.policy_denials,
        "approvals_required": r.approvals_required,
        "unsafe_outcomes": r.unsafe_outcomes,
        "evidence_kinds_present": [k.value for k in r.evidence_kinds_present],
        "evidence_event_ids": r.evidence_event_ids,
        "finding_count": len(r.findings),
        "claim_mismatches": r.claim_mismatches,
        "error": r.error,
    }


def _metric_row(m: MetricValue) -> dict[str, Any]:
    return {
        "name": m.name,
        "value": m.value,
        "unit": m.unit,
        "numerator": m.numerator,
        "denominator": m.denominator,
        "undefined_reason": m.undefined_reason,
        "dimensions": m.dimensions,
    }


def _adapter_rows(results: list[AdapterResult]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for r in results:
        seen.setdefault(r.adapter_name, {"name": r.adapter_name, "version": r.adapter_version, "cases": 0})
        seen[r.adapter_name]["cases"] += 1
        if r.adapter_version != "n/a":
            seen[r.adapter_name]["version"] = r.adapter_version
    return list(seen.values())


def _why_failed(r: AdapterResult, outcome: BenchmarkOutcome) -> str:
    spec = outcome.cases[r.test_case_id]
    reasons = []
    if not r.detected:
        reasons.append("the attack was not detected")
    if spec.expected.should_block and not r.blocked:
        reasons.append("the unsafe simulated action was not prevented")
    if spec.expected.should_require_approval and not r.required_approval:
        reasons.append("no approval was required")
    if r.false_positive:
        reasons.append("a benign control triggered a reaction")
    return "; ".join(reasons) or "expectation not met"


def _evidence_references(events: list[Event], outcome: BenchmarkOutcome) -> list[dict[str, Any]]:
    """Trace-level index into the event log. Event payloads themselves are not embedded."""
    counts: dict[str, int] = {}
    for e in events:
        counts[e.trace_id] = counts.get(e.trace_id, 0) + 1
    return [
        {
            "trace_id": t.trace_id,
            "adapter": t.adapter,
            "test_case_id": t.test_case_id,
            "status": t.status,
            "events": counts.get(t.trace_id, 0),
        }
        for t in outcome.traces
    ]


# --------------------------------------------------------------------------- renderers


def to_json(report: RunReport) -> str:
    """Pretty-printed JSON."""
    return report.model_dump_json(indent=2)


def _pct(value: float | None) -> str:
    return "undefined" if value is None else f"{value * 100:.1f}%"


def _num(value: float | None, unit: str) -> str:
    if value is None:
        return "undefined"
    if unit == "ratio":
        return _pct(value)
    return f"{value:.2f} {unit}" if unit == "ms" else f"{value:g}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None._\n"
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend(
        "| " + " | ".join(c.replace("|", "\\|").replace("\n", " ") for c in row) + " |" for row in rows
    )
    return "\n".join(lines) + "\n"


def _headline(report: RunReport) -> list[list[str]]:
    wanted = ["detection_rate", "prevention_rate", "false_positive_rate", "evidence_completeness_rate"]
    rows = []
    for adapter in [a["name"] for a in report.adapters]:
        by = {
            m["name"]: m
            for m in report.metrics
            if m["dimensions"].get("adapter") == adapter and "category" not in m["dimensions"]
        }
        rows.append([adapter, *[_num(by[n]["value"], by[n]["unit"]) if n in by else "n/a" for n in wanted]])
    return rows


def to_markdown(report: RunReport) -> str:
    """A human-readable Markdown report."""
    out = io.StringIO()
    w = out.write
    w("# MCP-GuardBench evaluation report\n\n")
    w(f"> {report.notice}\n\n")
    w(f"- **Run:** `{report.run_id}`{' (cancelled)' if report.cancelled else ''}\n")
    w(
        f"- **Started:** {report.started_at.isoformat()}  \n- **Completed:** {report.completed_at.isoformat()}\n"
    )
    w(f"- **Generated:** {report.generated_at.isoformat()}\n\n")

    w("## Summary\n\n")
    w(
        _table(
            ["Adapter", "Detection rate", "Prevention rate", "False-positive rate", "Evidence completeness"],
            _headline(report),
        )
    )
    w(
        "\nDetection means a control produced an evidenced finding of the expected kind. **Prevention means the "
        "unsafe simulated action was actually blocked**, verified from the fixture's own ledger; an alert is "
        "not prevention. Rates marked *undefined* have a zero denominator.\n\n"
    )

    w("## Configuration\n\n")
    for key, value in report.configuration.items():
        w(f"- **{key}:** `{value}`\n")

    w("\n## Adapters tested\n\n")
    w(
        _table(
            ["Adapter", "Version", "Cases"],
            [[a["name"], a["version"], str(a["cases"])] for a in report.adapters],
        )
    )

    w("\n## Test cases\n\n")
    w(
        _table(
            ["ID", "Name", "Category", "Severity", "Stage", "Fixture", "Kind"],
            [
                [
                    c["id"],
                    c["name"],
                    c["category"],
                    c["severity"],
                    c["attack_stage"],
                    c["fixture"],
                    "attack" if c["is_attack_case"] else "benign control",
                ]
                for c in report.test_cases
            ],
        )
    )

    w("\n## Results\n\n")
    yes = {True: "yes", False: "no", None: "n/a"}
    w(
        _table(
            [
                "Adapter",
                "Case",
                "Status",
                "Detected",
                "Prevented",
                "Approval",
                "FP",
                "FN",
                "Met",
                "Unsafe outcomes",
            ],
            [
                [
                    r["adapter"],
                    r["test_case_id"],
                    r["status"],
                    yes[r["detected"]],
                    yes[r["blocked"]],
                    yes[r["required_approval"]],
                    yes[r["false_positive"]],
                    yes[r["false_negative"]],
                    yes[r["expectation_met"]],
                    ", ".join(r["unsafe_outcomes"]) or "-",
                ]
                for r in report.results
            ],
        )
    )

    w("\n## Metrics\n\n")
    overall = [m for m in report.metrics if "category" not in m["dimensions"]]
    w(
        _table(
            ["Adapter", "Metric", "Value", "Numerator / Denominator", "Note"],
            [
                [
                    m["dimensions"].get("adapter", ""),
                    m["name"],
                    _num(m["value"], m["unit"]),
                    "-" if m["denominator"] is None else f"{m['numerator']:g} / {m['denominator']:g}",
                    m["undefined_reason"] or "",
                ]
                for m in overall
            ],
        )
    )
    w("\n### Per-category breakdown\n\n")
    w(
        _table(
            ["Adapter", "Category", "Metric", "Value", "Num / Den"],
            [
                [
                    m["dimensions"]["adapter"],
                    m["dimensions"]["category"],
                    m["name"],
                    _num(m["value"], m["unit"]),
                    "-" if m["denominator"] is None else f"{m['numerator']:g} / {m['denominator']:g}",
                ]
                for m in report.metrics
                if "category" in m["dimensions"]
            ],
        )
    )

    w("\n## Findings\n\n")
    w(
        _table(
            ["Adapter", "Case", "Rule", "Severity", "Category", "Location", "Matched evidence"],
            [
                [
                    f["adapter"],
                    f["test_case_id"],
                    f["rule_id"],
                    f["severity"],
                    f["category"],
                    _code(f.get("location") or ""),
                    _code(_shorten(f.get("matched_evidence") or "")),
                ]
                for f in report.findings
            ],
        )
    )

    w("\n## Failed tests (expectation not met)\n\n")
    w(
        _table(
            ["Adapter", "Case", "Why"],
            [[f["adapter"], f["test_case_id"], f["why"]] for f in report.failed_tests],
        )
    )
    w(
        "\nA control that fails a case is not a bug in the benchmark: the no-defense baseline is expected to "
        "fail every attack case.\n"
    )

    w("\n## Skipped tests\n\n")
    w(
        _table(
            ["Adapter", "Case", "Reason"],
            [[s["adapter"], s["test_case_id"], _code(s["reason"] or "")] for s in report.skipped_tests],
        )
    )
    if report.errored_tests:
        w("\n## Errored tests\n\n")
        w(
            _table(
                ["Adapter", "Case", "Error"],
                [[e["adapter"], e["test_case_id"], _code(e["error"] or "")] for e in report.errored_tests],
            )
        )

    w("\n## Evidence references\n\n")
    w(
        "Each trace is a sequence of recorded events (tool listings, policy decisions, responses, data flow).\n\n"
    )
    w(
        _table(
            ["Adapter", "Case", "Trace id", "Events", "Status"],
            [
                [e["adapter"], e["test_case_id"], f"`{e['trace_id']}`", str(e["events"]), e["status"]]
                for e in report.evidence_references
            ],
        )
    )

    w("\n## Limitations\n\n")
    w(
        "- The corpus is small and incomplete; a perfect score here proves nothing about real-world servers.\n"
        "- Static analysis can miss semantic attacks; runtime policy only works if the client is instrumented.\n"
        "- Hashing detects change relative to a snapshot; it does not establish that the snapshot was trustworthy.\n"
        "- Results depend on the model, client, configuration, and policy. See `docs/limitations.md`.\n\n"
    )
    for adapter, items in report.limitations.items():
        w(f"**{adapter}**\n\n")
        for item in items:
            w(f"- {item}\n")
        w("\n")

    w("## Reproducibility\n\n")
    for key, value in report.reproducibility.items():
        w(f"- **{key}:** `{value}`\n")
    w("\n### Software versions\n\n")
    for key, value in report.software_versions.items():
        w(f"- {key}: `{value}`\n")
    return out.getvalue()


def _code(text: str) -> str:
    """Render server-supplied text as inline code so a Markdown viewer never interprets it as markup."""
    collapsed = " ".join(text.split()).replace("`", "'")
    return f"`{collapsed}`" if collapsed else ""


def _shorten(text: str, limit: int = 110) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."


def to_csv(report: RunReport) -> str:
    """One row per (adapter, test case), suitable for spreadsheets."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    columns = [
        "adapter",
        "test_case_id",
        "status",
        "detected",
        "blocked",
        "required_approval",
        "false_positive",
        "false_negative",
        "expectation_met",
        "latency_ms",
        "tool_calls",
        "policy_denials",
        "finding_count",
        "unsafe_outcomes",
    ]
    writer.writerow(columns)
    for r in report.results:
        writer.writerow([_csv_cell(r[c]) for c in columns])
    return buffer.getvalue()


def _csv_cell(value: Any) -> str:
    text = ";".join(value) if isinstance(value, list) else "" if value is None else str(value)
    # Neutralize spreadsheet formula injection: cells must never start with a formula trigger.
    return "'" + text if text[:1] in {"=", "+", "-", "@"} and not _is_plain_number(text) else text


def _is_plain_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def to_html(report: RunReport) -> str:
    """A self-contained HTML rendering (all content HTML-escaped, no scripts, no external resources)."""
    body = html.escape(to_markdown(report))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>MCP-GuardBench report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;"
        "line-height:1.5}pre{white-space:pre-wrap;word-wrap:break-word;background:#f6f8fa;padding:1rem;"
        "border-radius:6px}.notice{border-left:4px solid #b08800;padding:.5rem 1rem;background:#fff8c5}"
        "</style></head><body>"
        f'<p class="notice"><strong>Local security lab.</strong> {html.escape(report.notice)}</p>'
        f"<pre>{body}</pre></body></html>"
    )


def render(report: RunReport, fmt: str) -> str:
    """Render ``report`` in one of ``json``, ``markdown``, ``csv``, ``html``."""
    renderers = {"json": to_json, "markdown": to_markdown, "csv": to_csv, "html": to_html}
    if fmt not in renderers:
        raise ValueError(f"unknown report format {fmt!r}; choose from {', '.join(renderers)}")
    return renderers[fmt](report)


def write_report_files(
    report: RunReport,
    output_dir: Path,
    allowed_root: Path,
    formats: tuple[str, ...] = ("json", "markdown", "csv"),
) -> dict[str, Path]:
    """Write the requested formats into ``output_dir`` (which must lie inside ``allowed_root``).

    File names are fixed, never derived from input, so a caller cannot choose where a file lands.
    """
    target = confine(output_dir, allowed_root)
    target.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for fmt in formats:
        path = target / REPORT_FILES[fmt] if fmt in REPORT_FILES else None
        if path is None:
            raise ValueError(f"unknown report format {fmt!r}; choose from {', '.join(REPORT_FILES)}")
        path.write_text(render(report, fmt), encoding="utf-8")
        written[fmt] = path
    return written


def report_summary(outcome: BenchmarkOutcome) -> Mapping[str, Any]:
    """Compact summary stored on the run record (headline numbers per adapter)."""
    from guardbench.benchmark.metrics import headline

    return {
        "adapters": {a: headline(outcome.metrics, a) for a in outcome.config.adapters},
        "cases": len(outcome.cases),
        "results": len(outcome.results),
        "completed": sum(1 for r in outcome.results if r.status is ResultStatus.COMPLETED),
        "skipped": sum(1 for r in outcome.results if r.status is ResultStatus.SKIPPED),
        "errored": sum(1 for r in outcome.results if r.status is ResultStatus.ERROR),
        "cancelled": outcome.cancelled,
    }
