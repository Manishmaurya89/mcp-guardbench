"""Report generation: content, redaction, safe rendering, and safe output paths."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

import pytest

from guardbench.benchmark.orchestrator import BenchmarkConfig, BenchmarkOutcome, Orchestrator
from guardbench.benchmark.report import (
    REPORT_FILES,
    SCOPE_NOTICE,
    RunReport,
    build_report,
    render,
    report_summary,
    to_csv,
    to_html,
    to_json,
    to_markdown,
    write_report_files,
)
from guardbench.benchmark.test_case_loader import load_test_cases
from guardbench.domain.clock import utc_now
from guardbench.domain.errors import PathNotAllowedError
from guardbench.domain.markers import MARKER_VALUES, TEST_SECRET
from guardbench.policy.models import load_policy

CASES_DIR = Path(__file__).resolve().parents[2] / "test_cases"
ADAPTERS = ("no-defense-baseline", "reference-static", "reference-runtime", "external-scanner")


async def make_outcome(**kw: object) -> BenchmarkOutcome:
    cases = load_test_cases(CASES_DIR, allowed_root=CASES_DIR)
    return await Orchestrator(cases, load_policy()).run(BenchmarkConfig(adapters=ADAPTERS, **kw))  # type: ignore[arg-type]


async def make_report(**kw: object) -> RunReport:
    return build_report(await make_outcome(**kw), generated_at=utc_now())


# ---------------------------------------------------------------- content


async def test_the_json_report_has_every_required_section() -> None:
    report = json.loads(to_json(await make_report(seed=5)))
    for key in (
        "configuration",
        "adapters",
        "test_cases",
        "results",
        "findings",
        "evidence_references",
        "metrics",
        "failed_tests",
        "skipped_tests",
        "limitations",
        "reproducibility",
        "software_versions",
        "generated_at",
        "started_at",
        "completed_at",
        "run_id",
        "notice",
    ):
        assert key in report, key
    assert report["configuration"]["seed"] == 5
    assert [a["name"] for a in report["adapters"]] == list(ADAPTERS)
    assert len(report["test_cases"]) == 12 and len(report["results"]) == 48


async def test_reproducibility_and_software_versions_are_recorded() -> None:
    report = await make_report()
    repro = report.reproducibility
    assert len(repro["policy_sha256"]) == 64 and len(repro["test_corpus_sha256"]) == 64
    assert repro["policy_id"] == "guardbench-default" and repro["mode"] == "unattended"
    assert "clean_server" in repro["fixtures"]
    assert report.software_versions["mcp"] == "2.2.0" and report.software_versions["python"].startswith("3.")
    assert "mcp-guardbench" in report.software_versions


async def test_every_format_states_that_results_come_from_local_reference_fixtures() -> None:
    report = await make_report()
    assert "local reference fixtures" in SCOPE_NOTICE and "No external" in SCOPE_NOTICE
    for fmt in ("json", "markdown", "html"):
        text = render(report, fmt)
        assert "local reference fixtures" in text, fmt
        assert "experimental" in text.lower(), fmt


async def test_failed_skipped_and_finding_sections_are_populated_honestly() -> None:
    report = await make_report()
    failed = {(f["adapter"], f["test_case_id"]) for f in report.failed_tests}
    assert all(("no-defense-baseline", c) in failed for c in ("TP-001", "DF-001", "PA-001", "RS-001"))
    runtime_failed = {c for a, c in failed if a == "reference-runtime"}
    assert runtime_failed == {"DF-002", "TP-003"}, "the runtime misses only the documented hard cases"
    assert ("reference-static", "PA-001") in failed, (
        "detected but not prevented is still a failed expectation"
    )
    assert {s["adapter"] for s in report.skipped_tests} == {"external-scanner"} and len(
        report.skipped_tests
    ) == 12
    assert all("no external scanner" in (s["reason"] or "") for s in report.skipped_tests)
    assert report.findings and all(f["rule_id"] and f["remediation"] for f in report.findings)


async def test_the_markdown_report_shows_undefined_rates_and_the_key_sections() -> None:
    text = to_markdown(await make_report())
    for heading in (
        "## Summary",
        "## Configuration",
        "## Adapters tested",
        "## Test cases",
        "## Results",
        "## Metrics",
        "## Findings",
        "## Failed tests",
        "## Skipped tests",
        "## Evidence references",
        "## Limitations",
        "## Reproducibility",
    ):
        assert heading in text, heading
    assert re.search(r"\| external-scanner \| undefined \| undefined \|", text)
    assert "Prevention means the unsafe simulated action was actually blocked" in text


async def test_reports_are_deterministic_apart_from_timing_and_ids() -> None:
    def normalize(report: RunReport) -> dict[str, object]:
        data = json.loads(to_json(report))
        for key in ("run_id", "generated_at", "started_at", "completed_at"):
            data.pop(key)
        for row in data["results"]:
            row.pop("latency_ms")
            row.pop("evidence_event_ids")
        data["metrics"] = [m for m in data["metrics"] if not m["name"].startswith("latency")]
        for finding in data["findings"]:
            finding.pop("evidence_event_ids")
            finding["evidence"].pop("destination_event_id", None)
            finding["evidence"].pop("source_event_id", None)
        return data

    assert normalize(await make_report(seed=1)) == normalize(await make_report(seed=1))


async def test_report_summary_holds_the_headline_numbers() -> None:
    summary = report_summary(await make_outcome())
    assert summary["cases"] == 12 and summary["results"] == 48
    assert summary["skipped"] == 12 and summary["errored"] == 0 and summary["completed"] == 36
    assert summary["adapters"]["reference-runtime"]["prevention_rate"] == pytest.approx(8 / 9)
    assert summary["adapters"]["reference-static"]["prevention_rate"] == 0.0
    assert summary["adapters"]["external-scanner"]["detection_rate"] is None


# ---------------------------------------------------------------- redaction and safe rendering


async def test_no_report_format_contains_a_synthetic_marker_value() -> None:
    report = await make_report()
    for fmt in ("json", "markdown", "csv", "html"):
        text = render(report, fmt).lower()
        assert not any(m.lower() in text for m in MARKER_VALUES), fmt
    # the full evidence lives in the JSON report; the Markdown table truncates long evidence
    assert "[REDACTED:synthetic_secret_1]" in to_json(report), "redaction leaves a safe identifier behind"


async def test_credential_shaped_strings_are_scrubbed_from_reports() -> None:
    outcome = await make_outcome()
    leaked = "AKIA" + "ABCDEFGHIJKLMNOP"
    outcome.results[0] = outcome.results[0].model_copy(update={"error": f"boom with {leaked}"})
    report = build_report(outcome, generated_at=utc_now())
    for fmt in ("json", "markdown", "csv", "html"):
        assert leaked not in render(report, fmt), fmt


async def test_hostile_tool_text_is_always_rendered_inside_markdown_code_spans() -> None:
    text = to_markdown(await make_report())
    occurrences = [m.start() for m in re.finditer(re.escape("<IMPORTANT>"), text)]
    assert occurrences, "sanity: the poisoned fixtures do produce this text in findings"
    for start in occurrences:
        line_start = text.rfind("\n", 0, start) + 1
        assert text[line_start:start].count("`") % 2 == 1, "hostile text escaped its code span"


async def test_html_is_escaped_static_and_has_no_external_resources() -> None:
    page = to_html(await make_report())
    assert "<IMPORTANT>" not in page and "&lt;IMPORTANT&gt;" in page
    assert "<script" not in page.lower()
    assert "http://" not in page and "https://" not in page
    assert "default-src 'none'" in page, "a restrictive CSP is embedded"
    assert "Local security lab." in page


async def test_csv_has_one_row_per_result_and_neutralizes_formula_injection() -> None:
    outcome = await make_outcome()
    outcome.results[0] = outcome.results[0].model_copy(
        update={"unsafe_outcomes": ["=HYPERLINK(1)", "-5", "+cmd"]}
    )
    rows = list(csv.reader(io.StringIO(to_csv(build_report(outcome, generated_at=utc_now())))))
    assert rows[0][:3] == ["adapter", "test_case_id", "status"]
    assert len(rows) == 1 + 48
    cell = rows[1][-1]
    assert cell.startswith("'"), "a cell beginning with = + - @ must not be executable in a spreadsheet"
    latency_column = rows[0].index("latency_ms")
    assert all(not r[latency_column].startswith("'") for r in rows[1:]), "plain numbers are left alone"


# ---------------------------------------------------------------- writing files


async def test_files_are_written_with_fixed_names_inside_the_allowed_root(tmp_path: Path) -> None:
    report = await make_report()
    written = write_report_files(report, tmp_path / "run1", tmp_path, ("json", "markdown", "csv", "html"))
    assert {fmt: path.name for fmt, path in written.items()} == REPORT_FILES
    assert json.loads(written["json"].read_text(encoding="utf-8"))["run_id"] == report.run_id
    assert written["markdown"].read_text(encoding="utf-8").startswith("# MCP-GuardBench evaluation report")


async def test_report_output_cannot_escape_the_reports_directory(tmp_path: Path) -> None:
    report = await make_report()
    root = tmp_path / "reports"
    root.mkdir()
    for hostile in (tmp_path, root / ".." / "elsewhere", Path("/tmp/guardbench-escape")):
        with pytest.raises(PathNotAllowedError):
            write_report_files(report, hostile, root)
    assert not (tmp_path / "elsewhere").exists()


async def test_unknown_report_formats_are_rejected(tmp_path: Path) -> None:
    report = await make_report()
    with pytest.raises(ValueError, match="unknown report format"):
        render(report, "pdf")
    with pytest.raises(ValueError, match="unknown report format"):
        write_report_files(report, tmp_path, tmp_path, ("exe",))


async def test_the_report_holds_no_raw_marker_in_a_scenario_that_definitely_produced_one() -> None:
    outcome = await make_outcome()
    assert any(TEST_SECRET in json.dumps(r.model_dump(mode="json")) for r in outcome.results), (
        "sanity: raw results contain the marker"
    )
    assert TEST_SECRET not in to_json(build_report(outcome, generated_at=utc_now()))
