"""The ``guardbench`` command-line interface."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from guardbench.cli.main import app
from guardbench.db import models, repositories
from guardbench.db.session import create_db_engine, create_session_factory, session_scope
from guardbench.domain.markers import MARKER_VALUES

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]
CASES = REPO / "test_cases"


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """An isolated database and reports directory; no .env file is read."""
    paths = {"db": tmp_path / "data" / "cli.db", "reports": tmp_path / "reports"}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUARDBENCH_DATABASE_URL", f"sqlite:///{paths['db']}")
    monkeypatch.setenv("GUARDBENCH_REPORTS_DIR", str(paths["reports"]))
    monkeypatch.setenv("GUARDBENCH_TEST_CASES_DIR", str(CASES))
    monkeypatch.setenv("GUARDBENCH_DEV_MODE", "true")
    monkeypatch.setenv("GUARDBENCH_LOG_JSON", "false")
    monkeypatch.delenv("GUARDBENCH_API_KEY", raising=False)
    return paths


def run(*args: str) -> Any:
    return runner.invoke(app, list(args))


def initialized(env: dict[str, Path]) -> None:
    result = run("init-db")
    assert result.exit_code == 0, result.output


def session_for(env: dict[str, Path]):  # type: ignore[no-untyped-def]
    return session_scope(create_session_factory(create_db_engine(f"sqlite:///{env['db']}")))


# ---------------------------------------------------------------- surface


def test_help_lists_every_required_command() -> None:
    result = run("--help")
    assert result.exit_code == 0
    for command in (
        "init-db",
        "seed-demo",
        "list-test-cases",
        "analyze-fixture",
        "fingerprint",
        "detect-drift",
        "benchmark",
        "report",
        "serve",
        "dashboard",
    ):
        assert command in result.output, command
    assert "MCP-GuardBench" in result.output


@pytest.mark.parametrize(
    "command",
    [
        ["init-db"],
        ["seed-demo"],
        ["list-test-cases"],
        ["analyze-fixture"],
        ["fingerprint"],
        ["detect-drift"],
        ["benchmark", "run"],
        ["report"],
        ["serve"],
        ["dashboard"],
    ],
)
def test_every_command_has_help_text(command: list[str]) -> None:
    result = run(*command, "--help")
    assert result.exit_code == 0 and "Usage:" in result.output
    assert len(result.output.strip().splitlines()) >= 3


def test_version_flag() -> None:
    result = run("--version")
    assert result.exit_code == 0 and re.match(r"mcp-guardbench \d+\.\d+\.\d+", result.output)


def test_no_arguments_shows_help_and_missing_options_are_usage_errors() -> None:
    assert "Commands:" in run().output
    result = run("analyze-fixture")
    assert result.exit_code == 2 and "--fixture" in result.output


# ---------------------------------------------------------------- database


def test_init_db_creates_the_database_and_is_idempotent(env: dict[str, Path]) -> None:
    assert not env["db"].exists()
    first = run("init-db")
    assert first.exit_code == 0 and "up to date" in first.output
    assert env["db"].exists(), "the parent directory is created automatically"
    assert run("init-db").exit_code == 0


def test_commands_that_need_a_database_explain_how_to_create_one(env: dict[str, Path]) -> None:
    for args in (
        ["seed-demo"],
        ["benchmark", "run", "--case-id", "BN-001"],
        ["summary", "--run-id", "0" * 8 + "-0000-0000-0000-" + "0" * 12],
    ):
        result = run(*args)
        assert result.exit_code == 1 and "init-db" in result.output, args


def test_seed_demo_registers_every_fixture_approves_baselines_and_stages_drift(env: dict[str, Path]) -> None:
    initialized(env)
    result = run("seed-demo")
    assert result.exit_code == 0, result.output
    assert "11 fixture servers" in result.output and "drift_server" in result.output
    with session_for(env) as session:
        servers = {s.name: s for s in session.query(models.MCPServer).all()}
        assert len(servers) == 11
        drift = servers["drift_server"]
        assert drift.lab_phase == 1 and drift.trust_status == "quarantined"
        assert repositories.approved_baseline(session, drift.id) is not None
        assert repositories.approved_baseline(session, servers["clean_server"].id) is not None
        assert repositories.approved_baseline(session, servers["poisoned_description_server"].id) is None
        assert (
            session.query(models.Finding).filter(models.Finding.category == "tool_definition_drift").count()
            == 1
        )


def test_seed_demo_is_idempotent(env: dict[str, Path]) -> None:
    initialized(env)
    assert run("seed-demo").exit_code == 0
    assert run("seed-demo").exit_code == 0
    with session_for(env) as session:
        assert session.query(models.MCPServer).count() == 11
        assert session.query(models.Project).count() == 1
        assert (
            session.query(models.ToolSnapshot)
            .filter(models.ToolSnapshot.is_approved_baseline.is_(True))
            .count()
            == 2
        )


# ---------------------------------------------------------------- inspection


def test_list_test_cases_shows_the_corpus(env: dict[str, Path]) -> None:
    result = run("list-test-cases")
    assert result.exit_code == 0
    for case_id in ("TP-001", "TP-002", "TP-003", "RI-001", "RD-001", "DF-001", "DF-002", "PA-001", "RS-001"):
        assert case_id in result.output
    for case_id in ("BN-001", "BN-002", "BN-003"):
        assert case_id in result.output
    assert "12 test case(s)." in result.output


def test_list_test_cases_refuses_directories_outside_the_allowed_root(
    env: dict[str, Path], tmp_path: Path
) -> None:
    for hostile in ("/etc", str(tmp_path), str(CASES.parent)):
        result = run("list-test-cases", "--cases", hostile)
        assert result.exit_code == 1 and "outside the allowed directory" in result.output, hostile


def test_list_fixtures_and_adapters() -> None:
    fixtures = run("list-fixtures").output
    assert "drift_server" in fixtures and "yes" in fixtures
    adapters = run("list-adapters").output.split()
    assert {"no-defense-baseline", "reference-static", "reference-runtime", "external-scanner"} <= set(
        adapters
    )


def test_analyze_fixture_reports_findings_and_stays_quiet_on_the_clean_server() -> None:
    poisoned = run("analyze-fixture", "--fixture", "poisoned_description_server")
    assert poisoned.exit_code == 0
    assert (
        "MA-090" in poisoned.output
        and "critical" in poisoned.output
        and "get_calendar_summary" in poisoned.output
    )
    clean = run("analyze-fixture", "--fixture", "clean_server")
    assert clean.exit_code == 0 and "No findings." in clean.output


def test_analyze_fixture_json_is_parseable_and_redacted() -> None:
    result = run("analyze-fixture", "--fixture", "poisoned_description_server", "--json")
    findings = json.loads(result.output)
    assert findings and all(f["rule_id"] and f["remediation"] for f in findings)
    assert not any(m.lower() in result.output.lower() for m in MARKER_VALUES)


def test_unknown_fixtures_give_a_helpful_error() -> None:
    for command in ("analyze-fixture", "fingerprint", "detect-drift"):
        result = run(command, "--fixture", "../../etc/passwd")
        assert (
            result.exit_code == 1 and "unknown fixture" in result.output and "clean_server" in result.output
        )


def test_fingerprint_is_stable_and_shows_sha256_hashes() -> None:
    first, second = (
        run("fingerprint", "--fixture", "clean_server"),
        run("fingerprint", "--fixture", "clean_server"),
    )
    assert first.exit_code == 0 and first.output == second.output
    assert len(re.findall(r"\b[0-9a-f]{64}\b", first.output)) == 4  # three tools plus the tool set
    assert "does not prove" in first.output


def test_detect_drift_shows_the_rug_pull_and_rejects_fixtures_without_state() -> None:
    result = run("detect-drift", "--fixture", "drift_server")
    assert result.exit_code == 0
    assert "Severity: high" in result.output and "block_until_reviewed" in result.output
    assert "lookup_record" in result.output and "server version changed" in result.output
    rejected = run("detect-drift", "--fixture", "clean_server")
    assert rejected.exit_code == 1 and "no state to advance" in rejected.output


# ---------------------------------------------------------------- benchmark


def test_benchmark_run_prints_metrics_and_writes_reports(env: dict[str, Path]) -> None:
    initialized(env)
    result = run(
        "benchmark",
        "run",
        "--project",
        "demo",
        "--cases",
        str(CASES),
        "--adapter",
        "reference-static",
        "--adapter",
        "reference-runtime",
        "--output",
        str(env["reports"] / "demo-run"),
    )
    assert result.exit_code == 0, result.output
    assert "reference-runtime" in result.output and "88.9%" in result.output and "44.4%" in result.output
    assert "actually" in result.output and "blocked" in result.output
    folder = env["reports"] / "demo-run"
    assert {p.name for p in folder.iterdir()} == {"report.json", "report.md", "summary.csv"}
    assert json.loads((folder / "report.json").read_text(encoding="utf-8"))["notice"]
    assert not any(
        m.lower() in (folder / "report.md").read_text(encoding="utf-8").lower() for m in MARKER_VALUES
    )


def test_the_documented_example_command_works_verbatim(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    initialized(env)
    monkeypatch.setenv("GUARDBENCH_TEST_CASES_DIR", "test_cases")
    monkeypatch.chdir(REPO)  # the example uses repo-relative paths
    monkeypatch.setenv("GUARDBENCH_REPORTS_DIR", str(env["reports"]))
    result = run(
        "benchmark",
        "run",
        "--project",
        "demo",
        "--cases",
        "test_cases/",
        "--adapter",
        "reference-static",
        "--adapter",
        "reference-runtime",
        "--output",
        str(env["reports"] / "demo-run") + "/",
    )
    assert result.exit_code == 0, result.output
    assert (env["reports"] / "demo-run" / "report.md").exists()


def test_report_command_renders_a_stored_run_in_every_format(env: dict[str, Path]) -> None:
    initialized(env)
    out = run(
        "benchmark", "run", "--adapter", "reference-runtime", "--case-id", "TP-001", "--case-id", "BN-001"
    ).output
    run_id = re.search(r"Run id: ([0-9a-f-]{36})", out).group(1)  # type: ignore[union-attr]
    markdown = run("report", "--run-id", run_id, "--format", "markdown")
    assert markdown.exit_code == 0 and markdown.output.startswith("# MCP-GuardBench evaluation report")
    assert json.loads(run("report", "--run-id", run_id, "--format", "json").output)["run_id"] == run_id
    assert run("report", "--run-id", run_id, "--format", "csv").output.startswith("adapter,test_case_id")
    assert "<pre>" in run("report", "--run-id", run_id, "--format", "html").output
    written = run(
        "report", "--run-id", run_id, "--format", "markdown", "--output", str(env["reports"] / "one")
    )
    assert written.exit_code == 0 and (env["reports"] / "one" / "report.md").exists()
    assert "reference-runtime" in run("summary", "--run-id", run_id).output


def test_undefined_metrics_are_shown_as_undefined(env: dict[str, Path]) -> None:
    initialized(env)
    result = run("benchmark", "run", "--adapter", "reference-runtime", "--case-id", "BN-001")
    assert result.exit_code == 0 and "undefined" in result.output


def test_no_persist_needs_no_database(env: dict[str, Path]) -> None:
    result = run("benchmark", "run", "--no-persist", "--adapter", "reference-runtime", "--case-id", "TP-001")
    assert result.exit_code == 0 and "reference-runtime" in result.output
    assert not env["db"].exists(), "--no-persist must not create or touch the database"


def test_the_external_placeholder_is_reported_as_skipped_not_scored(env: dict[str, Path]) -> None:
    result = run("benchmark", "run", "--no-persist", "--adapter", "external-scanner", "--case-id", "TP-001")
    assert result.exit_code == 0 and "skipped" in result.output and "undefined" in result.output


def test_benchmark_input_validation(env: dict[str, Path]) -> None:
    initialized(env)
    assert "unknown format" in run("benchmark", "run", "--format", "pdf", "--no-persist").output
    unknown_adapter = run("benchmark", "run", "--adapter", "not-real")
    assert unknown_adapter.exit_code == 1 and "unknown adapters" in unknown_adapter.output
    unknown_case = run("benchmark", "run", "--no-persist", "--case-id", "ZZ-999")
    assert unknown_case.exit_code != 0
    assert run("benchmark", "run", "--seed", "-1", "--no-persist").exit_code == 2


def test_benchmark_output_is_confined_and_rejected_before_any_work_is_done(
    env: dict[str, Path], tmp_path: Path
) -> None:
    initialized(env)
    result = run(
        "benchmark",
        "run",
        "--adapter",
        "reference-runtime",
        "--case-id",
        "BN-001",
        "--output",
        str(tmp_path / "elsewhere"),
    )
    assert result.exit_code == 1 and "outside the allowed directory" in result.output
    assert not (tmp_path / "elsewhere").exists()
    with session_for(env) as session:
        assert session.query(models.BenchmarkRun).count() == 0, "a rejected path must not leave a run behind"


def test_report_for_an_unknown_run_is_a_clean_error(env: dict[str, Path]) -> None:
    initialized(env)
    result = run("report", "--run-id", "00000000-0000-0000-0000-000000000000")
    assert result.exit_code == 1 and "not found" in result.output and "Traceback" not in result.output
    assert run("report", "--run-id", "not-a-uuid").exit_code == 2


def test_database_errors_are_one_clean_line_that_never_leaks_the_url(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDBENCH_DATABASE_URL", "postgresql://user:hunter2hunter2@127.0.0.1:1/db")
    result = run("init-db")
    assert (
        result.exit_code == 1 and "hunter2hunter2" not in result.output and "Traceback" not in result.output
    )


# ---------------------------------------------------------------- services


def test_serve_refuses_to_expose_dev_mode_beyond_loopback(env: dict[str, Path]) -> None:
    result = run("serve", "--host", "0.0.0.0")  # noqa: S104 - the test asserts this is refused
    assert (
        result.exit_code == 1 and "refusing to bind" in result.output and "no authentication" in result.output
    )


def test_serve_outside_dev_mode_requires_an_api_key(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDBENCH_DEV_MODE", "false")
    result = run("serve", "--host", "127.0.0.1")
    assert result.exit_code == 1 and "GUARDBENCH_API_KEY" in result.output


def test_dashboard_launches_a_fixed_command_without_a_shell(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_call(command: list[str], **kwargs: Any) -> int:
        captured["command"], captured["kwargs"] = command, kwargs
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)
    result = run("dashboard", "--port", "8555")
    assert result.exit_code == 0, result.output
    command = captured["command"]
    assert isinstance(command, list) and command[1:4] == ["-m", "streamlit", "run"]
    assert command[command.index("--server.address") + 1] == "127.0.0.1"
    assert command[command.index("--server.port") + 1] == "8555"
    assert captured["kwargs"].get("shell") is not True
    assert command[4].endswith("dashboard/app.py")


def test_dashboard_rejects_bad_ports() -> None:
    assert run("dashboard", "--port", "99999").exit_code == 2
    assert run("dashboard", "--port", "abc").exit_code == 2


def test_report_and_summary_accept_latest_and_require_exactly_one_selector(env: dict[str, Path]) -> None:
    initialized(env)
    assert "no finished runs" in run("report", "--latest").output
    run("benchmark", "run", "--adapter", "reference-runtime", "--case-id", "TP-001")
    assert run("report", "--latest").output.startswith("# MCP-GuardBench evaluation report")
    assert "reference-runtime" in run("summary", "--latest").output
    for args in (["report"], ["report", "--latest", "--run-id", "00000000-0000-0000-0000-000000000000"]):
        result = run(*args)
        assert result.exit_code == 1 and "exactly one of --run-id or --latest" in result.output, args


# ---------------------------------------------------------------- trace


def test_trace_shows_the_blocked_secret_flow_with_rule_decision_and_path(env: dict[str, Path]) -> None:
    initialized(env)
    run("benchmark", "run", "--adapter", "reference-runtime", "--case-id", "DF-001")
    result = run("trace", "--latest", "--adapter", "reference-runtime", "--case", "DF-001")
    assert result.exit_code == 0, result.output
    out = result.output
    assert "reference-runtime / DF-001" in out and "local security lab" in out
    for expected in (
        "tool_call_requested",
        "policy_decision",
        "POL-007",
        "deny",
        "data_flow",
        "tool_call_blocked",
    ):
        assert expected in out, expected
    assert "Synthetic data-flow paths" in out
    path = out.split("Synthetic data-flow paths", 1)[1]
    assert "synthetic_secret_1 (blocked):" in path
    hops = [
        line.strip() for line in path.splitlines() if "fixture_source" in line or "outbound_request" in line
    ]
    assert hops[0].startswith("fixture_source:read_private_record") and hops[-1].startswith(
        "-> outbound_request"
    )
    for marker in MARKER_VALUES:
        assert marker not in out, "a raw synthetic marker value reached the trace output"
    assert "[REDACTED:synthetic_secret_1]" in out


def test_trace_shows_the_approval_request_and_that_nobody_approved_it(env: dict[str, Path]) -> None:
    initialized(env)
    run("benchmark", "run", "--adapter", "reference-runtime", "--case-id", "PA-001")
    out = run("trace", "--latest", "--adapter", "reference-runtime", "--case", "PA-001").output
    assert "approval_requested" in out and "require_approval" in out and "POL-004" in out
    assert "pending (resolved by nobody)" in out
    assert "simulated-operator" not in out  # unattended mode never approves


def test_trace_of_the_baseline_has_no_policy_decisions(env: dict[str, Path]) -> None:
    initialized(env)
    run("benchmark", "run", "--adapter", "no-defense-baseline", "--case-id", "DF-001")
    out = run("trace", "--latest", "--adapter", "no-defense-baseline", "--case", "DF-001").output
    assert "tool_call_requested" in out and "policy_decision" not in out and "tool_call_blocked" not in out


def test_trace_by_run_id_and_clean_errors(env: dict[str, Path]) -> None:
    initialized(env)
    ran = run("benchmark", "run", "--adapter", "reference-runtime", "--case-id", "TP-001")
    run_id = re.search(r"Run id: ([0-9a-f-]{36})", ran.output)
    assert run_id, ran.output
    assert (
        run(
            "trace", "--run-id", run_id.group(1), "--adapter", "reference-runtime", "--case", "TP-001"
        ).exit_code
        == 0
    )

    missing = run("trace", "--latest", "--adapter", "reference-static", "--case", "TP-001")
    assert missing.exit_code == 1 and "available: reference-runtime/TP-001" in missing.output
    assert "Traceback" not in missing.output

    both_missing = run("trace", "--adapter", "reference-runtime", "--case", "TP-001")
    assert both_missing.exit_code == 1 and "exactly one of --run-id or --latest" in both_missing.output
    assert run("trace", "--latest").exit_code == 2  # --adapter and --case are required


def test_trace_before_any_run_explains_what_to_do(env: dict[str, Path]) -> None:
    initialized(env)
    result = run("trace", "--latest", "--adapter", "reference-runtime", "--case", "TP-001")
    assert result.exit_code == 1 and "no finished runs" in result.output


def test_trace_reads_only_the_redacted_payload(env: dict[str, Path]) -> None:
    """Even if the raw payload column held a marker, the command must never print it."""
    initialized(env)
    run("benchmark", "run", "--adapter", "reference-runtime", "--case-id", "DF-001")
    marker = sorted(MARKER_VALUES)[0]
    with session_for(env) as session:
        for event in session.query(models.Event).filter(models.Event.event_type == "policy_decision"):
            event.payload_json = {**event.payload_json, "reason": f"raw {marker}"}
    out = run("trace", "--latest", "--adapter", "reference-runtime", "--case", "DF-001").output
    assert marker not in out and "raw " not in out
