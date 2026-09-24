"""The ``guardbench`` command-line interface.

Every lab command works on the fixtures shipped in this repository and contacts no external
server. The one exception is ``inspect``, which reads the tool list of MCP servers the *user*
configured (read-only: ``tools/list`` only, no tool is ever called). Errors are reported as one
clear line on stderr with a non-zero exit status. The dashboard launcher runs a fixed command
without a shell.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import typer
from sqlalchemy import inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from guardbench import __version__
from guardbench.analysis.drift_detector import compare_snapshots
from guardbench.analysis.fingerprinting import build_snapshot
from guardbench.analysis.metadata_analyzer import analyze_server
from guardbench.benchmark.adapters import adapter_names
from guardbench.benchmark.orchestrator import BenchmarkConfig, Orchestrator
from guardbench.benchmark.report import (
    REPORT_FILES,
    RunReport,
    build_report,
    render,
    report_summary,
    write_report_files,
)
from guardbench.benchmark.test_case_loader import load_test_cases
from guardbench.config import Settings, load_settings
from guardbench.db import models, repositories
from guardbench.db.migrate import upgrade_to_head
from guardbench.db.session import create_db_engine, create_session_factory, session_scope
from guardbench.domain.clock import utc_now
from guardbench.domain.enums import RunMode, Severity
from guardbench.domain.errors import GuardBenchError, InspectionError
from guardbench.domain.schemas import ProjectCreate, ServerIdentity
from guardbench.inspection import render as inspect_render
from guardbench.inspection.client import ServerListing, list_many, tools_from_listing
from guardbench.inspection.configs import (
    ConfigLoad,
    ServerSpec,
    discover_configs,
    load_config,
    load_json_file,
)
from guardbench.inspection.pins import PinFile, load_pins, save_pins
from guardbench.inspection.service import ServerResult
from guardbench.inspection.service import build_report as build_inspection_report
from guardbench.logging_config import configure_logging
from guardbench.mcp_lab.fixtures import create_fixture, fixture_info, fixture_names
from guardbench.policy.models import load_policy
from guardbench.runtime.redaction import Redactor
from guardbench.safe_paths import confine
from guardbench.services import runs as run_service
from guardbench.services import trace as trace_service
from guardbench.services.demo import seed_demo

BANNER = "MCP-GuardBench: local security lab. Results are experimental. No external server is scanned."
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_ADAPTERS = ("no-defense-baseline", "reference-static", "reference-runtime")
DASHBOARD_APP = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"

app = typer.Typer(
    name="guardbench",
    help="MCP-GuardBench: check your own MCP servers (`inspect`, read-only) and benchmark MCP security "
    "controls against local fixtures.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
    pretty_exceptions_show_locals=False,  # locals can hold connection URLs
)
benchmark_app = typer.Typer(help="Run and inspect benchmarks.", no_args_is_help=True, rich_markup_mode=None)
app.add_typer(benchmark_app, name="benchmark")

_redactor = Redactor()


def guarded[F: Callable[..., Any]](func: F) -> F:
    """Turn a :class:`GuardBenchError` into a single clear error line and exit status 1."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except GuardBenchError as exc:
            typer.secho(f"error: {_redactor.redact_text(str(exc))}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from exc
        except SQLAlchemyError as exc:
            # Never print the URL or the driver's full message: either can contain credentials.
            orig = getattr(exc, "orig", None)
            detail = type(orig).__name__ if orig is not None else type(exc).__name__
            typer.secho(
                f"error: database problem ({detail}). Check GUARDBENCH_DATABASE_URL and that the "
                "database is reachable; for a new database run `guardbench init-db`.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1) from exc

    return wrapper  # type: ignore[return-value]


def _settings() -> Settings:
    settings = load_settings()
    configure_logging(
        "WARNING" if settings.log_level == "INFO" else settings.log_level, json_output=settings.log_json
    )
    return settings


def _session_factory(settings: Settings):  # type: ignore[no-untyped-def]
    engine = create_db_engine(settings.database_url)
    if not inspect(engine).has_table("projects"):
        raise GuardBenchError("the database is not initialized; run `guardbench init-db` first")
    return create_session_factory(engine)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True))
    body = ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)) for r in rows]
    return "\n".join([line, "  ".join("-" * w for w in widths), *body])


def _pct(value: float | None) -> str:
    return "undefined" if value is None else f"{value * 100:.1f}%"


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"mcp-guardbench {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    """MCP-GuardBench command-line interface."""


# --------------------------------------------------------------------------- database


@app.command("init-db")
@guarded
def init_db() -> None:
    """Create or upgrade the database schema with Alembic migrations."""
    settings = _settings()
    upgrade_to_head(settings.database_url, settings.alembic_ini)
    typer.echo("Database is up to date.")


@app.command("seed-demo")
@guarded
def seed_demo_command() -> None:
    """Register and scan every lab fixture, approve baselines, and stage a simulated rug pull (idempotent)."""
    settings = _settings()
    factory = _session_factory(settings)
    with session_scope(factory) as session:
        result = seed_demo(session)
        typer.echo(BANNER)
        typer.echo(f"Project '{result.project.name}': {len(result.servers)} fixture servers scanned.")
        if result.approved:
            typer.echo(f"Approved baselines: {', '.join(result.approved)}")
        if result.drifted:
            typer.echo(f"Simulated rug pull staged (drift now visible): {', '.join(result.drifted)}")
    typer.echo("Next: `guardbench benchmark run`, then `guardbench serve` and `guardbench dashboard`.")


# --------------------------------------------------------------------------- inspection


@app.command("list-test-cases")
@guarded
def list_test_cases(
    cases: Annotated[
        Path | None, typer.Option("--cases", help="Test-case directory (must be the allowlisted one).")
    ] = None,
) -> None:
    """List the test cases in the allowlisted test-case directory."""
    settings = _settings()
    directory = confine(cases or settings.test_cases_dir, settings.test_cases_dir)
    loaded = load_test_cases(directory, allowed_root=settings.test_cases_dir)
    rows = [
        [
            c.spec.id,
            c.spec.category.value,
            c.spec.severity.value,
            c.spec.attack_stage.value,
            c.spec.server_fixture,
            "attack" if c.spec.is_attack_case else "control",
            c.spec.name,
        ]
        for c in loaded
    ]
    typer.echo(_table(["ID", "CATEGORY", "SEVERITY", "STAGE", "FIXTURE", "KIND", "NAME"], rows))
    typer.echo(f"\n{len(loaded)} test case(s).")


@app.command("list-fixtures")
def list_fixtures() -> None:
    """List the allowlisted lab fixtures."""
    rows = [
        [i.name, str(i.tool_count), "yes" if i.supports_state_advance else "no", i.summary]
        for i in fixture_info()
    ]
    typer.echo(_table(["FIXTURE", "TOOLS", "DRIFT", "SUMMARY"], rows))


@app.command("list-adapters")
def list_adapters() -> None:
    """List the selectable security adapters."""
    for name in adapter_names():
        typer.echo(name)


def _fixture(name: str):  # type: ignore[no-untyped-def]
    if name not in fixture_names():
        raise GuardBenchError(f"unknown fixture {name!r}; choose from: {', '.join(fixture_names())}")
    return create_fixture(name)


@app.command("analyze-fixture")
@guarded
def analyze_fixture(
    fixture: Annotated[str, typer.Option("--fixture", help="Allowlisted fixture name.")],
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Run the static metadata analyzer on a fixture's tools."""
    lab = _fixture(fixture)
    findings = analyze_server(lab.name, lab.tool_definitions())
    if as_json:
        typer.echo(json.dumps(_redactor.redact([f.model_dump(mode="json") for f in findings]), indent=2))
        return
    typer.echo(f"{BANNER}\nFixture: {lab.name}: {lab.summary}\n")
    if not findings:
        typer.echo("No findings.")
        return
    rows = [
        [
            f.severity.value,
            f.rule_id,
            f"{f.confidence:.2f}",
            f.category.value,
            f.tool_name or "",
            f.location or "",
        ]
        for f in findings
    ]
    typer.echo(_table(["SEVERITY", "RULE", "CONF", "CATEGORY", "TOOL", "LOCATION"], rows))
    top = max(f.severity for f in findings)
    typer.echo(
        f"\n{len(findings)} finding(s); highest severity: {top.value}. "
        "Static analysis can miss semantic attacks."
    )


@app.command("fingerprint")
@guarded
def fingerprint(fixture: Annotated[str, typer.Option("--fixture", help="Allowlisted fixture name.")]) -> None:
    """Print SHA-256 fingerprints of a fixture's tool definitions and of the whole tool set."""
    lab = _fixture(fixture)
    snapshot = build_snapshot(lab.name, lab.tool_definitions(), lab.identity())
    typer.echo(f"Fixture: {lab.name}  (server version {snapshot.identity.version})")
    typer.echo(_table(["TOOL", "SHA-256"], [[n, h] for n, h in sorted(snapshot.tool_hashes.items())]))
    typer.echo(f"\nTool set: {snapshot.snapshot_hash}")
    typer.echo("A hash detects change relative to a snapshot; it does not prove the server is trustworthy.")


@app.command("detect-drift")
@guarded
def detect_drift(
    fixture: Annotated[str, typer.Option("--fixture", help="A drift-capable fixture, e.g. drift_server.")],
) -> None:
    """Snapshot a fixture, apply its deterministic change, and report the drift."""
    lab = _fixture(fixture)
    if not lab.supports_state_advance:
        raise GuardBenchError(f"fixture {fixture!r} has no state to advance; try `--fixture drift_server`")
    baseline = build_snapshot(lab.name, lab.tool_definitions(), lab.identity())
    lab.advance_state()
    current = build_snapshot(lab.name, lab.tool_definitions(), lab.identity())
    report = compare_snapshots(baseline, current)
    typer.echo(f"{BANNER}\nFixture: {lab.name}")
    typer.echo(f"Baseline : {report.old_hash}\nCurrent  : {report.new_hash}")
    typer.echo(
        f"Drifted  : {report.drifted}   Severity: {report.severity.value}   "
        f"Action: {report.recommended_action}"
    )
    for reason in report.reasons:
        typer.echo(f"  - {reason}")


# --------------------------------------------------------------------------- your own MCP servers


class FailOn(StrEnum):
    """Lowest finding severity that makes ``inspect`` exit with status 1."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _unique_specs(loads: list[ConfigLoad]) -> list[ServerSpec]:
    """Every server from every config; a name used twice gets the client label appended."""
    specs: list[ServerSpec] = []
    taken: set[str] = set()
    for load in loads:
        for spec in load.servers:
            name, n = spec.name, 2
            if name in taken:
                name = f"{spec.name} ({load.client})"
            while name in taken:
                name, n = f"{spec.name} ({load.client} {n})", n + 1
            taken.add(name)
            specs.append(dataclasses.replace(spec, name=name))
    return specs


def _offline_listing(path: Path) -> tuple[ServerResult, ServerListing]:
    name = path.stem
    tools = tools_from_listing(load_json_file(path, what="tools file"))
    result = ServerResult(name=name, source=str(path), transport="file", target=str(path))
    return result, ServerListing(identity=ServerIdentity(name=name), tools=tools)


@app.command("inspect")
@guarded
def inspect_command(
    configs: Annotated[
        list[Path] | None,
        typer.Argument(
            help="MCP client config file(s): claude_desktop_config.json, .mcp.json, .cursor/mcp.json, "
            ".vscode/mcp.json, ...",
            show_default=False,
        ),
    ] = None,
    discover: Annotated[
        bool,
        typer.Option(
            "--discover",
            help="Also read the well-known config files of Claude Desktop, Claude Code, Cursor, Windsurf and "
            "VS Code on this machine.",
        ),
    ] = False,
    tools_json: Annotated[
        list[Path] | None,
        typer.Option(
            "--tools-json",
            help="Offline: analyze a saved tools/list result (JSON) without starting anything. Repeatable.",
        ),
    ] = None,
    server: Annotated[
        list[str] | None, typer.Option("--server", help="Only inspect this server name. Repeatable.")
    ] = None,
    pins: Annotated[
        Path,
        typer.Option("--pins", help="Pin file of approved tool fingerprints (written by --update-pins)."),
    ] = Path("guardbench-pins.json"),
    update_pins: Annotated[
        bool,
        typer.Option(
            "--update-pins", help="Approve what was seen now: write the current fingerprints to the pin file."
        ),
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", min=1.0, max=600.0, help="Seconds allowed per server.")
    ] = 30.0,
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", help="Lowest finding severity to print.")
    ] = Severity.LOW,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on", help="Exit with status 1 when a finding reaches this severity ('none' never)."
        ),
    ] = FailOn.HIGH,
    details: Annotated[
        bool, typer.Option("--details", help="List every finding, not only high and critical ones.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Check the MCP servers in your own client config. Read-only: tools/list only, no tool is called.

    stdio servers are started exactly as your MCP client would start them (same command, arguments,
    and environment); HTTP servers are contacted at their configured URL. Tool metadata and server
    instructions are analyzed with the deterministic rules, and fingerprints are compared with the
    pin file to catch tools that changed after you approved them. Exit status 1 means a server could
    not be inspected or a finding reached --fail-on.
    """
    from guardbench.asyncio_utils import run_sync

    loads: list[ConfigLoad] = [load_config(path, client="config") for path in configs or []]
    if discover:
        for client, path in discover_configs():
            try:
                loads.append(load_config(path, client=client))
            except InspectionError as exc:
                loads.append(
                    ConfigLoad(source=str(path), client=client, servers=[], problems=[f"skipped: {exc}"])
                )
    offline = [_offline_listing(path) for path in tools_json or []]
    specs = _unique_specs(loads)
    if server:
        known = {s.name for s in specs} | {r.name for r, _ in offline}
        unknown = sorted(set(server) - known)
        if unknown:
            raise GuardBenchError(f"unknown server name(s) {unknown}; configured: {sorted(known)}")
        specs = [s for s in specs if s.name in server]
        offline = [(r, lst) for r, lst in offline if r.name in server]
    if not specs and not offline:
        if discover or configs:
            raise GuardBenchError("no MCP servers found to inspect")
        raise GuardBenchError(
            "give an MCP config file, --discover, or --tools-json (see `guardbench inspect --help`)"
        )

    pin_file = load_pins(pins)
    if not as_json:
        typer.echo(inspect_render.BANNER)
        for line in inspect_render.render_loads(loads):
            typer.echo(line)
        if specs:
            typer.echo(f"Listing tools of {len(specs)} server(s) (timeout {timeout:g}s each)...")
        typer.echo("")

    listings: dict[str, ServerListing | InspectionError] = dict(
        run_sync(lambda: list_many(specs, timeout=timeout)) if specs else {}
    )
    results = [
        ServerResult(name=s.name, source=s.source, transport=s.transport, target=s.display_target())
        for s in specs
    ]
    for result, listing in offline:
        results.append(result)
        listings[result.name] = listing
    report = build_inspection_report(results, listings, pin_file)

    if update_pins:
        pin_file = pin_file or PinFile()
        pinned = [r for r in report.servers if r.snapshot is not None]
        for result in pinned:
            assert result.snapshot is not None
            pin_file.pin(result.snapshot)
        save_pins(pin_file, pins)

    if as_json:
        typer.echo(json.dumps(_redactor.redact(report.to_dict()), indent=2))
    else:
        typer.echo(
            inspect_render.render_text(
                report, min_severity=min_severity, details=details, suggest_pinning=not update_pins
            )
        )
        if update_pins:
            typer.echo(f"Pinned {len(pinned)} server(s) in {pins}.")

    failed = [s.name for s in report.servers if not s.ok]
    threshold = None if fail_on is FailOn.NONE else Severity(fail_on.value)
    over = threshold is not None and report.highest is not None and report.highest >= threshold
    if failed or over:
        reasons = ([f"{len(failed)} server(s) could not be inspected"] if failed else []) + (
            [f"a finding reached --fail-on {fail_on.value}"] if over else []
        )
        typer.secho(f"Exit status 1: {'; '.join(reasons)}.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- benchmark


@benchmark_app.command("run")
@guarded
def benchmark_run(
    project: Annotated[str, typer.Option("--project", help="Project name (created if missing).")] = "demo",
    cases: Annotated[
        Path | None, typer.Option("--cases", help="Test-case directory (must be the allowlisted one).")
    ] = None,
    adapter: Annotated[
        list[str] | None, typer.Option("--adapter", help="Adapter to run; repeatable.")
    ] = None,
    case_id: Annotated[
        list[str] | None, typer.Option("--case-id", help="Only run these test-case ids; repeatable.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write report files here (inside the reports directory).")
    ] = None,
    formats: Annotated[
        list[str] | None, typer.Option("--format", help="json, markdown, csv, html; repeatable.")
    ] = None,
    seed: Annotated[int, typer.Option("--seed", min=0, help="Seed for reproducible trace ids.")] = 0,
    mode: Annotated[
        RunMode,
        typer.Option("--mode", help="unattended never approves; interactive allows an approval step."),
    ] = RunMode.UNATTENDED,
    persist: Annotated[
        bool, typer.Option("--persist/--no-persist", help="Store the run in the database.")
    ] = True,
) -> None:
    """Run test cases against one or more adapters and print verified metrics."""
    settings = _settings()
    directory = confine(cases or settings.test_cases_dir, settings.test_cases_dir)
    selected = tuple(adapter) if adapter else DEFAULT_ADAPTERS
    wanted = tuple(formats) if formats else ("json", "markdown", "csv")
    bad_formats = sorted(set(wanted) - set(REPORT_FILES))
    if bad_formats:
        raise GuardBenchError(f"unknown format(s) {bad_formats}; choose from {', '.join(REPORT_FILES)}")
    output_dir = (
        confine(output, settings.reports_dir) if output is not None else None
    )  # fail fast, before any work
    typer.echo(BANNER)

    if persist:
        report = _run_persisted(settings, project, directory, selected, case_id, seed, mode)
    else:
        loaded = load_test_cases(directory, allowed_root=settings.test_cases_dir)
        outcome = _run_local(loaded, selected, case_id, seed, mode)
        report = build_report(outcome, generated_at=utc_now())
        _print_summary(report_summary(outcome)["adapters"], outcome.results, outcome.run_id)

    if output_dir is not None:
        written = write_report_files(report, output_dir, settings.reports_dir, wanted)
        for fmt, path in written.items():
            typer.echo(f"Wrote {fmt}: {path}")


def _run_local(
    loaded: list[Any], adapters: tuple[str, ...], ids: list[str] | None, seed: int, mode: RunMode
) -> Any:
    from guardbench.asyncio_utils import run_sync

    orchestrator = Orchestrator(loaded, load_policy())
    config = BenchmarkConfig(
        adapters=adapters, test_case_ids=tuple(ids) if ids else None, seed=seed, mode=mode
    )

    def progress(adapter_name: str, case: str, status: str) -> None:
        typer.echo(f"  {adapter_name:22} {case:8} {status}")

    return run_sync(lambda: orchestrator.run(config, progress=progress))


def _run_persisted(
    settings: Settings,
    project: str,
    directory: Path,
    adapters: tuple[str, ...],
    ids: list[str] | None,
    seed: int,
    mode: RunMode,
) -> RunReport:
    factory = _session_factory(settings)
    with session_scope(factory) as session:
        row = repositories.get_project_by_name(session, project) or repositories.create_project(
            session, ProjectCreate(name=project, description="Created by `guardbench benchmark run`.")
        )
        run = run_service.create_run(
            session, row.id, adapters=list(adapters), test_case_ids=ids, seed=seed, mode=mode
        )
        session.commit()
        finished = run_service.execute_run(
            session, run.id, test_cases_dir=directory, registry=run_service.RunRegistry()
        )
        summary = finished.summary_json
        report = RunReport.model_validate(run_service.report_for_run(finished))
        typer.echo(f"Run {finished.id}: {finished.status}")
        _print_summary(summary.get("adapters", {}), None, finished.id, report=report)
    return report


def _print_summary(
    adapters: dict[str, dict[str, float | None]],
    results: Any,
    run_id: UUID,
    *,
    report: RunReport | None = None,
) -> None:
    rows = [
        [
            name,
            _pct(h.get("detection_rate")),
            _pct(h.get("prevention_rate")),
            _pct(h.get("false_positive_rate")),
            _pct(h.get("evidence_completeness_rate")),
        ]
        for name, h in adapters.items()
    ]
    typer.echo("")
    typer.echo(_table(["ADAPTER", "DETECTION", "PREVENTION", "FALSE POSITIVES", "EVIDENCE"], rows))
    if report is not None and report.skipped_tests:
        typer.echo(f"\n{len(report.skipped_tests)} case(s) skipped (see the report for reasons).")
    typer.echo(
        "\nDetection: an evidenced finding of the expected kind. Prevention: the unsafe simulated action was"
    )
    typer.echo("actually blocked (verified from fixture ground truth). 'undefined' means a zero denominator.")
    typer.echo(f"Run id: {run_id}")


def _resolve_run(session: Session, run_id: UUID | None, latest: bool) -> models.BenchmarkRun:
    """The run named by --run-id, or the most recent finished run for --latest. Exactly one is required."""
    if (run_id is None) == (not latest):
        raise GuardBenchError("give exactly one of --run-id or --latest")
    if run_id is not None:
        return repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    row = session.scalars(
        select(models.BenchmarkRun)
        .where(models.BenchmarkRun.status.in_(["completed", "cancelled"]))
        .order_by(models.BenchmarkRun.completed_at.desc())
        .limit(1)
    ).first()
    if row is None:
        raise GuardBenchError("no finished runs yet; run `guardbench benchmark run` first")
    return row


@app.command("report")
@guarded
def report_command(
    run_id: Annotated[UUID | None, typer.Option("--run-id", help="A run id from `benchmark run`.")] = None,
    latest: Annotated[bool, typer.Option("--latest", help="Use the most recent finished run.")] = False,
    fmt: Annotated[str, typer.Option("--format", help="json, markdown, csv, or html.")] = "markdown",
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write into this directory (inside the reports directory)."),
    ] = None,
) -> None:
    """Print (or write) the stored report of a finished run."""
    settings = _settings()
    if fmt not in REPORT_FILES:
        raise GuardBenchError(f"unknown format {fmt!r}; choose from {', '.join(REPORT_FILES)}")
    output_dir = confine(output, settings.reports_dir) if output is not None else None
    factory = _session_factory(settings)
    with session_scope(factory) as session:
        run = _resolve_run(session, run_id, latest)
        report = RunReport.model_validate(run_service.report_for_run(run))
    if output_dir is not None:
        written = write_report_files(report, output_dir, settings.reports_dir, (fmt,))
        typer.echo(f"Wrote {fmt}: {written[fmt]}")
    else:
        typer.echo(render(report, fmt))


@app.command("summary")
@guarded
def summary_command(
    run_id: Annotated[UUID | None, typer.Option("--run-id", help="A run id.")] = None,
    latest: Annotated[bool, typer.Option("--latest", help="Use the most recent finished run.")] = False,
) -> None:
    """Show the headline metrics of a stored run."""
    settings = _settings()
    factory = _session_factory(settings)
    with session_scope(factory) as session:
        run = _resolve_run(session, run_id, latest)
        report = RunReport.model_validate(run_service.report_for_run(run))
    rows = []
    for adapter in [a["name"] for a in report.adapters]:
        values = {
            m["name"]: m["value"]
            for m in report.metrics
            if m["dimensions"].get("adapter") == adapter and "category" not in m["dimensions"]
        }
        rows.append(
            [
                adapter,
                *[_pct(values.get(k)) for k in ("detection_rate", "prevention_rate", "false_positive_rate")],
            ]
        )
    typer.echo(_table(["ADAPTER", "DETECTION", "PREVENTION", "FALSE POSITIVES"], rows))


@app.command("trace")
@guarded
def trace_command(
    adapter: Annotated[str, typer.Option("--adapter", help="Adapter name, e.g. reference-runtime.")],
    case: Annotated[str, typer.Option("--case", help="Test-case id, e.g. DF-001.")],
    run_id: Annotated[UUID | None, typer.Option("--run-id", help="A run id.")] = None,
    latest: Annotated[bool, typer.Option("--latest", help="Use the most recent finished run.")] = False,
) -> None:
    """Print the recorded event trace of one test case under one adapter (redacted payloads only)."""
    settings = _settings()
    factory = _session_factory(settings)
    with session_scope(factory) as session:
        run = _resolve_run(session, run_id, latest)
        trace = trace_service.load_trace(session, run, adapter, case)
        run_label = str(run.id)
    typer.echo(
        f"{BANNER}\nTrace {trace.trace_id}: {adapter} / {case} (run {run_label}), {len(trace.rows)} events\n"
    )
    headers = ["#", "EVENT", "TOOL", "DECISION", "RULE", "DETAIL"]
    rows = [[str(r.position), r.event_type, r.tool, r.decision, r.rule, r.detail] for r in trace.rows]
    typer.echo(_table(headers, rows))
    if trace.flows:
        typer.echo("\nSynthetic data-flow paths (marker ids only; nothing real is tracked):")
        for flow in trace.flows:
            typer.echo("\n".join(f"  {line}" for line in flow))


# --------------------------------------------------------------------------- services


@app.command("serve")
@guarded
def serve(
    host: Annotated[str | None, typer.Option("--host", help="Bind address (default from settings).")] = None,
    port: Annotated[
        int | None, typer.Option("--port", min=1, max=65535, help="Port (default from settings).")
    ] = None,
) -> None:
    """Start the REST API. Refuses to expose the unauthenticated dev mode beyond loopback."""
    import uvicorn

    settings = _settings()
    bind = host or settings.api_host
    if bind not in LOOPBACK_HOSTS and settings.dev_mode:
        raise GuardBenchError(
            f"refusing to bind {bind} in dev mode: it has no authentication. "
            "Set GUARDBENCH_DEV_MODE=false and GUARDBENCH_API_KEY, or bind 127.0.0.1."
        )
    if not settings.dev_mode and settings.api_key_value is None:
        raise GuardBenchError("GUARDBENCH_API_KEY is required when GUARDBENCH_DEV_MODE is false")
    typer.echo(
        f"{BANNER}\nServing on http://{bind}:{port or settings.api_port}  (dev mode: {settings.dev_mode})"
    )
    uvicorn.run(
        "guardbench.api.main:create_app",
        factory=True,
        host=bind,
        port=port or settings.api_port,
        log_config=None,
    )


@app.command("dashboard")
@guarded
def dashboard(
    port: Annotated[
        int | None, typer.Option("--port", min=1, max=65535, help="Port (default from settings).")
    ] = None,
    host: Annotated[str, typer.Option("--host", help="Bind address for the dashboard.")] = "127.0.0.1",
) -> None:
    """Start the read-only Streamlit dashboard (it reads data through the API)."""
    settings = _settings()
    if not DASHBOARD_APP.is_file():
        raise GuardBenchError("dashboard app not found; is the package installed correctly?")
    if shutil.which(sys.executable) is None:
        raise GuardBenchError("cannot locate the Python interpreter")
    try:
        import streamlit  # noqa: F401
    except ImportError as exc:
        raise GuardBenchError(
            "streamlit is not installed; install with `pip install 'mcp-guardbench[dashboard]'`"
        ) from exc
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(DASHBOARD_APP),
        "--server.address",
        host,
        "--server.port",
        str(port or settings.dashboard_port),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]  # fixed argument list; nothing here comes from a request
    typer.echo(
        f"{BANNER}\nDashboard on http://{host}:{port or settings.dashboard_port} (API: {settings.api_url})"
    )
    raise typer.Exit(subprocess.call(command))  # noqa: S603


if __name__ == "__main__":  # pragma: no cover
    app()
