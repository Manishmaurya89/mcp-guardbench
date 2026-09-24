"""Benchmark runs: create, execute, cancel, and inspect."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response, status
from sqlalchemy import select

from guardbench.api.dependencies import AuthDep, RedactorDep, SessionDep, SettingsDep
from guardbench.api.pagination import PageDep, count_rows
from guardbench.api.redaction import RedactingRoute
from guardbench.benchmark.report import RunReport, render
from guardbench.db import models, repositories
from guardbench.domain.enums import RunStatus
from guardbench.domain.errors import ConflictError, ValidationFailure
from guardbench.domain.schemas import EventRead, Page, RunCreate, RunRead
from guardbench.services import runs as run_service
from guardbench.services.test_cases import load_and_sync

router = APIRouter(prefix="/runs", tags=["runs"], dependencies=[AuthDep], route_class=RedactingRoute)

MEDIA_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "html": "text/html; charset=utf-8",
}


def _run_read(run: models.BenchmarkRun) -> RunRead:
    """API view of a run. The full stored report is served by ``/runs/{id}/report``, not inlined."""
    summary = {k: v for k, v in run.summary_json.items() if k != "report"}
    return RunRead(
        id=run.id,
        project_id=run.project_id,
        status=RunStatus(run.status),
        started_at=run.started_at,
        completed_at=run.completed_at,
        configuration_json=run.configuration_json,
        summary_json=summary,
    )


@router.post("", response_model=RunRead, status_code=status.HTTP_201_CREATED)
def create_run(body: RunCreate, session: SessionDep, settings: SettingsDep) -> RunRead:
    """Create a pending run. Adapters and test-case ids are validated; no paths are accepted."""
    if body.test_case_ids:
        known = {c.spec.id for c in load_and_sync(session, settings.test_cases_dir)}
        unknown = sorted(set(body.test_case_ids) - known)
        if unknown:
            raise ValidationFailure(f"unknown test case ids: {unknown}; known: {sorted(known)}")
    run = run_service.create_run(
        session,
        body.project_id,
        adapters=body.adapters,
        test_case_ids=body.test_case_ids,
        seed=body.seed,
        mode=body.mode,
    )
    session.commit()
    return _run_read(run)


@router.get("", response_model=Page[RunRead])
def list_runs(
    session: SessionDep,
    page: PageDep,
    status_filter: Annotated[RunStatus | None, Query(alias="status")] = None,
    project_id: UUID | None = None,
) -> Page[RunRead]:
    """List runs, newest first."""
    statement = select(models.BenchmarkRun)
    if status_filter is not None:
        statement = statement.where(models.BenchmarkRun.status == status_filter.value)
    if project_id is not None:
        statement = statement.where(models.BenchmarkRun.project_id == project_id)
    rows = session.scalars(
        statement.order_by(models.BenchmarkRun.created_at.desc()).limit(page.limit).offset(page.offset)
    ).all()
    return Page[RunRead](
        items=[_run_read(r) for r in rows],
        total=count_rows(session, statement),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{run_id}", response_model=RunRead)
def get_run(run_id: UUID, session: SessionDep) -> RunRead:
    """Fetch one run with its configuration and summary."""
    return _run_read(repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run"))


@router.post("/{run_id}/execute", response_model=RunRead)
def execute_run(run_id: UUID, request: Request, session: SessionDep, settings: SettingsDep) -> RunRead:
    """Execute a pending run against the local lab fixtures. Blocks until the run finishes."""
    run = run_service.execute_run(
        session,
        run_id,
        test_cases_dir=settings.test_cases_dir,
        registry=request.app.state.run_registry,
    )
    return _run_read(run)


@router.post("/{run_id}/cancel", response_model=RunRead)
def cancel_run(run_id: UUID, request: Request, session: SessionDep) -> RunRead:
    """Cancel a pending run, or ask a running one to stop at the next case boundary."""
    return _run_read(run_service.cancel_run(session, run_id, request.app.state.run_registry))


@router.get("/{run_id}/events", response_model=Page[EventRead])
def list_events(
    run_id: UUID,
    session: SessionDep,
    page: PageDep,
    trace_id: Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")] = None,
    event_type: Annotated[str | None, Query(max_length=48)] = None,
    tool_name: Annotated[str | None, Query(max_length=256)] = None,
) -> Page[EventRead]:
    """The run's event trace in order. Only *redacted* payloads are ever returned."""
    repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    statement = select(models.Event).where(models.Event.run_id == run_id)
    if trace_id is not None:
        statement = statement.where(models.Event.trace_id == trace_id)
    if event_type is not None:
        statement = statement.where(models.Event.event_type == event_type)
    if tool_name is not None:
        statement = statement.where(models.Event.tool_name == tool_name)
    rows = session.scalars(
        statement.order_by(models.Event.sequence).limit(page.limit).offset(page.offset)
    ).all()
    return Page[EventRead](
        items=[EventRead.model_validate(r) for r in rows],
        total=count_rows(session, statement),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{run_id}/report")
def get_report(
    run_id: UUID,
    session: SessionDep,
    redactor: RedactorDep,
    report_format: Annotated[Literal["json", "markdown", "csv", "html"], Query(alias="format")] = "json",
) -> Response:
    """The run's report in the requested format. Always redacted; HTML is escaped and CSP-restricted."""
    run = repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    stored = run_service.report_for_run(run)
    if run.status not in {RunStatus.COMPLETED.value, RunStatus.CANCELLED.value}:
        raise ConflictError(f"run {run_id} is {run.status}; no report is available")
    report = RunReport.model_validate(redactor.redact(stored))
    headers = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    if report_format == "html":
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return Response(
        content=render(report, report_format), media_type=MEDIA_TYPES[report_format], headers=headers
    )
