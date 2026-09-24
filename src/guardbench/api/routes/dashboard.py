"""Headline numbers for the dashboard."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func, select

from guardbench.api.dependencies import AuthDep, SessionDep
from guardbench.api.redaction import RedactingRoute
from guardbench.db import models
from guardbench.domain.enums import FindingStatus, RunStatus, Severity
from guardbench.domain.schemas import DashboardSummary

router = APIRouter(tags=["dashboard"], dependencies=[AuthDep], route_class=RedactingRoute)

#: Adapter whose rates populate the single-number overview cards, when it took part in the latest run.
PRIMARY_ADAPTER = "reference-runtime"


def _count(session: SessionDep, model: type, *criteria: object) -> int:
    return int(session.scalar(select(func.count()).select_from(model).where(*criteria)) or 0)  # type: ignore[arg-type]


@router.get("/dashboard-summary", response_model=DashboardSummary)
def dashboard_summary(session: SessionDep) -> DashboardSummary:
    """Totals plus the headline rates of the most recent completed run."""
    latest = session.scalars(
        select(models.BenchmarkRun)
        .where(models.BenchmarkRun.status == RunStatus.COMPLETED.value)
        .order_by(models.BenchmarkRun.completed_at.desc())
        .limit(1)
    ).first()
    headlines: dict[str, dict[str, float | None]] = {}
    if latest is not None:
        raw = latest.summary_json.get("adapters", {})
        headlines = {a: dict(v) for a, v in raw.items()} if isinstance(raw, dict) else {}
    primary = headlines.get(PRIMARY_ADAPTER) or (next(iter(headlines.values()), {}) if headlines else {})
    return DashboardSummary(
        total_runs=_count(session, models.BenchmarkRun),
        total_test_cases=_count(session, models.TestCase),
        total_servers=_count(session, models.MCPServer),
        open_findings=_count(session, models.Finding, models.Finding.status == FindingStatus.OPEN.value),
        high_severity_findings=_count(
            session,
            models.Finding,
            models.Finding.status == FindingStatus.OPEN.value,
            models.Finding.severity.in_([Severity.HIGH.value, Severity.CRITICAL.value]),
        ),
        detection_rate=primary.get("detection_rate"),
        prevention_rate=primary.get("prevention_rate"),
        latest_run_id=latest.id if latest else None,
        latest_run_headlines=headlines,
    )
