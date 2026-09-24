"""Benchmark metrics."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from guardbench.api.dependencies import AuthDep, SessionDep
from guardbench.api.redaction import RedactingRoute
from guardbench.db import models, repositories
from guardbench.domain.schemas import MetricRead

router = APIRouter(tags=["metrics"], dependencies=[AuthDep], route_class=RedactingRoute)


@router.get("/runs/{run_id}/metrics", response_model=list[MetricRead])
def list_run_metrics(run_id: UUID, session: SessionDep, adapter: str | None = None) -> list[MetricRead]:
    """Metrics for a run. A null ``metric_value`` means *undefined*; see ``undefined_reason``."""
    repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    rows = session.scalars(
        select(models.Metric).where(models.Metric.run_id == run_id).order_by(models.Metric.metric_name)
    ).all()
    metrics = [MetricRead.model_validate(r) for r in rows]
    if adapter is not None:
        metrics = [m for m in metrics if m.dimensions_json.get("adapter") == adapter]
    return metrics
