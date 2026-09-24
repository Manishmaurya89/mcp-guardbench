"""Findings, globally and per run. Output is always redacted."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import Select, case, select

from guardbench.api.dependencies import AuthDep, SessionDep
from guardbench.api.pagination import PageDep, count_rows
from guardbench.api.redaction import RedactingRoute
from guardbench.db import models, repositories
from guardbench.domain.enums import FindingCategory, FindingStatus, Severity
from guardbench.domain.schemas import FindingRead, Page

router = APIRouter(tags=["findings"], dependencies=[AuthDep], route_class=RedactingRoute)

_SEVERITY_RANK = case(*[(models.Finding.severity == s.value, s.rank) for s in Severity], else_=-1)


def _filtered(
    statement: Select[tuple[models.Finding]],
    severity: Severity | None,
    category: FindingCategory | None,
    status: FindingStatus | None,
) -> Select[tuple[models.Finding]]:
    if severity is not None:
        statement = statement.where(models.Finding.severity == severity.value)
    if category is not None:
        statement = statement.where(models.Finding.category == category.value)
    if status is not None:
        statement = statement.where(models.Finding.status == status.value)
    return statement


def _page(session: SessionDep, statement: Select[tuple[models.Finding]], page: PageDep) -> Page[FindingRead]:
    rows = session.scalars(
        statement.order_by(_SEVERITY_RANK.desc(), models.Finding.created_at.desc(), models.Finding.id)
        .limit(page.limit)
        .offset(page.offset)
    ).all()
    return Page[FindingRead](
        items=[FindingRead.model_validate(r) for r in rows],
        total=count_rows(session, statement),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/findings", response_model=Page[FindingRead])
def list_findings(
    session: SessionDep,
    page: PageDep,
    severity: Severity | None = None,
    category: FindingCategory | None = None,
    status: FindingStatus | None = None,
    run_id: UUID | None = None,
    server_id: UUID | None = None,
) -> Page[FindingRead]:
    """All findings, most severe first, with optional filters."""
    statement = _filtered(select(models.Finding), severity, category, status)
    if run_id is not None:
        statement = statement.where(models.Finding.run_id == run_id)
    if server_id is not None:
        statement = statement.where(models.Finding.server_id == server_id)
    return _page(session, statement, page)


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: UUID, session: SessionDep) -> FindingRead:
    """Fetch one finding with its evidence."""
    row = repositories.get_or_raise(session, models.Finding, finding_id, "finding")
    return FindingRead.model_validate(row)


@router.get("/runs/{run_id}/findings", response_model=Page[FindingRead])
def list_run_findings(
    run_id: UUID,
    session: SessionDep,
    page: PageDep,
    severity: Severity | None = None,
    category: FindingCategory | None = None,
    status: FindingStatus | None = None,
) -> Page[FindingRead]:
    """Findings produced by one run (paginated)."""
    repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    statement = _filtered(
        select(models.Finding).where(models.Finding.run_id == run_id), severity, category, status
    )
    return _page(session, statement, page)
