"""Test-case catalogue and validation. Test cases are chosen by ID; the API never accepts a path."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select

from guardbench.api.dependencies import AuthDep, SessionDep, SettingsDep
from guardbench.api.pagination import PageDep, count_rows
from guardbench.api.redaction import RedactingRoute
from guardbench.benchmark.test_case_loader import parse_test_case
from guardbench.db import models
from guardbench.domain.errors import GuardBenchError, TestCaseError
from guardbench.domain.schemas import Page, TestCaseRead, ValidateTestCaseRequest, ValidateTestCaseResponse
from guardbench.logging_config import get_logger
from guardbench.services.test_cases import find_test_case, load_and_sync, test_case_to_read

log = get_logger("api.test_cases")
router = APIRouter(
    prefix="/test-cases", tags=["test-cases"], dependencies=[AuthDep], route_class=RedactingRoute
)


def _ensure_loaded(session: SessionDep, settings: SettingsDep) -> None:
    """Populate the catalogue from the allowlisted directory the first time it is needed."""
    if session.scalar(select(models.TestCase.id).limit(1)) is not None:
        return
    try:
        load_and_sync(session, settings.test_cases_dir)
        session.commit()
    except GuardBenchError:
        session.rollback()
        log.exception("test_case_directory_unavailable")


@router.get("", response_model=Page[TestCaseRead])
def list_test_cases(
    session: SessionDep,
    settings: SettingsDep,
    page: PageDep,
    category: str | None = None,
    enabled: bool | None = None,
) -> Page[TestCaseRead]:
    """List test cases, optionally filtered by category or enabled flag."""
    _ensure_loaded(session, settings)
    statement = select(models.TestCase)
    if category is not None:
        statement = statement.where(models.TestCase.category == category)
    if enabled is not None:
        statement = statement.where(models.TestCase.enabled.is_(enabled))
    rows = session.scalars(
        statement.order_by(models.TestCase.external_id).limit(page.limit).offset(page.offset)
    ).all()
    return Page[TestCaseRead](
        items=[test_case_to_read(r) for r in rows],
        total=count_rows(session, statement),
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/validate", response_model=ValidateTestCaseResponse)
def validate_test_case(body: ValidateTestCaseRequest) -> ValidateTestCaseResponse:
    """Validate test-case YAML *text*. Nothing is stored, no path is read, and nothing is executed."""
    try:
        spec = parse_test_case(body.yaml, source="request")
    except TestCaseError as exc:
        return ValidateTestCaseResponse(valid=False, errors=[str(exc)])
    return ValidateTestCaseResponse(valid=True, errors=[], spec=spec.model_dump(mode="json"))


@router.get("/{test_case_id}", response_model=TestCaseRead)
def get_test_case(test_case_id: str, session: SessionDep, settings: SettingsDep) -> TestCaseRead:
    """Fetch a test case by database id or by its external id (for example ``TP-001``)."""
    _ensure_loaded(session, settings)
    return test_case_to_read(find_test_case(session, test_case_id))
