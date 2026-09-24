"""Keep the ``test_cases`` table in step with the allowlisted test-case directory."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardbench.benchmark.test_case_loader import LoadedTestCase, load_test_cases
from guardbench.db import models
from guardbench.domain.errors import NotFoundError
from guardbench.domain.schemas import TestCaseRead


def sync_test_cases(session: Session, cases: list[LoadedTestCase]) -> dict[str, models.TestCase]:
    """Upsert ``cases`` by external id. Returns rows keyed by external id. Flushes, never commits."""
    existing = {row.external_id: row for row in session.scalars(select(models.TestCase))}
    for case in cases:
        spec = case.spec
        row = existing.get(spec.id)
        if row is None:
            row = models.TestCase(external_id=spec.id)
            session.add(row)
            existing[spec.id] = row
        row.name = spec.name
        row.category = spec.category.value
        row.severity = spec.severity.value
        row.description = spec.description
        row.yaml_path = case.path.name  # the file name only; never an absolute path
        row.spec_hash = case.spec_hash
        row.expected_behaviors = {
            **spec.expected.model_dump(mode="json"),
            "attack_stage": spec.attack_stage.value,
            "fixture": spec.server_fixture,
            "is_attack_case": spec.is_attack_case,
        }
        row.enabled = spec.enabled
    session.flush()
    return {c.spec.id: existing[c.spec.id] for c in cases}


def load_and_sync(session: Session, directory: Path) -> list[LoadedTestCase]:
    """Load the allowlisted directory and sync it to the database."""
    cases = load_test_cases(directory, allowed_root=directory)
    sync_test_cases(session, cases)
    return cases


def find_test_case(session: Session, identifier: str) -> models.TestCase:
    """Look up by database UUID or by external id such as ``TP-001``."""
    try:
        row = session.get(models.TestCase, UUID(identifier))
    except ValueError:
        row = session.scalars(
            select(models.TestCase).where(models.TestCase.external_id == identifier)
        ).first()
    if row is None:
        raise NotFoundError(f"test case {identifier!r} not found")
    return row


def test_case_to_read(row: models.TestCase) -> TestCaseRead:
    """API view of a stored test case."""
    return TestCaseRead.model_validate(row)
