"""Benchmark run lifecycle and persistence.

A run moves ``pending -> running -> completed | failed | cancelled``. Execution is synchronous
within the caller; cancellation is cooperative and thread-safe (a cancel request arrives on a
different worker thread than the execute that is running).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardbench.asyncio_utils import run_sync
from guardbench.benchmark.adapters import adapter_names
from guardbench.benchmark.orchestrator import BenchmarkConfig, BenchmarkOutcome, Orchestrator
from guardbench.benchmark.report import build_report, report_summary
from guardbench.db import models, repositories
from guardbench.domain.clock import Clock, SystemClock
from guardbench.domain.enums import RunMode, RunStatus, Severity
from guardbench.domain.errors import ConflictError, GuardBenchError, ValidationFailure
from guardbench.logging_config import get_logger
from guardbench.policy.models import PolicyConfig, load_policy
from guardbench.runtime.redaction import Redactor
from guardbench.services.test_cases import load_and_sync

log = get_logger("runs")


@dataclass(slots=True)
class RunRegistry:
    """Cancellation events for runs currently executing in this process."""

    _events: dict[UUID, threading.Event] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def register(self, run_id: UUID) -> threading.Event:
        """Create the cancel event for a run that is about to execute."""
        event = threading.Event()
        with self._lock:
            self._events[run_id] = event
        return event

    def request_cancel(self, run_id: UUID) -> bool:
        """Signal cancellation; returns whether the run was executing here."""
        with self._lock:
            event = self._events.get(run_id)
        if event is None:
            return False
        event.set()
        return True

    def release(self, run_id: UUID) -> None:
        """Forget a finished run."""
        with self._lock:
            self._events.pop(run_id, None)


def config_from_run(run: models.BenchmarkRun) -> BenchmarkConfig:
    """Rebuild the orchestrator configuration recorded on a run."""
    raw = run.configuration_json
    ids = raw.get("test_case_ids")
    return BenchmarkConfig(
        adapters=tuple(raw["adapters"]),
        test_case_ids=tuple(ids) if ids else None,
        seed=int(raw.get("seed", 0)),
        mode=RunMode(raw.get("mode", RunMode.UNATTENDED.value)),
        min_detection_severity=Severity(raw.get("min_detection_severity", Severity.MEDIUM.value)),
    )


def create_run(
    session: Session,
    project_id: UUID,
    *,
    adapters: list[str],
    test_case_ids: list[str] | None,
    seed: int,
    mode: RunMode = RunMode.UNATTENDED,
) -> models.BenchmarkRun:
    """Create a pending run. Adapter names are validated against the registry; nothing else is trusted."""
    repositories.get_or_raise(session, models.Project, project_id, "project")
    unknown = sorted(set(adapters) - set(adapter_names()))
    if unknown:
        raise ValidationFailure(f"unknown adapters {unknown}; available: {adapter_names()}")
    config = BenchmarkConfig(
        adapters=tuple(dict.fromkeys(adapters)),
        test_case_ids=tuple(test_case_ids) if test_case_ids else None,
        seed=seed,
        mode=mode,
    )
    run = models.BenchmarkRun(
        project_id=project_id,
        status=RunStatus.PENDING.value,
        configuration_json=config.to_json(),
        summary_json={},
    )
    session.add(run)
    session.flush()
    return run


def execute_run(
    session: Session,
    run_id: UUID,
    *,
    test_cases_dir: Path,
    registry: RunRegistry,
    policy: PolicyConfig | None = None,
    clock: Clock | None = None,
) -> models.BenchmarkRun:
    """Execute a pending run, persist its outcome, and return it. Commits as it goes."""
    clock = clock or SystemClock()
    run = repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    if run.status != RunStatus.PENDING.value:
        raise ConflictError(f"run {run_id} is {run.status}; only a pending run can be executed")

    run.status = RunStatus.RUNNING.value
    run.started_at = clock.now()
    session.commit()  # make 'running' visible so a concurrent cancel request can see it
    cancel = registry.register(run.id)
    try:
        cases = load_and_sync(session, test_cases_dir)
        outcome = run_sync(
            lambda: Orchestrator(cases, policy or load_policy(), clock=clock).run(
                config_from_run(run), run_id=run.id, cancel=cancel
            )
        )
        persist_outcome(session, run, outcome, clock)
    except Exception as exc:
        session.rollback()
        run = repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
        run.status = RunStatus.FAILED.value
        run.completed_at = clock.now()
        run.summary_json = {"error": Redactor().redact_text(f"{type(exc).__name__}: {exc}")[:400]}
        session.commit()
        log.exception("run_failed", extra={"run_id": str(run_id)})
        raise GuardBenchError(f"run {run_id} failed; see its summary for the error") from exc
    finally:
        registry.release(run.id)
    return run


def persist_outcome(
    session: Session, run: models.BenchmarkRun, outcome: BenchmarkOutcome, clock: Clock
) -> None:
    """Store events, findings, metrics, and the redacted report for a finished outcome."""
    by_external = {row.external_id: row for row in session.scalars(select(models.TestCase))}

    for event in outcome.events:
        session.add(
            models.Event(
                id=event.id,
                run_id=run.id,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_event_id=event.parent_event_id,
                sequence=event.sequence,
                timestamp=event.timestamp,
                event_type=event.event_type,
                source=event.source,
                server_name=event.server_name,
                tool_name=event.tool_name,
                payload_json=event.payload_json,
                redacted_payload_json=event.redacted_payload_json,
                risk_tags=event.risk_tags,
                decision=event.decision.value if event.decision else None,
            )
        )
    for result in outcome.results:
        test_case = by_external.get(result.test_case_id)
        for finding in result.findings:
            session.add(
                repositories.finding_to_row(
                    finding.model_copy(update={"detected_by": finding.detected_by or result.adapter_name}),
                    run_id=run.id,
                    test_case_id=test_case.id if test_case else None,
                )
            )
    for metric in outcome.metrics:
        session.add(
            models.Metric(
                run_id=run.id,
                metric_name=metric.name,
                metric_value=metric.value,
                unit=metric.unit,
                dimensions_json={
                    **metric.dimensions,
                    "numerator": metric.numerator,
                    "denominator": metric.denominator,
                    "undefined_reason": metric.undefined_reason,
                },
            )
        )

    report = build_report(outcome, generated_at=clock.now())
    run.summary_json = {
        **report_summary(outcome),
        "traces": [
            {"trace_id": t.trace_id, "adapter": t.adapter, "test_case_id": t.test_case_id, "status": t.status}
            for t in outcome.traces
        ],
        "report": report.model_dump(mode="json"),
    }
    run.status = RunStatus.CANCELLED.value if outcome.cancelled else RunStatus.COMPLETED.value
    run.completed_at = outcome.completed_at
    session.commit()


def cancel_run(session: Session, run_id: UUID, registry: RunRegistry) -> models.BenchmarkRun:
    """Cancel a pending run immediately, or signal a running one to stop at the next case boundary."""
    run = repositories.get_or_raise(session, models.BenchmarkRun, run_id, "run")
    if run.status == RunStatus.PENDING.value:
        run.status = RunStatus.CANCELLED.value
        run.completed_at = SystemClock().now()
        session.commit()
    elif run.status == RunStatus.RUNNING.value:
        if not registry.request_cancel(run.id):
            raise ConflictError(f"run {run_id} is marked running but is not executing in this process")
    else:
        raise ConflictError(f"run {run_id} is already {run.status}")
    return run


def report_for_run(run: models.BenchmarkRun) -> dict[str, Any]:
    """The stored, already-redacted report of a finished run."""
    report = run.summary_json.get("report")
    if not isinstance(report, dict):
        raise ConflictError(f"run {run.id} has no report yet (status: {run.status})")
    return report
