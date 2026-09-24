"""The benchmark orchestrator.

Runs every (adapter x test case) pair under identical conditions: a fresh fixture, a fresh
approval service, its own trace, and the same policy. Each adapter's claimed result is then
verified against ground truth (``result_normalizer``), and metrics are computed.

Failures are never swallowed: an adapter that cannot run is recorded as *skipped* with its reason;
one that crashes is recorded as an *error* (with a logged traceback and an ERROR event), and the
rest of the run continues.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID, uuid4

from guardbench.benchmark.adapters import AdapterContext, SecurityAdapter, create_adapter
from guardbench.benchmark.metrics import compute_metrics
from guardbench.benchmark.result_normalizer import finalize_result
from guardbench.benchmark.test_case_loader import LoadedTestCase, corpus_hash
from guardbench.domain.clock import Clock, SystemClock
from guardbench.domain.enums import EventType, ResultStatus, RunMode, Severity
from guardbench.domain.errors import AdapterUnavailableError, ValidationFailure
from guardbench.domain.schemas import AdapterResult, Event, MetricValue
from guardbench.domain.testcase import TestCaseSpec
from guardbench.logging_config import get_logger
from guardbench.mcp_lab.fixtures import create_fixture
from guardbench.policy.approval import ApprovalService
from guardbench.policy.models import PolicyConfig
from guardbench.runtime.data_flow import DataFlowTracker
from guardbench.runtime.recorder import Recorder
from guardbench.runtime.redaction import Redactor
from guardbench.runtime.trace_context import DeterministicIdSource

log = get_logger("orchestrator")

ORCHESTRATOR_SOURCE = "orchestrator"
MAX_ERROR_CHARS = 300
AdapterFactory = Callable[[str], SecurityAdapter]
ProgressCallback = Callable[[str, str, str], None]


class CancelSignal(Protocol):
    """Anything with ``is_set()``. A ``threading.Event`` works across threads; so does ``asyncio.Event``."""

    def is_set(self) -> bool:
        """Whether cancellation has been requested."""
        ...


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    """Everything that defines a run, recorded in the report for reproducibility."""

    adapters: tuple[str, ...]
    test_case_ids: tuple[str, ...] | None = None
    seed: int = 0
    mode: RunMode = RunMode.UNATTENDED
    min_detection_severity: Severity = Severity.MEDIUM

    def to_json(self) -> dict[str, Any]:
        """JSON-safe view."""
        return {
            "adapters": list(self.adapters),
            "test_case_ids": list(self.test_case_ids) if self.test_case_ids else None,
            "seed": self.seed,
            "mode": self.mode.value,
            "min_detection_severity": self.min_detection_severity.value,
        }


@dataclass(frozen=True, slots=True)
class TraceInfo:
    """Which trace belongs to which (adapter, test case)."""

    trace_id: str
    adapter: str
    test_case_id: str
    status: str


@dataclass(slots=True)
class BenchmarkOutcome:
    """Everything a run produced, ready to persist or report."""

    run_id: UUID
    config: BenchmarkConfig
    started_at: Any
    completed_at: Any
    cases: dict[str, TestCaseSpec]
    results: list[AdapterResult]
    events: list[Event]
    traces: list[TraceInfo]
    metrics: list[MetricValue]
    policy_id: str
    policy_hash: str
    corpus_hash: str
    max_response_bytes: int
    cancelled: bool = False
    notes: list[str] = field(default_factory=list)


class Orchestrator:
    """Coordinates a benchmark run. Holds no global state; every run is independent."""

    def __init__(
        self,
        cases: Sequence[LoadedTestCase],
        policy: PolicyConfig,
        *,
        clock: Clock | None = None,
        adapter_factory: AdapterFactory = create_adapter,
    ) -> None:
        self._cases = list(cases)
        self._policy = policy
        self._clock = clock or SystemClock()
        self._adapter_factory = adapter_factory
        self._redactor = Redactor()

    def select(self, ids: Sequence[str] | None) -> list[LoadedTestCase]:
        """Cases to run (all if ``ids`` is ``None``). Unknown ids are an error, never ignored."""
        if ids is None:
            return list(self._cases)
        known = {c.spec.id for c in self._cases}
        unknown = sorted(set(ids) - known)
        if unknown:
            raise ValidationFailure(f"unknown test case ids: {unknown}; known: {sorted(known)}")
        return [c for c in self._cases if c.spec.id in set(ids)]

    async def run(
        self,
        config: BenchmarkConfig,
        *,
        run_id: UUID | None = None,
        cancel: CancelSignal | None = None,
        progress: ProgressCallback | None = None,
    ) -> BenchmarkOutcome:
        """Execute the benchmark and return the verified outcome."""
        run_id = run_id or uuid4()
        selected = self.select(config.test_case_ids)
        recorder = Recorder(
            run_id=run_id, clock=self._clock, ids=DeterministicIdSource(f"guardbench:{config.seed}")
        )
        tracker = DataFlowTracker(clock=self._clock)
        recorder.bus.subscribe(
            lambda e: tracker.observe_event_payload(e.trace_id, e.id, e.event_type, e.payload_json)
        )
        started = self._clock.now()
        run_trace = recorder.new_trace()
        recorder.record(
            run_trace,
            EventType.RUN_STARTED,
            ORCHESTRATOR_SOURCE,
            payload={"config": config.to_json(), "cases": [c.spec.id for c in selected]},
        )

        results: list[AdapterResult] = []
        traces: list[TraceInfo] = []
        cancelled = False
        for adapter_name in config.adapters:
            for case in selected:
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    results.append(self._skipped(adapter_name, case.spec, "run was cancelled"))
                    continue
                if not case.spec.enabled:
                    results.append(self._skipped(adapter_name, case.spec, "test case is disabled"))
                    continue
                result, trace_info = await self._run_one(adapter_name, case.spec, config, recorder, tracker)
                results.append(result)
                traces.append(trace_info)
                if progress:
                    progress(adapter_name, case.spec.id, result.status.value)

        cases = {c.spec.id: c.spec for c in selected}
        metrics = compute_metrics(results, cases, config.adapters)
        completed = self._clock.now()
        recorder.record(
            run_trace,
            EventType.RUN_COMPLETED,
            ORCHESTRATOR_SOURCE,
            payload={"results": len(results), "cancelled": cancelled},
        )
        return BenchmarkOutcome(
            run_id=run_id,
            config=config,
            started_at=started,
            completed_at=completed,
            cases=cases,
            results=results,
            events=list(recorder.events),
            traces=traces,
            metrics=metrics,
            policy_id=self._policy.policy_id,
            policy_hash=self._policy.canonical_hash(),
            corpus_hash=corpus_hash(self._cases),
            max_response_bytes=self._policy.responses.max_bytes,
            cancelled=cancelled,
        )

    async def _run_one(
        self,
        adapter_name: str,
        spec: TestCaseSpec,
        config: BenchmarkConfig,
        recorder: Recorder,
        tracker: DataFlowTracker,
    ) -> tuple[AdapterResult, TraceInfo]:
        trace = recorder.new_trace()
        context = AdapterContext(
            fixture=create_fixture(spec.server_fixture),
            recorder=recorder,
            tracker=tracker,
            approvals=ApprovalService(clock=self._clock),
            policy_config=self._policy,
            mode=config.mode,
            trace=trace,
            max_response_bytes=self._policy.responses.max_bytes,
            min_detection_severity=config.min_detection_severity,
            clock=self._clock,
        )
        started = self._clock.now()
        adapter: SecurityAdapter | None = None
        try:
            adapter = self._adapter_factory(adapter_name)
            t0 = time.perf_counter()
            await adapter.prepare(context)
            claimed = await adapter.execute(spec, context)
            latency_ms = (time.perf_counter() - t0) * 1000
            result = finalize_result(
                spec,
                claimed,
                context.truth,
                recorder.events_for_trace(trace.trace_id),
                min_severity=config.min_detection_severity,
                approvals_requested=len(context.approvals.all()),
            ).model_copy(update={"latency_ms": round(latency_ms, 3)})
        except AdapterUnavailableError as exc:
            reason = self._safe(str(exc))
            recorder.record(
                trace, EventType.ERROR, ORCHESTRATOR_SOURCE, payload={"skipped": True, "reason": reason}
            )
            result = self._skipped(adapter_name, spec, reason, started=started)
        except Exception as exc:
            log.exception("adapter_failed", extra={"adapter": adapter_name, "test_case": spec.id})
            message = self._safe(f"{type(exc).__name__}: {exc}")
            recorder.record(trace, EventType.ERROR, ORCHESTRATOR_SOURCE, payload={"error": message})
            result = self._errored(adapter_name, spec, message, started)
        finally:
            if adapter is not None:
                await self._cleanup(adapter, context)
        return result, TraceInfo(trace.trace_id, adapter_name, spec.id, result.status.value)

    async def _cleanup(self, adapter: SecurityAdapter, context: AdapterContext) -> None:
        try:
            await adapter.cleanup(context)
        except Exception:
            log.exception("adapter_cleanup_failed", extra={"adapter": adapter.name})

    def _safe(self, text: str) -> str:
        return self._redactor.redact_text(text)[:MAX_ERROR_CHARS]

    def _skipped(
        self, adapter: str, spec: TestCaseSpec, reason: str, *, started: Any = None
    ) -> AdapterResult:
        now = self._clock.now()
        return AdapterResult(
            adapter_name=adapter,
            adapter_version="n/a",
            test_case_id=spec.id,
            started_at=started or now,
            completed_at=now,
            status=ResultStatus.SKIPPED,
            error=reason,
            limitations=["No result was produced; nothing has been inferred or estimated."],
        )

    def _errored(self, adapter: str, spec: TestCaseSpec, message: str, started: Any) -> AdapterResult:
        return AdapterResult(
            adapter_name=adapter,
            adapter_version="n/a",
            test_case_id=spec.id,
            started_at=started,
            completed_at=self._clock.now(),
            status=ResultStatus.ERROR,
            error=message,
            limitations=["The adapter failed; this case is excluded from all metrics."],
        )
