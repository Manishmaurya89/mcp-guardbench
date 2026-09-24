"""Security adapters: the uniform interface every control under test implements.

An adapter *claims* a result (detected / blocked / required approval / findings). The
orchestrator never takes prevention on an adapter's word: it verifies the claim against ground
truth recorded by the scenario runner (see ``result_normalizer``). An adapter that cannot run
here must say so (raise :class:`AdapterUnavailableError`); results are never invented.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Protocol

from guardbench.benchmark.guards import RuntimePolicyGuard, StaticAnalyzerGuard
from guardbench.benchmark.result_normalizer import claim_result
from guardbench.benchmark.runner import GroundTruth, Guard, PassthroughGuard, ScenarioRun, ScenarioRunner
from guardbench.domain.clock import Clock, SystemClock
from guardbench.domain.enums import RunMode, Severity
from guardbench.domain.errors import AdapterUnavailableError
from guardbench.domain.schemas import AdapterResult
from guardbench.domain.testcase import TestCaseSpec
from guardbench.mcp_lab.base import LabFixture
from guardbench.policy.approval import ApprovalService
from guardbench.policy.models import PolicyConfig
from guardbench.runtime.data_flow import DataFlowTracker
from guardbench.runtime.recorder import Recorder
from guardbench.runtime.trace_context import TraceContext

ADAPTER_VERSION = "1.0.0"


@dataclass(slots=True)
class AdapterContext:
    """Everything an adapter needs to run one test case, plus what it leaves behind."""

    fixture: LabFixture
    recorder: Recorder
    tracker: DataFlowTracker
    approvals: ApprovalService
    policy_config: PolicyConfig
    mode: RunMode
    trace: TraceContext
    max_response_bytes: int
    min_detection_severity: Severity = Severity.MEDIUM
    clock: Clock = field(default_factory=SystemClock)
    #: Filled in by the scenario runner. ``None`` if the adapter never ran the scenario through it.
    truth: GroundTruth | None = None
    run: ScenarioRun | None = None
    guard: Guard | None = None


class SecurityAdapter(Protocol):
    """The adapter interface. ``name`` is the identifier used on the CLI and in reports."""

    name: str
    version: str

    async def prepare(self, context: AdapterContext) -> None:
        """Set up per-test-case state."""
        ...

    async def execute(self, test_case: TestCaseSpec, context: AdapterContext) -> AdapterResult:
        """Run the test case and return the adapter's claimed result."""
        ...

    async def cleanup(self, context: AdapterContext) -> None:
        """Release per-test-case state."""
        ...


class GuardAdapter(ABC):
    """Base for adapters implemented as a guard driven by the scenario runner."""

    name: str
    version: str = ADAPTER_VERSION
    limitations: tuple[str, ...] = ()

    @abstractmethod
    def make_guard(self) -> Guard:
        """A fresh guard for one test case (guards hold per-case state)."""

    async def prepare(self, context: AdapterContext) -> None:
        """Create the guard for this test case."""
        context.guard = self.make_guard()

    async def execute(self, test_case: TestCaseSpec, context: AdapterContext) -> AdapterResult:
        """Play the scenario under this adapter's guard and return its claimed result."""
        assert context.guard is not None, "prepare() must run before execute()"
        started = context.clock.now()
        run = ScenarioRun(
            fixture=context.fixture,
            recorder=context.recorder,
            tracker=context.tracker,
            approvals=context.approvals,
            policy_config=context.policy_config,
            mode=context.mode,
            trace=context.trace,
            max_response_bytes=context.max_response_bytes,
        )
        context.run = run
        context.truth = await ScenarioRunner(run, context.guard).execute(test_case)
        return claim_result(
            adapter_name=self.name,
            adapter_version=self.version,
            spec=test_case,
            run=run,
            started_at=started,
            completed_at=context.clock.now(),
            limitations=list(self.limitations),
        )

    async def cleanup(self, context: AdapterContext) -> None:
        """Drop the guard."""
        context.guard = None


class NoDefenseBaselineAdapter(GuardAdapter):
    """Provides no protection and only records what happened. The reference point for every metric."""

    name = "no-defense-baseline"
    limitations = ("Provides no detection or prevention by design; it only records what happened.",)

    def make_guard(self) -> Guard:
        """A guard that exposes, allows, and passes through everything."""
        return PassthroughGuard()


class ReferenceStaticAnalyzerAdapter(GuardAdapter):
    """Metadata and drift analysis. Alerts, but sits outside the call path, so it cannot prevent."""

    name = "reference-static"
    limitations = (
        "Static analysis inspects tool metadata and definition drift only; it cannot see tool "
        "responses, arguments, or runtime data flow.",
        "Alert-only: it is not in the call path, so an alert never stops an unsafe action.",
        "Rule-based and transparent, so it can miss semantic attacks phrased outside its patterns.",
    )

    def make_guard(self) -> Guard:
        """An alert-only static guard."""
        return StaticAnalyzerGuard()


class ReferenceRuntimePolicyAdapter(GuardAdapter):
    """In-path enforcement: tool registration checks, a deterministic call policy, response inspection."""

    name = "reference-runtime"
    limitations = (
        "Only effective when the client is instrumented to route every call through it.",
        "Response and metadata inspection use the same transparent pattern rules; they can be bypassed "
        "by wording they do not cover.",
        "Synthetic data-flow tracking follows exact and lightly normalized marker strings, "
        "not transformed data.",
        "Unattended mode never grants approvals, so anything needing approval is held, not executed.",
    )

    def make_guard(self) -> Guard:
        """An in-path runtime policy guard."""
        return RuntimePolicyGuard()


class ExternalScannerAdapter(ABC):
    """Documented extension point for third-party scanners (see ``docs/adapter-development.md``).

    Subclass it, implement :meth:`check_available` and :meth:`execute`, and register the class in
    ``ADAPTER_FACTORIES``. If the tool
    is not installed or configured, raise :class:`AdapterUnavailableError`: the test case is then
    reported as *skipped* with your reason. Never return a made-up result.
    """

    name: str
    version: str = "0"

    async def prepare(self, context: AdapterContext) -> None:
        """Verify the external tool is available; raise :class:`AdapterUnavailableError` if not."""
        self.check_available()

    @abstractmethod
    def check_available(self) -> None:
        """Raise :class:`AdapterUnavailableError` with a clear reason if the tool cannot run."""

    @abstractmethod
    async def execute(self, test_case: TestCaseSpec, context: AdapterContext) -> AdapterResult:
        """Run the external tool against the fixture and translate its output into an ``AdapterResult``."""

    async def cleanup(self, context: AdapterContext) -> None:  # noqa: B027 - optional hook, no-op by default
        """Release any external resources."""


class UnavailableExternalAdapter(ExternalScannerAdapter):
    """Stands in for an external scanner that is not installed. It always reports itself unavailable."""

    name = "external-scanner"

    def check_available(self) -> None:
        """Always unavailable: no external scanner is integrated in this version."""
        raise AdapterUnavailableError(
            "no external scanner is integrated; implement ExternalScannerAdapter and validate its "
            "results separately (see docs/adapter-development.md)"
        )

    async def execute(self, test_case: TestCaseSpec, context: AdapterContext) -> AdapterResult:
        """Never reached: ``prepare`` raises first."""
        self.check_available()
        raise AssertionError("unreachable")  # pragma: no cover


AdapterFactory = type[GuardAdapter] | type[ExternalScannerAdapter]

#: Adapters selectable by name. Extend this mapping to add an adapter.
ADAPTER_FACTORIES: dict[str, AdapterFactory] = {
    NoDefenseBaselineAdapter.name: NoDefenseBaselineAdapter,
    ReferenceStaticAnalyzerAdapter.name: ReferenceStaticAnalyzerAdapter,
    ReferenceRuntimePolicyAdapter.name: ReferenceRuntimePolicyAdapter,
    UnavailableExternalAdapter.name: UnavailableExternalAdapter,
}


def adapter_names() -> list[str]:
    """Names of all selectable adapters."""
    return list(ADAPTER_FACTORIES)


def create_adapter(name: str) -> SecurityAdapter:
    """Instantiate an adapter by name. Unknown names raise ``AdapterUnavailableError`` with the choices."""
    factory = ADAPTER_FACTORIES.get(name)
    if factory is None:
        raise AdapterUnavailableError(f"unknown adapter {name!r}; available: {', '.join(adapter_names())}")
    return factory()
