# Adapter development

An adapter is how a security control — a static scanner, a runtime monitor, a gateway, a client
configuration — is evaluated against the local fixtures under identical conditions. This page covers
both ways to add one: as a **guard** driven by the built-in scenario runner (what the three reference
adapters do), or as a **fully external process/tool** wrapped in your own `execute()`.

## The common result shape

Every adapter is reduced to one `AdapterResult`
([`src/guardbench/domain/schemas.py`](../src/guardbench/domain/schemas.py)), regardless of how it works
internally: `adapter_name`, `adapter_version`, `test_case_id`, `started_at`/`completed_at`, `status`,
`detected`, `blocked`, `required_approval`, `false_positive`, `false_negative`, `findings`,
`evidence_event_ids`, `latency_ms`, `error`, `limitations`, `tool_calls`, `policy_denials`,
`approvals_required`, `unsafe_outcomes`, `evidence_kinds_present`, `expectation_met`, `claim_mismatches`.

**Vendor-specific scores are never compared.** Whatever a tool reports internally, your adapter's job is
to translate it into this shape — and even then, `detected` and `blocked` on the object your `execute()`
returns are treated as a *claim*. The orchestrator verifies that claim before scoring
([`result_normalizer.py`](../src/guardbench/benchmark/result_normalizer.py)):

* `detected` is recomputed from `findings` that carry real evidence and match the test case's expected
  category, at or above the configured minimum severity. Claiming detection with no qualifying findings
  is recorded in `claim_mismatches`, not trusted.
* `blocked` (prevention) is read from the fixture's own ledger of what actually executed — **never**
  from your adapter's claim. If your adapter didn't run the scenario through the GuardBench runner (so
  no ground truth exists), the case is reported as **not blocked**, with a limitation noting that
  prevention could not be verified.
* `required_approval` is read from whether an `ApprovalRequest` was actually created.

## The interface

```python
class SecurityAdapter(Protocol):
    name: str
    version: str

    async def prepare(self, context: AdapterContext) -> None: ...
    async def execute(self, test_case: TestCaseSpec, context: AdapterContext) -> AdapterResult: ...
    async def cleanup(self, context: AdapterContext) -> None: ...
```

(`src/guardbench/benchmark/adapters.py`). `AdapterContext` carries everything a case needs: the live
`fixture`, the `recorder` and `tracker`, the `approvals` service, the `policy_config`, the run `mode`
(`unattended` never approves anything), the response-size limit, and — for guard-based adapters — the
`Guard` for this case.

## Path A: a guard driven by the scenario runner (recommended for anything that inspects the same
MCP traffic the reference controls see)

Implement the `Guard` protocol (`src/guardbench/benchmark/runner.py`):

```python
class Guard(Protocol):
    name: str

    def on_tools_listed(
        self,
        run: ScenarioRun,
        tools: list[ToolDefinitionData],
        identity: ServerIdentity,
        *,
        pin_baseline: bool,
    ) -> frozenset[str]:
        """Return the names of tools to withhold from the model."""

    def before_call(self, run: ScenarioRun, tool_name: str, arguments: dict[str, Any]) -> CallVerdict:
        """Decide whether a call may run."""

    def inspect_response(
        self, run: ScenarioRun, tool_name: str, result: ToolCallResult
    ) -> ResponseInspection:
        """Inspect a tool response before it reaches the model."""
```

Then subclass `GuardAdapter` (`ABC`, in `adapters.py`) and implement one method:

```python
from guardbench.benchmark.adapters import GuardAdapter
from guardbench.benchmark.runner import Guard


class MyGuard:
    name = "my-control"

    def on_tools_listed(self, run, tools, identity, *, pin_baseline):
        return frozenset()  # withhold nothing, or return names to hide

    def before_call(self, run, tool_name, arguments):
        return CallVerdict()  # .allowed defaults to True; see CallVerdict for denial/approval fields

    def inspect_response(self, run, tool_name, result):
        return ResponseInspection()  # text_for_model=None passes the response through unchanged


class MyAdapter(GuardAdapter):
    name = "my-control"
    limitations = ("State any real limitation here; it is shown in every report.",)

    def make_guard(self) -> Guard:
        return MyGuard()
```

`GuardAdapter.execute()` already does the rest: it runs the scenario through `ScenarioRunner`, times it,
and calls `claim_result()` to build the `AdapterResult`. Study
[`guards.py`](../src/guardbench/benchmark/guards.py) — `StaticAnalyzerGuard` (alert-only,
`before_call` always allows) and `RuntimePolicyGuard` (in-path enforcement using
[`policy/engine.py`](../src/guardbench/policy/engine.py)) — before writing your own; most new static or
runtime controls fit this pattern.

## Path B: an external scanner or gateway

If the control is a separate binary, service, or SaaS API, subclass `ExternalScannerAdapter`:

```python
class ExternalScannerAdapter(ABC):
    name: str
    version: str = "0"

    async def prepare(self, context: AdapterContext) -> None:
        self.check_available()  # already implemented; calls your check_available()

    @abstractmethod
    def check_available(self) -> None:
        """Raise AdapterUnavailableError with a clear reason if the tool cannot run."""

    @abstractmethod
    async def execute(self, test_case: TestCaseSpec, context: AdapterContext) -> AdapterResult:
        """Run the external tool and translate its output into an AdapterResult."""
```

* **If the tool is not installed or configured, raise `AdapterUnavailableError`.** The orchestrator
  reports the case as **skipped** — not scored, not a silent zero. This project ships one such adapter
  (`UnavailableExternalAdapter`, registered as `external-scanner`) as a documented placeholder: it always
  raises, because no external scanner is integrated by default. Follow that pattern; never invent a
  result to avoid a skip.
* If you do run the scenario through `ScenarioRunner` yourself inside `execute()` (so ground truth
  exists), `blocked` will be verified normally. If your tool works entirely outside the runner — for
  example, it scans a server independently and reports a verdict after the fact — `blocked` will always
  come back `False` with a limitation explaining why; that is expected and correct, not a bug to work
  around. Detection can still be scored normally as long as you build real `Finding` objects.
* Any credentials, URLs, or configuration your adapter needs must come from environment variables (see
  `.env.example`), never be hard-coded, and must never be logged. `check_available()` is the right place
  to fail closed if a required setting is missing.

## Registering an adapter

Add it to `ADAPTER_FACTORIES` in `src/guardbench/benchmark/adapters.py`:

```python
ADAPTER_FACTORIES: dict[str, AdapterFactory] = {
    NoDefenseBaselineAdapter.name: NoDefenseBaselineAdapter,
    ReferenceStaticAnalyzerAdapter.name: ReferenceStaticAnalyzerAdapter,
    ReferenceRuntimePolicyAdapter.name: ReferenceRuntimePolicyAdapter,
    UnavailableExternalAdapter.name: UnavailableExternalAdapter,
    MyAdapter.name: MyAdapter,
}
```

It is now selectable everywhere adapters are named: `guardbench list-adapters`, `guardbench benchmark
run --adapter my-control`, and `POST /runs`.

## Building findings

A `Finding` needs, at minimum, a `category`, `severity`, `rule_id`, `title`, `detected_by`, and evidence
(`evidence_json`, `evidence_event_ids`). Findings that don't match the test case's expected category, or
that fall below the run's minimum severity, don't count toward `detected` — build findings that are
honest about what your control actually found, not tuned to match the test corpus.

## Validating a new adapter

1. `guardbench list-adapters` — confirm it's registered.
2. `guardbench benchmark run --no-persist --adapter my-control --case-id BN-001 --case-id BN-002` — it
   must produce `false_positive_rate: 0%` on the benign controls before anything else is meaningful.
3. `guardbench benchmark run --no-persist --adapter my-control --adapter no-defense-baseline` over the
   full corpus — compare against the baseline (which must always show 0% detection/prevention) and
   against `reference-static`/`reference-runtime` to sanity-check the numbers.
4. Read the resulting report's **Limitations** section for your adapter — it prints exactly the
   `limitations` tuple you set. Make sure it is honest and specific.
5. Write tests for your guard/adapter the way `tests/unit/test_policy_engine.py` and
   `tests/integration/test_benchmark.py` test the reference ones: unit tests for the decision logic, an
   integration test that runs it through the real orchestrator against the fixtures.

An adapter you write is, itself, unverified until it's been run against this corpus and reviewed — see
[limitations.md](limitations.md), item 9.
