# Architecture

## Layers

Each layer only depends on the ones below it. The domain layer has no framework dependency at all.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  CLI (Typer)              API (FastAPI)              Dashboard (Streamlit)│
│  src/guardbench/cli       src/guardbench/api          src/guardbench/     │
│                                                        dashboard          │
│  Talk to the database     Thin routes; validate       GET-only HTTP      │
│  and services directly.   input/output; dependency-   client against the │
│                            injected sessions.           API. No DB access.│
└──────────────┬───────────────────┬───────────────────────────────────────┘
               │                   │
        ┌──────▼───────────────────▼──────┐
        │  services/  (scan, runs, test_   │  Orchestration glue: turns HTTP/CLI
        │  cases, demo, trace)             │  requests into calls on the layers below.
        └──────┬───────────────────────────┘
               │
   ┌───────────▼────────────┬──────────────────┬───────────────────┐
   │ benchmark/              │ analysis/         │ policy/            │
   │ orchestrator, adapters, │ metadata_analyzer,│ engine, models,    │
   │ runner, metrics, report │ fingerprinting,   │ approval           │
   │                          │ drift_detector    │                    │
   │ Executes test cases      │ Pure functions;   │ Deterministic call │
   │ against fixtures through │ no hidden network │ and response       │
   │ adapters; normalizes     │ calls; easy to    │ policy; approval   │
   │ results; computes        │ unit test.        │ workflow with no  │
   │ metrics.                 │                   │ auto-bypass.       │
   └───────────┬──────────────┴───────┬───────────┴────────┬──────────┘
               │                      │                     │
        ┌──────▼──────┐        ┌──────▼───────┐     ┌───────▼────────┐
        │ mcp_lab/     │        │ runtime/      │     │ db/             │
        │ 8 fixture    │        │ recorder,     │     │ SQLAlchemy 2.x  │
        │ servers,     │        │ redaction,    │     │ models, Alembic │
        │ client_runner│        │ data_flow,    │     │ migrations,     │
        │ (real MCP    │        │ event_bus     │     │ Postgres+SQLite │
        │ traffic)     │        │               │     │                 │
        └──────────────┘        │ Receives      │     └─────────────────┘
                                 │ structured    │
                                 │ events, redacts│
                                 │ before storing.│
                                 └───────────────┘
               │                      │                     │
               └──────────────────────┴─────────────────────┘
                                       │
                         ┌─────────────▼─────────────┐
                         │  domain/                   │
                         │  enums, schemas (Pydantic  │
                         │  v2), errors, testcase,    │
                         │  markers, clock            │
                         │                             │
                         │  No FastAPI or database     │
                         │  import. Everything above   │
                         │  builds on these types.      │
                         └─────────────────────────────┘
```

`mcp_lab/` (the test lab) is the one package that is deliberately, structurally separate from the rest:
it contains the only code that behaves like an attacker, it is import-restricted (see below), and
nothing outside `benchmark/` and the CLI's inspection commands depends on it.

## Domain entities

Every entity below exists as both a Pydantic v2 schema (`domain/schemas.py`) and a SQLAlchemy 2.x model
(`db/models.py`), with a matching Alembic migration. UUID primary keys throughout, all timestamps stored
as timezone-aware UTC (`UTCDateTime`), JSON columns use PostgreSQL `JSONB` with a compatible SQLite
fallback (`JSONType`), and indexes exist on `run_id`, `trace_id`, `server_id`, `event_type`, `severity`,
and `created_at` (see the naming convention and indexes in `db/base.py` / `db/models.py` and the initial
migration).

* **Project** — id, name, description, created_at. The top-level grouping for servers and runs.
* **MCPServer** — id, project_id, name, transport, endpoint, source_type, version, trust_status,
  created_at, plus `lab_phase` (drives the deterministic rug-pull demo).
* **ToolDefinition** — id, server_id, name, description, input_schema, output_schema, annotations,
  definition_hash, observed_at.
* **ToolSnapshot** — id, server_id, snapshot_hash, normalized_tools_json, created_at. What fingerprinting
  and drift detection compare.
* **TestCase** — id, external_id (the human-readable `TP-001` style id), name, category, severity,
  description, yaml_path, expected_behaviors, enabled. Mirrors `TestCaseSpec` in the database for
  auditability; the YAML file under `test_cases/` remains the source of truth.
* **BenchmarkRun** — id, project_id, status, started_at, completed_at, configuration_json, summary_json.
* **Event** — id, run_id, trace_id, parent_event_id, timestamp, event_type, source, server_name,
  tool_name, payload_json, redacted_payload_json, risk_tags, decision. The append-only evidence log.
* **Finding** — id, run_id, test_case_id, title, category, severity, confidence, status, description,
  evidence_json, remediation, created_at.
* **Metric** — id, run_id, metric_name, metric_value, unit, dimensions_json.

## Why the layering matters for security

* **Domain has no framework dependency.** Validation (test-case safety rules, marker allowlists,
  credential-shape rejection) lives here and runs identically whether it's called from the CLI, the API,
  or a test — there's exactly one place a rule can be bypassed, and it's covered by unit tests.
* **Analysis is pure.** The static analyzer, fingerprinting, and drift detection take data in and return
  data out — no I/O, no network, no state. That's what makes them deterministic (a re-run with the same
  input always produces the same findings) and safe to fuzz/test exhaustively.
* **Runtime is the only place redaction happens**, and it happens on the way *in* (before a payload is
  ever stored as `redacted_payload_json`), not as a filter applied on the way out. The API additionally
  redacts structurally at the response boundary (`RedactingRoute`) as defence in depth, and fails closed
  (500) if it cannot determine a response is safe to redact.
* **`mcp_lab/` is quarantined.** Fixture source files may only import `typing`, `sqlite3`, and
  `guardbench` itself (checked by AST in `tests/security/test_fixture_isolation.py`); no fixture opens a
  socket, spawns a process, touches a real file, or reads the real clock. A fixture is instantiated only
  through the static `REGISTRY` — a name is looked up as a dict key, never turned into an import path or
  a shell command.
* **The API is thin.** Routes validate input/output with Pydantic, get a database session through
  FastAPI's dependency injection, and delegate everything else to `services/`. Business logic that needs
  testing without an HTTP layer lives in `services/`, not in a route function.
* **The dashboard is read-only by construction.** `ApiClient` (`dashboard/api_client.py`) exposes only a
  `get()`/`get_or_none()`/`all_pages()` surface over HTTP; it has no `post`/`put`/`delete` methods and
  holds no database credentials, so a bug in the dashboard cannot mutate benchmark data.

## Data flow of one test case

1. The CLI or API loads a `TestCaseSpec` from YAML (`benchmark/test_case_loader.py`) and resolves its
   fixture through the allowlist (`mcp_lab/fixtures.py`).
2. The `Orchestrator` builds an `AdapterContext` and, for each selected adapter, calls
   `prepare()` → `execute()` → `cleanup()`.
3. A guard-based adapter's `execute()` runs the case through `ScenarioRunner`
   (`benchmark/runner.py`), which drives the fixture over a real in-process MCP connection
   (`mcp_lab/client_runner.py`) and calls the guard's three hooks at each step.
4. Every step is recorded as an `Event` through the `Recorder` (`runtime/recorder.py`), which redacts
   the payload before it is ever persisted.
5. `result_normalizer.py` verifies the adapter's claim against the fixture's `FixtureLedger` (ground
   truth) and against the recorded findings, producing a verified `AdapterResult`.
6. `metrics.py` aggregates `AdapterResult`s across the run into `MetricValue`s, explicit about undefined
   denominators.
7. `report.py` renders the run (configuration, per-case results, metrics, findings, reproducibility
   metadata) as Markdown/JSON/CSV/HTML.

## Why sync SQLAlchemy under an async API

FastAPI routes and the benchmark orchestrator are async, but the database layer uses SQLAlchemy 2.x in
synchronous mode, run through a small `run_sync` helper (`asyncio_utils.py`) that offloads blocking calls
to a thread. This keeps the ORM layer (session lifecycle, migrations, `pgserver`-based test fixtures)
simple and avoids maintaining two SQLAlchemy dialects; at this benchmark's scale (a handful of fixtures,
tens of test cases per run) the thread-pool overhead is not a bottleneck. A future version could move to
`AsyncSession` if the workload grows.
