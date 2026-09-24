# Contributing

MCP-GuardBench is a local defensive security lab (see [SECURITY.md](SECURITY.md) for the responsible-use
policy — read it before contributing anything that touches fixtures, adapters, or test cases).
Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

```bash
git clone <this repository>
cd mcp-guardbench
make setup      # venv, install, .env with generated credentials, database schema
make test       # 700+ tests on SQLite, ~30s, no network, no Docker
```

`make setup` works with either [`uv`](https://docs.astral.sh/uv/) (used automatically if installed) or a
plain `venv`+`pip`. Python 3.12+ is required.

## Before you open a pull request

```bash
make lint        # ruff check + ruff format --check
make typecheck    # mypy --strict over src/
make test         # full suite
```

(`make check` runs all three.) All must pass. If you touched anything database-related, also run
`make test-postgres` (starts an embedded PostgreSQL via `pgserver`, no Docker daemon needed) — some bugs
(NUL-byte handling, JSONB behavior, column types) only reproduce there.

## Code style

* Ruff is the source of truth for style and a chunk of correctness linting (`E`, `F`, `W`, `I`, `B`,
  `UP`, `S`, `SIM`, `RUF`, `C4`, `PT`, `T20` — see `[tool.ruff.lint]` in `pyproject.toml`, including the
  small set of per-file exceptions and why each exists).
* mypy runs in `strict` mode over `src/`. New code should type-check cleanly; don't add `# type: ignore`
  without a comment explaining what mypy is (correctly) unable to infer.
* Match the surrounding module's docstring density and naming. Public functions and classes get a
  docstring that says *why*, not just *what* — the codebase leans toward explaining intent
  ("alert-only, so it can never prevent anything") over restating the signature.
* Small functions, explicit error handling, dependency injection over globals, no module-level mutable
  state that holds real data (config objects and read-only registries like the fixture allowlist are
  fine).

## The safety rules are enforced, not just documented

Several invariants are checked by `tests/security/`, not by convention — if you're adding a fixture,
adapter, or anything touching input parsing, run this suite and read the tests it contains before you
start, since they define the actual constraints:

* `test_fixture_isolation.py` — fixture source files may only import `typing`, `sqlite3`, and
  `guardbench`; no filesystem, network, subprocess, or wall-clock access; SQLite only ever opens
  `:memory:`; no real network call reaches the process (an autouse fixture blocks sockets and asserts the
  block itself works).
* `test_benchmark_safety.py` — the benchmark never executes real destructive actions; simulated ledger
  entries only.
* `test_api_security.py`, `test_nul_bytes.py` — API input handling (size limits, NUL bytes, path
  confinement, authentication fail-closed behavior).
* `test_docker_config.py` — the Docker Compose/Dockerfile isolation properties (non-root, capabilities
  dropped, read-only filesystems, no Docker socket, loopback-only ports) are asserted, not just described
  in a comment.

If you add a new kind of "dangerous-looking" behavior, it must land inside the same simulation boundary
(a `FixtureLedger` entry, never a real side effect) and should get its own regression test in this suite.

## Adding a fixture

See [`src/guardbench/mcp_lab/servers/README.md`](src/guardbench/mcp_lab/servers/README.md) for the
requirements every fixture must meet (deterministic, hermetic, in-memory state, a short docstring
explaining what it demonstrates), then register it in
[`src/guardbench/mcp_lab/fixtures.py`](src/guardbench/mcp_lab/fixtures.py)'s static `REGISTRY`.

## Adding a test case

See [docs/test-case-format.md](docs/test-case-format.md). Test cases are YAML files under `test_cases/`;
`guardbench list-test-cases` will tell you immediately if one fails to load.

## Adding an adapter

See [docs/adapter-development.md](docs/adapter-development.md). Whatever you build, remember: **detection
is verified against evidenced findings, and prevention is verified against the fixture's own ledger, not
against your adapter's claim.** Don't try to make an adapter self-report a better result than what
actually happened — the normalizer will record the mismatch, and a misleading adapter isn't useful to
anyone comparing controls.

## Commit and PR conventions

* Keep commits focused; a commit message should explain *why*, not just restate the diff.
* Update the relevant doc in `docs/` in the same PR as a behavior change — a metric definition, a policy
  rule, a limitation — rather than leaving docs to drift from code.
* If you change output that a test snapshots or the sample report shows, regenerate it
  (`make demo && make report`) and note that you did.
* New behavior needs new tests. This project does not accept "trust me, I tested it locally" for
  anything touching detection, prevention, redaction, or input validation.

## Reporting a security issue in the project itself

Don't open a public issue for that — see [SECURITY.md](SECURITY.md#reporting-a-vulnerability).
