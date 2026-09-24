# Contributing

MCP-GuardBench is a defensive security project (see [SECURITY.md](SECURITY.md) for the responsible-use
policy, and read it before contributing anything that touches fixtures, adapters, test cases, or
`guardbench inspect`). Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Where help matters most

1. **New test cases, especially hard ones** ([below](#contributing-a-test-case)). The reference controls
   were written alongside the first seven attack cases, so they score well on them. Cases written by
   people who did not write the controls are what make the numbers mean something.
2. **Reports from `guardbench inspect` on real servers**: false alarms, misses, and servers it cannot
   start. Use the "inspect result" issue template, and remove anything private first.
3. **Adapters for other open-source MCP security tools**, following the Cisco MCP Scanner adapter
   (see [docs/adapter-development.md](docs/adapter-development.md#a-worked-example-wrapping-a-real-third-party-scanner)).
4. **Better rules** in `src/guardbench/analysis/` that catch a hard case without new false alarms on the
   benign controls (`BN-001` to `BN-003`) or on the official reference servers.

## Getting started

```bash
git clone https://github.com/Manishmaurya89/mcp-guardbench
cd mcp-guardbench
make setup      # venv, install, .env with generated credentials, database schema
make test       # 800+ tests on SQLite, ~30s, no network, no Docker
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
`make test-postgres` (starts an embedded PostgreSQL via `pgserver`, no Docker daemon needed): some bugs
(NUL-byte handling, JSONB behavior, column types) only reproduce there.

## Code style

* Ruff is the source of truth for style and a chunk of correctness linting (`E`, `F`, `W`, `I`, `B`,
  `UP`, `S`, `SIM`, `RUF`, `C4`, `PT`, `T20`; see `[tool.ruff.lint]` in `pyproject.toml`, including the
  small set of per-file exceptions and why each exists).
* mypy runs in `strict` mode over `src/`. New code should type-check cleanly; don't add `# type: ignore`
  without a comment explaining what mypy is (correctly) unable to infer.
* Match the surrounding module's docstring density and naming. Public functions and classes get a
  docstring that says *why*, not just *what*: the codebase leans toward explaining intent
  ("alert-only, so it can never prevent anything") over restating the signature.
* Small functions, explicit error handling, dependency injection over globals, no module-level mutable
  state that holds real data (config objects and read-only registries like the fixture allowlist are
  fine).

## The safety rules are enforced, not just documented

Several invariants are checked by `tests/security/`, not by convention. If you're adding a fixture,
adapter, or anything touching input parsing, run this suite and read the tests it contains before you
start, since they define the actual constraints:

* `test_fixture_isolation.py`: fixture source files may only import `typing`, `sqlite3`, and
  `guardbench`; no filesystem, network, subprocess, or wall-clock access; SQLite only ever opens
  `:memory:`; no real network call reaches the process (an autouse fixture blocks sockets and asserts the
  block itself works).
* `test_benchmark_safety.py`: the benchmark never executes real destructive actions; simulated ledger
  entries only.
* `test_api_security.py`, `test_nul_bytes.py`: API input handling (size limits, NUL bytes, path
  confinement, authentication fail-closed behavior).
* `test_inspection_readonly.py`: `guardbench inspect` never calls a tool, reads a resource, or gets a
  prompt; it does not import the hostile lab fixtures; it never uses a shell. Its integration tests also
  check that configured secrets never appear in any output.
* `test_docker_config.py`: the Docker Compose/Dockerfile isolation properties (non-root, capabilities
  dropped, read-only filesystems, no Docker socket, loopback-only ports) are asserted, not just described
  in a comment.

If you add a new kind of "dangerous-looking" behavior, it must land inside the same simulation boundary
(a `FixtureLedger` entry, never a real side effect) and should get its own regression test in this suite.

## Adding a fixture

See [`src/guardbench/mcp_lab/servers/README.md`](src/guardbench/mcp_lab/servers/README.md) for the
requirements every fixture must meet (deterministic, hermetic, in-memory state, a short docstring
explaining what it demonstrates), then register it in
[`src/guardbench/mcp_lab/fixtures.py`](src/guardbench/mcp_lab/fixtures.py)'s static `REGISTRY`.

## Contributing a test case

This is the most valuable contribution you can make. Not sure how to build it? Open a
"Propose a test case" issue with the idea and someone can help turn it into code.

1. **Describe the attack against a synthetic fixture.** Reuse an existing fixture if one fits; otherwise
   add one (see "Adding a fixture" above). Mark hostile text with `GUARDBENCH-SYNTHETIC-INJECTION`, use only
   the synthetic markers, and record every dangerous-looking effect in the fixture's ledger.
2. **Write the YAML** under `test_cases/` (format: [docs/test-case-format.md](docs/test-case-format.md)).
   `guardbench list-test-cases` tells you immediately if it fails to load.
3. **Check it is a real attack:** with `--adapter no-defense-baseline` it must produce an unsafe outcome
   (`test_every_attack_case_is_a_real_attack_against_the_baseline` enforces this). A benign control must
   produce none.
4. **Run every adapter on it and report the result honestly**, even (especially) when a reference control
   fails. Do not change a control in the same pull request to make your case pass; improving the control
   is a separate, reviewable change.
5. **Update the counts** that tests and docs state (fixtures, cases, headline rates), the table in
   `test_cases/README.md`, and regenerate the sample report.

## Adding an adapter

See [docs/adapter-development.md](docs/adapter-development.md). Whatever you build, remember: **detection
is verified against evidenced findings, and prevention is verified against the fixture's own ledger, not
against your adapter's claim.** Don't try to make an adapter self-report a better result than what
actually happened. The normalizer will record the mismatch, and a misleading adapter isn't useful to
anyone comparing controls.

## Commit and PR conventions

* Keep commits focused; a commit message should explain *why*, not just restate the diff.
* Update the relevant doc in `docs/` in the same PR as a behavior change (a metric definition, a policy
  rule, a limitation) rather than leaving docs to drift from code.
* If you change output that a test snapshots or the sample report shows, regenerate it
  (`make demo && make report`) and note that you did.
* New behavior needs new tests. This project does not accept "trust me, I tested it locally" for
  anything touching detection, prevention, redaction, or input validation.

## Reporting a security issue in the project itself

Don't open a public issue for that; see [SECURITY.md](SECURITY.md#reporting-a-vulnerability).
