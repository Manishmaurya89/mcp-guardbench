# Security policy

## Responsible-use policy (read this first)

MCP-GuardBench is a **local, defensive security research lab**. It exists to evaluate detection and
prevention controls against safe, intentionally vulnerable servers that ship *inside this repository*.
It is not a penetration-testing tool, an exploit framework, or a scanner for other people's systems.

By using this repository you agree to:

1. **Run it only against the local fixtures created by this repository.** Never point any part of this
   project — the fixtures, the adapters, the scenario runner — at a public, third-party, or production
   MCP server. There is no configuration flag for that; targets are resolved only through the static
   fixture allowlist in [`src/guardbench/mcp_lab/fixtures.py`](src/guardbench/mcp_lab/fixtures.py).
2. **Never use real credentials, secrets, production APIs, private files, or real personal data**, in
   test cases, fixtures, configuration, or committed code. Use only the harmless, clearly synthetic
   markers this project defines: `TEST_SECRET_123`, `TEST_PRIVATE_RECORD`, `SIMULATED_EXTERNAL_DESTINATION`.
   See [`src/guardbench/domain/markers.py`](src/guardbench/domain/markers.py).
3. **Not implement or extend this project with malware, persistence mechanisms, real exfiltration,
   credential theft, or destructive actions.** Every "dangerous-looking" behavior in the fixtures
   (write/delete/send/execute) is a simulation recorded to an in-memory ledger — it has no real-world
   effect. Keep it that way in anything you add.
4. **Not use it to attack, scan, or probe systems you do not own or do not have explicit authorization to
   test.** This applies to every MCP server, API, or network endpoint outside this repository's own local
   fixtures, without exception.
5. **Treat every benchmark result as evidence about controls under lab conditions**, not as a safety
   certification for any real server or client. See [docs/limitations.md](docs/limitations.md).

If you are extending this project (a new fixture, a new adapter, a new test case) and are unsure whether
something crosses these lines, prefer the safer option — a clearly labelled simulation over anything that
could have a real effect — and say so explicitly in the code and its docstring, per
[CONTRIBUTING.md](CONTRIBUTING.md).

## Supported versions

This is a research/lab project at `0.1.0` (pre-1.0). There is one supported line: the latest commit on
the default branch. There are no numbered security-patch releases at this stage.

## Reporting a vulnerability

If you find a security issue in MCP-GuardBench itself — for example, a way the lab's own safety
boundaries could be bypassed (a fixture reaching the real network or filesystem, a credential leaking
through the API or logs, an authentication bypass, a path-traversal in the file-confinement helpers) —
please report it privately rather than opening a public issue:

* Open a **GitHub Security Advisory** on this repository (Security tab → "Report a vulnerability"), if
  the repository is hosted on GitHub, so the report stays private until a fix is available.
* If that is not available, open an issue that states only "possible security issue, details sent
  privately" and include contact information for a maintainer to reach you, without publishing exploit
  details in the issue itself.

Please include:

* what boundary you believe is broken (network isolation, credential handling, path confinement,
  authentication, etc.) and why;
* steps to reproduce, ideally as a failing test against the fixtures in this repository — the security
  test suite in `tests/security/` is exactly the place such a regression test belongs;
* the potential impact, scoped to this project (this is a local lab; "impact" here usually means "the
  safety boundary this project promises does not hold", not impact on a production system).

We aim to acknowledge reports within a few days and will credit reporters in the fix's changelog unless
they ask not to be.

## What is explicitly out of scope

* Vulnerabilities in third-party dependencies (report those upstream; `pyproject.toml` pins minimum
  versions and dependency updates are welcome as ordinary pull requests).
* "The static analyzer/runtime policy missed an attack" — that is expected and tracked as a limitation
  (see [docs/limitations.md](docs/limitations.md)), not a vulnerability in the project. If you have a test
  case that demonstrates a *safety-boundary* violation (the sandbox itself is escaped, not "the reference
  detector has a false negative"), that is in scope.
* Findings against MCP servers, clients, or products that are not part of this repository. This project
  does not scan third-party software and cannot receive vulnerability reports about it.
