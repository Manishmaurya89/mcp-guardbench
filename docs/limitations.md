# Limitations

MCP-GuardBench is a **local evaluation laboratory**. Read this page before you quote any number it
produces. Every limitation below is also repeated, where it applies, in the generated reports.

## The nine statements this project stands behind

### 1. This project does not prove an MCP server is safe

A benchmark can only show that a control did or did not handle the cases in its corpus. It cannot
show the absence of vulnerabilities in any real server, client, or deployment. No score in this
repository is a safety certificate, and nothing here should be used to argue that a server is
"secure", "verified", or "approved" for production. The benchmark never targets a public or
third-party MCP server; its results describe only the local reference fixtures. `guardbench inspect`
reads the tool list of servers *you* configured, and a clean result from it is no certificate either
(see [`guardbench inspect`](#guardbench-inspect-checking-your-own-servers) below).

### 2. Static analysis can miss semantic attacks

The reference static analyzer is a transparent rule catalogue (regular expressions, structural
checks on schemas, and capability inference; see [`risk_rules.py`](../src/guardbench/analysis/risk_rules.py)).
It reads English-language patterns after Unicode normalization. It will miss:

* paraphrased, translated, split-across-fields, or otherwise obfuscated instructions;
* attacks whose harm depends on context the metadata does not contain;
* anything that only appears in tool *responses* or at *call time*.

In the demo run it detects 4 of the 9 attack cases (44.4%) and, being alert-only, prevents none of them.
That gap is the point of the comparison. It misses `TP-003`, the same attack as
`TP-001` written in Spanish, exactly as this section predicts.

### 3. Runtime policy can be bypassed if the client is not instrumented

The reference runtime adapter only protects calls that are routed through it. A client that talks to
the server directly, uses a second transport, or skips the hook gets no protection at all. The
`no-defense-baseline` adapter is the model of that situation. The runtime policy is also only as good as its
rules: response inspection uses the same transparent pattern matching as the static analyzer.

### 4. Hashing detects change but does not establish initial trust

Fingerprints are SHA-256 over a canonical form of each tool definition. They tell you that a definition
*changed relative to a snapshot* (a rug pull, an accidental schema edit). They say nothing about whether the
snapshot you approved was trustworthy in the first place. A server that is malicious from the start
produces a stable, matching hash. A server's self-reported name and version are not proof of identity.

### 5. LLM-based detection can produce false positives and false negatives

**This project ships no LLM-based detector and calls no external model by default.** Every core check is
deterministic and runs without one. The "agent" in the benchmark is a deterministic script, not a language
model. If you add an LLM-backed adapter, expect non-deterministic results, prompt sensitivity, and both false
positives and false negatives; measure them with the benign controls (BN-001 to BN-003) and repeat runs before
trusting any figure.

### 6. A sandbox is not automatically a complete security boundary

The fixtures are hermetic by construction (no network, no subprocesses, no filesystem, in-memory state only)
and that is enforced by tests, independent of Docker. `docker-compose.yml` adds defence in depth: non-root
user, all capabilities dropped, read-only root filesystems, an internal network for the attack fixtures, and
loopback-only published ports. Those settings are checked statically by `tests/security/test_docker_config.py`.
Containers still share a kernel with their host, and configuration files do not prove runtime behaviour; see
"What was and was not run" below.

### 7. The benchmark corpus is incomplete

There are 11 fixtures and 12 test cases (9 attacks, 3 benign controls). That is a starting corpus, not a
survey of MCP attacks. It does not cover, among others: resources, prompts, sampling, or authorization flows;
HTTP transports; multi-server interactions beyond name shadowing; long-horizon or multi-step social
engineering; malicious dependencies; or denial-of-service beyond one oversized response.

Two further caveats about the corpus:

* **The reference controls were written alongside the first seven attack cases**, and `reference-runtime`
  scores 100% on those seven. That shows the controls handle the cases they were designed against, nothing
  more. Two *hard cases* were added later to probe weaknesses stated on this page, and the controls were
  not changed to pass them: `TP-003` (poisoning in Spanish) and `DF-002` (a secret that leaves
  base64-encoded). Neither reference control detects either one. `reference-runtime` still *prevents*
  `DF-002`, but only because unattended mode never approves an outbound send: if an operator approved it,
  the encoded secret would leave unnoticed. Overall it scores 77.8% detection and 88.9% prevention.
* With 9 attack cases every rate is coarse (one case is 11.1 percentage points). No confidence intervals are
  computed. Rates report their numerator and denominator so this is visible.

### 8. Results depend on model, client, configuration, and policy

Reported outcomes depend on the scripted agent's behaviour (including the "gullible agent" condition used in
test cases), the policy file (`default_policy.yaml`), the response-size limit, the run mode
(`unattended` never approves anything), the seed, and library versions. Every report records the policy hash,
corpus hash, seed, mode, and versions so a run can be reproduced; changing any of them can change the result.
A different model or client would behave differently, and this project does not measure real models.

### 9. External scanner integrations require separate validation

One real third-party control is integrated: Cisco AI Defense's open-source MCP Scanner
(`cisco-mcp-scanner`, [`cisco_scanner.py`](../src/guardbench/benchmark/cisco_scanner.py)). Its numbers
describe **only its YARA analyzer**, run offline, at the pinned version recorded in the report; its API
and LLM analyzers need keys and were not evaluated, and a newer version may score differently. The mapping
from its threat names to GuardBench categories is this project's (documented in `THREAT_CATEGORIES`), and
the scanner reports which rule matched but not where, so its evidence-completeness score is low by
construction. The `external-scanner` adapter remains as a documented placeholder that always reports itself
*unavailable*; its cases are recorded as **skipped**, never scored. If you write an adapter:

* detection is derived from findings that carry evidence and match the test case, not from the tool's own
  verdict or score;
* prevention is verified from the fixture ledger, and an adapter that does not run the scenario through the
  GuardBench runner is reported as **not blocked** with an explicit note that prevention could not be verified;
* the mapping from a vendor's output to `AdapterResult` is your code, and it needs its own review and tests.
  See [adapter-development.md](adapter-development.md).

## `guardbench inspect` (checking your own servers)

`inspect` reuses the benchmark's analyzers on real servers, so everything above about static analysis
applies to it too. In addition:

* **Starting a stdio server runs its code.** `inspect` starts each configured server exactly as your MCP
  client does, with your privileges. Inspect only servers you would run anyway; inspecting a server is as
  risky as installing it, not less.
* **It sees metadata only:** tool definitions and server instructions. It does not see tool responses,
  runtime behavior, the server's source code, or its dependencies, and it does not list resources or
  prompts. A server that behaves badly only when called will look clean.
* **No findings is not a guarantee.** The rules match English-language patterns (see #2 and `TP-003`).
* **Expect hygiene findings on legitimate servers.** Against 7 official MCP reference servers
  (filesystem, memory, everything, sequential-thinking, fetch, git, time; 52 tools) it reported no high or
  critical findings, and 96 medium/low ones such as "path parameter without directory restriction" on
  every filesystem tool. Those describe what a tool *can* do, not an attack. High and critical findings are
  the ones to act on, which is why `--fail-on` defaults to `high`.
* **A pin says "unchanged", not "safe"** (see #4). Servers that legitimately change their tools per
  version, per user, or per session will report drift until you re-pin them.
* HTTP servers that need an OAuth flow are not supported; static `headers` from the config are.

## Other limitations you should know about

| Area | Limitation |
|---|---|
| Scope of MCP | Only **tools** are exercised, over an in-process transport (plus a stdio runner for fixtures). Resources, prompts, sampling, HTTP/SSE transports and OAuth are not covered. |
| Data-flow tracking | Follows exact and lightly normalized **synthetic markers** through hops (source, model context, tool argument, outbound request). It does not follow transformed data (base64, chunking, paraphrase, hashing). |
| Approvals | Simulated only. A `simulated-operator` can resolve requests in tests and demos and is always labelled as simulated. Human factors (approval fatigue, misleading prompts) are not modelled. |
| Audit log | Events are stored with raw and redacted payloads, and the API serves only the redacted form. The log is **not tamper-evident** (no hash chain or signatures). |
| Redaction | Recognises the three synthetic markers and common real-credential *shapes*; it is a safety net for the lab, not a general secret scanner. |
| Latency | Measured in-process on one machine over a handful of cases (nearest-rank p50/p95). It says nothing about network deployments and varies between runs. |
| Determinism | Verdicts and trace ids are reproducible for a fixed seed, corpus, policy and versions. Timestamps and latency values are not. |
| Concurrency | Runs execute sequentially. The lab makes no claims about behaviour under concurrent agents. |

## What was and was not run

* **Verified:** the full test suite on SQLite; the database-backed tests and the Alembic migration against a real
  PostgreSQL 16 (an embedded server started by `scripts/test_postgres.py`, no Docker); `make setup`,
  `make seed`, `make demo`, `make cisco-demo`, `make report` and `make test` from a clean checkout on Python
  3.12 and 3.13; `guardbench inspect` against 7 official MCP reference servers started with `npx`/`uvx` on
  macOS; the `cisco-mcp-scanner` adapter against `cisco-ai-mcp-scanner` 4.8.4 with outbound network blocked
  (it made no network request).
* **Checked statically only:** `docker-compose.yml`, the `Dockerfile` and `.dockerignore` (validated with
  `docker compose config` and by the tests in `tests/security/test_docker_config.py`). The images have **not
  been built** and the containers **not started** locally; the CI workflow builds and starts them. An
  installed-wheel run with a read-only working directory, PostgreSQL, the API in non-dev mode and the
  dashboard approximates the container's behaviour, but it is not the same as running Docker.
* **Not verified:** the `postgres:16-alpine` image and the compose-level hardening options (capability drops,
  read-only root, tmpfs, networks) on a real daemon.

Run `make docker-up` and `make docker-demo` on a machine with Docker to close that gap.
