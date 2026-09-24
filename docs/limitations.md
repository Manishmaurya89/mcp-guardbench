# Limitations

MCP-GuardBench is a **local evaluation laboratory**. Read this page before you quote any number it
produces. Every limitation below is also repeated, where it applies, in the generated reports.

## The nine statements this project stands behind

### 1. This project does not prove an MCP server is safe

A benchmark can only show that a control did or did not handle the cases in its corpus. It cannot
show the absence of vulnerabilities in any real server, client, or deployment. No score in this
repository is a safety certificate, and nothing here should be used to argue that a server is
"secure", "verified", or "approved" for production. No public or third-party MCP server is ever
scanned; every result describes only the local reference fixtures.

### 2. Static analysis can miss semantic attacks

The reference static analyzer is a transparent rule catalogue (regular expressions, structural
checks on schemas, and capability inference; see [`risk_rules.py`](../src/guardbench/analysis/risk_rules.py)).
It reads English-language patterns after Unicode normalization. It will miss:

* paraphrased, translated, split-across-fields, or otherwise obfuscated instructions;
* attacks whose harm depends on context the metadata does not contain;
* anything that only appears in tool *responses* or at *call time*.

In the demo run it detects 4 of the 7 attack cases (57.1%) and, being alert-only, prevents none of them.
That gap is the point of the comparison, not a defect to hide.

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
positives and false negatives; measure them with the benign controls (BN-001, BN-002) and repeat runs before
trusting any figure.

### 6. A sandbox is not automatically a complete security boundary

The fixtures are hermetic by construction (no network, no subprocesses, no filesystem, in-memory state only)
and that is enforced by tests, independent of Docker. `docker-compose.yml` adds defence in depth: non-root
user, all capabilities dropped, read-only root filesystems, an internal network for the attack fixtures, and
loopback-only published ports. Those settings are checked statically by `tests/security/test_docker_config.py`.
Containers still share a kernel with their host, and configuration files do not prove runtime behaviour; see
"What was and was not run" below.

### 7. The benchmark corpus is incomplete

There are 8 fixtures and 9 test cases (7 attacks, 2 benign controls). That is a starting corpus, not a
survey of MCP attacks. It does not cover, among others: resources, prompts, sampling, or authorization flows;
HTTP transports; multi-server interactions beyond name shadowing; long-horizon or multi-step social
engineering; malicious dependencies; or denial-of-service beyond one oversized response.

Two further caveats about the corpus:

* **The reference controls were written alongside the fixtures.** A perfect score for `reference-runtime`
  (100% detection and prevention here) shows that the controls handle the cases they were designed against. It
  is not evidence of real-world effectiveness, and it will not survive a case the authors did not anticipate.
* With 7 attack cases every rate is coarse (one case is 14.3 percentage points). No confidence intervals are
  computed. Rates report their numerator and denominator so this is visible.

### 8. Results depend on model, client, configuration, and policy

Reported outcomes depend on the scripted agent's behaviour (including the "gullible agent" condition used in
test cases), the policy file (`default_policy.yaml`), the response-size limit, the run mode
(`unattended` never approves anything), the seed, and library versions. Every report records the policy hash,
corpus hash, seed, mode, and versions so a run can be reproduced; changing any of them can change the result.
A different model or client would behave differently, and this project does not measure real models.

### 9. External scanner integrations require separate validation

Only a documented placeholder exists for third-party scanners (`external-scanner`); it always reports itself
*unavailable*, and its cases are recorded as **skipped**, never scored. If you write an adapter:

* detection is derived from findings that carry evidence and match the test case, not from the tool's own
  verdict or score;
* prevention is verified from the fixture ledger, and an adapter that does not run the scenario through the
  GuardBench runner is reported as **not blocked** with an explicit note that prevention could not be verified;
* the mapping from a vendor's output to `AdapterResult` is your code, and it needs its own review and tests.
  See [adapter-development.md](adapter-development.md).

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

Stated plainly, because "the tests pass" can hide gaps:

* **Verified:** the full test suite on SQLite; the database-backed tests and the Alembic migration against a real
  PostgreSQL 16 (an embedded server started by `scripts/test_postgres.py`, no Docker); a clean-clone run of
  `make setup`, `make seed`, `make demo`, `make report` and `make test` on Python 3.12 and 3.13.
* **Checked statically only:** `docker-compose.yml`, the `Dockerfile` and `.dockerignore` (validated with
  `docker compose config` and by the tests in `tests/security/test_docker_config.py`). The development machine
  had no running Docker daemon, so the images were **not built** and the containers were **not started** by the
  author. An installed-wheel run with a read-only working directory, PostgreSQL, the API in non-dev mode and the
  dashboard approximated the container's behaviour, but it is not the same as running Docker.
* **Not verified:** the `postgres:16-alpine` image and the compose-level hardening options (capability drops,
  read-only root, tmpfs, networks) on a real daemon.

Run `make docker-up` and `make docker-demo` on a machine with Docker to close that gap.
