# Threat model

> MCP-GuardBench is an **evaluation framework, not a guarantee of safety**. It measures whether a
> security control notices or stops the behaviors below, *in this lab, against these fixtures*. A
> good score here is evidence about the control under these conditions; it is not proof that any
> real MCP server, client, or deployment is safe. See [limitations.md](limitations.md).

## Actors

| Actor | What they can do here | How the lab represents them |
|---|---|---|
| Malicious MCP server author | Ships a server whose tools are malicious from the start | [`poisoned_description_server`](../src/guardbench/mcp_lab/servers/poisoned_description_server.py), [`poisoned_schema_server`](../src/guardbench/mcp_lab/servers/poisoned_schema_server.py) |
| Compromised MCP server | A previously-trusted server starts behaving differently | [`drift_server`](../src/guardbench/mcp_lab/servers/drift_server.py) (a deterministic, two-phase rug pull) |
| Malicious or compromised tool description | Hides instructions in a tool's `description`, schema text, or annotations | TP-001, TP-002 test cases; [`metadata_analyzer.py`](../src/guardbench/analysis/metadata_analyzer.py) |
| Attacker-controlled tool response | A clean-looking tool returns hostile content at call time | [`response_injection_server`](../src/guardbench/mcp_lab/servers/response_injection_server.py), RI-001 |
| Misconfigured MCP client | Routes calls around the runtime guard, or trusts everything a response says | Modelled by the `no-defense-baseline` adapter and by `PassthroughGuard` |
| Overprivileged service account | A tool is granted write/delete/send/execute it should not have | [`excessive_permission_server`](../src/guardbench/mcp_lab/servers/excessive_permission_server.py), PA-001; `Capability` inference in the static analyzer |
| Accidental schema change | A tool definition changes for an ordinary, non-malicious reason | Same drift mechanism as the compromised-server case; the drift report never assumes intent, only severity |
| Malicious dependency | Out of scope for this lab (no package installation happens); see `docs/limitations.md`, item 7 | Not simulated |
| Untrusted user input | Arguments passed to a tool call | `LabFixture.call_tool` validates every call against the tool's own JSON Schema before dispatch |
| Human operator approving an unsafe action | Approves a `require_approval` request without enough scrutiny | [`ApprovalService`](../src/guardbench/policy/approval.py) / `SimulatedOperator`, always labelled `simulated=True`; unattended benchmark runs never approve anything |

## Assets

| Asset | Where it lives | Protection in this lab |
|---|---|---|
| Tool definitions | `ToolDefinitionData`, `ToolSnapshot` rows | Canonical SHA-256 fingerprinting + drift detection ([`fingerprinting.py`](../src/guardbench/analysis/fingerprinting.py), [`drift_detector.py`](../src/guardbench/analysis/drift_detector.py)) |
| Agent context | What the scripted agent "sees" after a tool call | `model_context_update` events record what was exposed vs. withheld; a guard that keeps hostile text out of context also stops any scripted follow-up (`if_model_context_contains`) |
| Synthetic secrets | `TEST_SECRET_123`, `TEST_PRIVATE_RECORD` markers only — never real credentials | `find_credential_shapes`, `Redactor`, `DataFlowTracker` |
| Local files inside the test sandbox | Fixtures hold state in memory or `sqlite3://:memory:` only; no real filesystem access | Enforced by `tests/security/test_fixture_isolation.py` (import allowlist, no filesystem/network/subprocess) |
| Tool arguments | What the agent sends to a tool | Validated against the tool's JSON Schema before dispatch; scanned for synthetic markers by the ledger and the runtime guard |
| Tool responses | What a tool returns | `ResponseInspection` / `check_response` (size limit, injection pattern check, quarantine) |
| Audit logs | `events` table | `payload_json` (raw) vs. `redacted_payload_json` (API-visible); only the redacted form ever leaves the process boundary |
| Approval decisions | `ApprovalRequest` rows | No auto-bypass; every simulated resolution is permanently labelled `simulated-operator` |
| Server identity and version | `ServerIdentity` (self-reported name/version at handshake) | Treated as a claim, not proof — drift and fingerprinting compare *content*, not just the reported version |

## Trust boundaries

```
 test orchestrator                MCP server                  MCP client                  model
┌──────────────────┐  (1)   ┌──────────────────┐  (2)   ┌──────────────────┐  (3)   ┌────────────┐
│ ScenarioRunner /  │───────▶│ LabFixture       │───────▶│ Guard             │───────▶│ scripted   │
│ orchestrator      │        │ (build_server)   │        │ (adapter under    │        │ "agent"    │
└──────────────────┘        └──────────────────┘        │  test)            │        └─────┬──────┘
                                                          └──────────────────┘              │ (4)
                                                                                             ▼
                                                                                     tool invocation
                                                                                             │ (5)
                                                                                             ▼
                                                                              tool response → model context
                                                                                             │
                                        (6) runtime monitor → evidence database             │
                                                    ▲                                       │
                                                    └───────────────────────────────────────┘
                                                          (7) dashboard → API (read-only)
```

1. **Test orchestrator to test server** — the orchestrator only ever talks to fixtures created through
   the static [`REGISTRY`](../src/guardbench/mcp_lab/fixtures.py) allowlist; a fixture name is a
   dictionary key, never a path, module, or shell argument.
2. **MCP server to MCP client** — real MCP JSON-RPC over an in-process transport
   (`mcp.Client(..., mode="legacy", cache=None)`, cache disabled so drift stays observable) or, for
   the fixture-isolation tests, real stdio via `mcp.server.stdio.stdio_server`. Everything the server
   sends — tool listings and responses — is untrusted input from here on.
3. **MCP client to model** — the `Guard` interface is the boundary a control under test occupies. It
   sees every tools-list and every call before the scripted agent does, and can withhold tools or
   short-circuit calls.
4. **Model to tool invocation** — the scripted agent decides which tool to call from a fixed scenario
   script; `if_model_context_contains` models a "gullible agent" that only takes a follow-up action if
   hostile text actually reached its context, without running an LLM.
5. **Tool response to model context** — `ResponseInspection` / `check_response` can truncate, quarantine,
   or pass a response before it is recorded as part of the model's context.
6. **Runtime monitor to evidence database** — every step above emits an `Event`. The recorder writes
   both the raw and the redacted payload; only the redacted payload is ever queryable through the API.
7. **Dashboard to API** — the dashboard holds no database credentials and makes GET-only HTTP calls to
   the API; the API's `RedactingRoute` fails closed rather than ever emitting an unredacted response.

Every boundary above is crossed by real code in this repository, not a diagram of intent — see the
file references for where to read it, and `tests/security/` for what is verified about each one.
