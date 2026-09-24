# Test cases

Nine YAML test cases, all safe, deterministic, and run only against the local fixtures in
[`src/guardbench/mcp_lab/servers/`](../src/guardbench/mcp_lab/servers/). See
[`../docs/test-case-format.md`](../docs/test-case-format.md) for the file format and how to add one.

| ID | Category | Severity | Fixture | Name |
|---|---|---|---|---|
| [BN-001](BN-001-clean-server-metadata.yaml) | benign_control | info | clean_server | Clean server metadata (benign control) |
| [BN-002](BN-002-clean-server-read-calls.yaml) | benign_control | info | clean_server | Ordinary read-only calls (benign control) |
| [DF-001](DF-001-sensitive-marker-flow.yaml) | sensitive_data_flow | critical | secret_flow_server | Synthetic secret flows from a local source into an outbound argument |
| [PA-001](PA-001-excessive-permission.yaml) | excessive_permission | high | excessive_permission_server | Simulated write, delete, send and execute without approval |
| [RD-001](RD-001-tool-definition-drift.yaml) | tool_definition_drift | high | drift_server | Tool definition changes after approval (rug pull) |
| [RI-001](RI-001-response-injection.yaml) | response_injection | high | response_injection_server | Injection delivered in a tool response |
| [RS-001](RS-001-oversized-response.yaml) | oversized_response | medium | oversized_response_server | Response far larger than the configured limit |
| [TP-001](TP-001-tool-description-injection.yaml) | tool_poisoning | high | poisoned_description_server | Hidden instruction in tool description |
| [TP-002](TP-002-schema-injection.yaml) | tool_poisoning | high | poisoned_schema_server | Hidden instruction inside the tool schema |

`BN-001` and `BN-002` are **benign controls**: a correct security control must leave them alone. They
are what `false_positive_rate` is computed from. The other seven are attack cases, scored for detection
and prevention.

## Try them yourself

```bash
guardbench list-test-cases                       # everything above, from the live loader
guardbench benchmark run --case-id DF-001 \
    --adapter no-defense-baseline --adapter reference-runtime --no-persist
```

## Safety

Every case is validated at load time (`TestCaseSpec` in
[`../src/guardbench/domain/testcase.py`](../src/guardbench/domain/testcase.py)):

* `synthetic_markers` may only be `TEST_SECRET_123`, `TEST_PRIVATE_RECORD`, or
  `SIMULATED_EXTERNAL_DESTINATION` — never a real-looking secret.
* `server_fixture` must be one of the eight allowlisted local fixtures; a case can never point at a real
  server, a file path, or a module.
* `safe_behavior` must declare the full baseline (`no_external_network`, `no_real_secret`,
  `no_destructive_action`) on every case.
* Descriptions and scenario arguments are scanned for real-credential *shapes* and rejected if found.

A test case cannot, by construction, attack anything other than the fixtures shipped in this repository.
