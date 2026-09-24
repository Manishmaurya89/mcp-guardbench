# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/) and is pre-1.0, so minor versions may change behavior.

## [0.1.0] - Unreleased

First public release.

### Added

- `guardbench inspect`: read-only check of the MCP servers configured in Claude Desktop, Claude Code,
  Cursor, VS Code and Windsurf (stdio, Streamable HTTP, SSE; JSONC; `${VAR}` expansion). Requests
  `tools/list` only, analyzes tool metadata and server instructions with the benchmark's rules, pins
  fingerprints to catch rug pulls, masks configured secrets, escapes server output, and exits 1 for CI
  when a finding reaches `--fail-on`. Validated against 7 official MCP reference servers.
- `cisco-mcp-scanner` adapter: benchmarks Cisco AI Defense's open-source MCP Scanner (YARA analyzer,
  offline) as a separate program; `make cisco-demo` installs it into its own virtual environment.
- Hard test cases `TP-003` (tool poisoning written in Spanish) and `DF-002` (a secret that leaves
  base64-encoded), and benign control `BN-003` (descriptions that legitimately reference sibling tools),
  with three new fixtures. The reference controls were not changed to pass them.
- Fixture ground truth recognizes base64 and hex encodings of the synthetic markers.
- The benchmark lab: 11 local fixtures, 12 test cases, reference static and runtime controls, verified
  detection and prevention metrics, reports (JSON, Markdown, CSV, HTML), REST API, read-only dashboard,
  PostgreSQL and SQLite support, Docker Compose setup.
