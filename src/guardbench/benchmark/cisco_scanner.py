"""Adapter for Cisco AI Defense's open-source MCP Scanner (``cisco-ai-mcp-scanner``, Apache-2.0).

The first real third-party control benchmarked here. It runs as a separate program in its own
environment, because its dependency set (for example a pinned ``litellm``) is large and would
conflict with this project's. Install it with, for example::

    uv tool install cisco-ai-mcp-scanner==4.8.4      # or: pipx install cisco-ai-mcp-scanner

and put ``mcp-scanner`` on ``PATH`` or point ``GUARDBENCH_CISCO_MCP_SCANNER`` at the executable
(``make cisco-demo`` does both). When it cannot be found the adapter reports itself unavailable and
its cases are *skipped*, never scored.

Only the scanner's **YARA analyzer** is used. It runs locally and needs no API key. The API, LLM,
and VirusTotal analyzers are never enabled, and credential-like variables are removed from the
scanner's environment, so no fixture data leaves the machine.

Fairness: the scanner sees exactly what the reference static analyzer sees (every tool listing the
scenario produces, through the same :class:`~guardbench.benchmark.runner.Guard` hook), and its
findings pass the same evidence and category checks as every other adapter's. Like any scanner it
is alert-only, so prevention is 0% by construction. It reports *which* rule matched but not *where*
or *what text*, so its findings carry less evidence than the reference analyzer's.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from guardbench.benchmark.guards import _claim
from guardbench.benchmark.runner import CallVerdict, ResponseInspection, ScenarioRun
from guardbench.domain.enums import EventType, FindingCategory, Severity
from guardbench.domain.errors import AdapterError, AdapterUnavailableError
from guardbench.domain.schemas import Finding, ServerIdentity, ToolDefinitionData
from guardbench.mcp_lab.base import ToolCallResult

ENV_VAR = "GUARDBENCH_CISCO_MCP_SCANNER"
EXECUTABLE = "mcp-scanner"
PACKAGE = "cisco-ai-mcp-scanner"
TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_BYTES = 20 * 1024 * 1024
_MAX_CACHE = 128

#: The scanner's YARA threat types, mapped onto GuardBench categories. The scanner only ever sees
#: tool *metadata*, so hostile content in it is tool poisoning; language describing dangerous
#: capabilities is excessive permission. Anything unrecognized is a policy violation, which no
#: attack case expects: an unknown label can never inflate detection, only count as a false alarm.
THREAT_CATEGORIES: dict[str, FindingCategory] = {
    "PROMPT INJECTION": FindingCategory.TOOL_POISONING,
    "TOOL POISONING": FindingCategory.TOOL_POISONING,
    "DATA EXFILTRATION": FindingCategory.TOOL_POISONING,
    "CREDENTIAL HARVESTING": FindingCategory.TOOL_POISONING,
    "INJECTION ATTACK": FindingCategory.TOOL_POISONING,
    "CODE EXECUTION": FindingCategory.EXCESSIVE_PERMISSION,
    "SYSTEM MANIPULATION": FindingCategory.EXCESSIVE_PERMISSION,
}
UNKNOWN_THREAT_CATEGORY = FindingCategory.POLICY_VIOLATION
_SEVERITIES = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
#: Removed from the scanner's environment: nothing it runs here needs a credential.
_CREDENTIAL_ENV = re.compile(r"(?i)(api[_-]?key|token|secret|passw(or)?d|credential)")
_cache: dict[str, list[dict[str, Any]]] = {}


def locate_scanner() -> str:
    """Absolute path of the ``mcp-scanner`` executable, or :class:`AdapterUnavailableError` saying why not.

    Absolute, because the scanner runs with a temporary working directory.
    """
    configured = os.environ.get(ENV_VAR)
    if configured:
        path = Path(configured).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.absolute())
        raise AdapterUnavailableError(f"{ENV_VAR}={configured} is not an executable file")
    found = shutil.which(EXECUTABLE)
    if found is None:
        raise AdapterUnavailableError(
            f"Cisco MCP Scanner not found: install it (`uv tool install {PACKAGE}`) or set {ENV_VAR}"
        )
    return str(Path(found).absolute())


def scanner_version(executable: str) -> str:
    """The installed scanner version, read with the interpreter next to the executable, else ``unknown``."""
    resolved = Path(executable).resolve()
    for candidate in (resolved.parent / "python", resolved.parent / "python.exe"):
        if not candidate.is_file():
            continue
        try:
            done = subprocess.run(  # noqa: S603 - fixed arguments, interpreter found next to the scanner
                [str(candidate), "-c", f"import importlib.metadata as m; print(m.version({PACKAGE!r}))"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            break
        version = done.stdout.strip()
        if done.returncode == 0 and re.fullmatch(r"[0-9A-Za-z.+\-]{1,40}", version):
            return version
        break
    return "unknown"


def _scanner_env() -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("MCP_SCANNER_") and not _CREDENTIAL_ENV.search(k)
    }
    env["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"  # litellm would otherwise fetch a price list at import
    return env


def tools_payload(tools: Sequence[ToolDefinitionData]) -> dict[str, Any]:
    """The tools as an MCP ``tools/list`` result, the scanner's static input format."""
    out = []
    for t in tools:
        item: dict[str, Any] = {
            "name": t.name,
            "description": t.description or "",
            "inputSchema": t.input_schema,
        }
        if t.title:
            item["title"] = t.title
        if t.output_schema is not None:
            item["outputSchema"] = t.output_schema
        if t.annotations:
            item["annotations"] = t.annotations
        if t.meta:
            item["_meta"] = t.meta
        out.append(item)
    return {"tools": out}


def run_scanner(
    executable: str, tools: Sequence[ToolDefinitionData], *, timeout: float = TIMEOUT_SECONDS
) -> list[dict[str, Any]]:
    """Run ``mcp-scanner --analyzers yara static`` on ``tools`` and return its raw per-tool rows.

    Identical listings are scanned once per process (the result is deterministic).
    """
    payload = json.dumps(tools_payload(tools), sort_keys=True)
    key = hashlib.sha256(f"{executable}\0{payload}".encode()).hexdigest()
    if key in _cache:
        return _cache[key]
    with tempfile.TemporaryDirectory(prefix="guardbench-cisco-") as tmp:
        path = Path(tmp) / "tools.json"
        path.write_text(payload, encoding="utf-8")
        command = [
            executable,
            "--analyzers",
            "yara",
            "--raw",
            "--log-level",
            "error",
            "static",
            "--tools",
            str(path),
        ]
        try:
            done = subprocess.run(  # noqa: S603 - fixed argument list; the executable is configured by the operator
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_scanner_env(),
                cwd=tmp,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"mcp-scanner did not finish within {timeout:g}s") from exc
        except OSError as exc:
            raise AdapterError(f"mcp-scanner could not be started: {type(exc).__name__}") from exc
    if done.returncode != 0:
        tail = " ".join(done.stderr.split())[-300:]
        raise AdapterError(f"mcp-scanner exited with status {done.returncode}: {tail}")
    rows = parse_output(done.stdout)
    if len(_cache) >= _MAX_CACHE:
        _cache.clear()
    _cache[key] = rows
    return rows


def parse_output(stdout: str) -> list[dict[str, Any]]:
    """The scanner's ``--raw`` JSON: a list with one object per scanned tool."""
    if len(stdout) > MAX_OUTPUT_BYTES:
        raise AdapterError("mcp-scanner output is unexpectedly large")
    text = stdout.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Tolerate log lines printed before the JSON document: parse from the first line opening a list.
        start = 0 if text.startswith("[") else text.find("\n[") + 1
        try:
            data = json.loads(text[start:]) if start > 0 else None
        except json.JSONDecodeError:
            data = None
        if data is None:
            raise AdapterError("mcp-scanner did not print the expected JSON (is it version 4.x?)") from None
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise AdapterError("mcp-scanner JSON is not a list of per-tool results")
    return data


def findings_from_output(rows: Sequence[dict[str, Any]], *, server_name: str | None) -> list[Finding]:
    """Translate the scanner's per-tool rows into GuardBench findings, one per reported threat."""
    findings: list[Finding] = []
    for row in rows:
        if row.get("item_type", "tool") != "tool":
            continue
        if row.get("status") not in (None, "completed"):
            raise AdapterError(
                f"mcp-scanner could not scan tool {row.get('tool_name')!r}: status {row.get('status')!r}"
            )
        yara = (row.get("findings") or {}).get("yara_analyzer") or {}
        threats = [t for t in yara.get("threat_names") or [] if isinstance(t, str)]
        if not threats:
            continue
        tool = str(row.get("tool_name") or "<unknown>")
        scanner_severity = str(yara.get("severity") or "").upper()
        severity = _SEVERITIES.get(scanner_severity, Severity.INFO)
        summary = str(yara.get("threat_summary") or ", ".join(threats))[:300]
        taxonomies = [t for t in yara.get("mcp_taxonomies") or [] if isinstance(t, dict)]
        for threat in threats:
            label = threat.strip().upper()
            findings.append(
                Finding(
                    rule_id="CISCO-YARA:" + re.sub(r"[^A-Z0-9]+", "_", label).strip("_"),
                    title=f"Cisco MCP Scanner (YARA): {threat.strip().lower()}",
                    category=THREAT_CATEGORIES.get(label, UNKNOWN_THREAT_CATEGORY),
                    severity=severity,
                    confidence=1.0,
                    description=f"The Cisco MCP Scanner's YARA rules flagged tool '{tool}' for "
                    f"{threat.lower()}. The scanner reports the rule, not the matched text or its location.",
                    location="tool",
                    matched_evidence=summary,
                    remediation="Review the tool's metadata before exposing it to a model; see the Cisco MCP "
                    "Scanner documentation for the rule.",
                    deterministic=True,
                    server_name=server_name,
                    tool_name=tool,
                    evidence={
                        "scanner": PACKAGE,
                        "analyzer": "yara",
                        "threat_name": threat,
                        "scanner_severity": scanner_severity or None,
                        "confidence_reported": False,
                        "taxonomies": [
                            {k: t.get(k) for k in ("scanner_category", "aitech", "aitech_name")}
                            for t in taxonomies
                        ],
                    },
                )
            )
    return findings


class CiscoScannerGuard:
    """Runs the scanner on every tool listing and records its findings. Alert-only: never blocks."""

    name = "cisco-mcp-scanner"

    def __init__(self, executable: str) -> None:
        self._executable = executable

    def on_tools_listed(
        self,
        run: ScenarioRun,
        tools: list[ToolDefinitionData],
        identity: ServerIdentity,
        *,
        pin_baseline: bool,
    ) -> frozenset[str]:
        """Scan the listing; withhold nothing."""
        for finding in findings_from_output(
            run_scanner(self._executable, tools), server_name=run.server_name
        ):
            event = run.emit(
                EventType.STATIC_FINDING,
                self.name,
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "matched": finding.matched_evidence,
                },
                tool_name=finding.tool_name,
                risk_tags=(finding.category.value,),
            )
            run.findings.append(_claim(finding, self.name, run, [str(event.id)]))
        return frozenset()

    def before_call(self, run: ScenarioRun, tool_name: str, arguments: dict[str, Any]) -> CallVerdict:
        """A scanner cannot stop calls."""
        return CallVerdict()

    def inspect_response(
        self, run: ScenarioRun, tool_name: str, result: ToolCallResult
    ) -> ResponseInspection:
        """The scanner's static mode does not see responses."""
        return ResponseInspection()
