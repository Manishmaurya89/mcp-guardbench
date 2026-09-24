"""The Cisco MCP Scanner adapter: output translation, isolation, and honest skips.

The real scanner is not a dependency, so these tests drive the adapter with a small fake
``mcp-scanner`` that speaks the same command line and ``--raw`` JSON format. One test runs the
real scanner when it is installed (``make cisco-demo`` installs it) and is skipped otherwise.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from guardbench.benchmark import cisco_scanner as cisco
from guardbench.benchmark.orchestrator import BenchmarkConfig, BenchmarkOutcome, Orchestrator
from guardbench.benchmark.test_case_loader import load_test_cases
from guardbench.domain.enums import FindingCategory, ResultStatus, Severity
from guardbench.domain.errors import AdapterError, AdapterUnavailableError
from guardbench.policy.models import load_policy

CASES_DIR = Path(__file__).resolve().parents[2] / "test_cases"
ADAPTER = "cisco-mcp-scanner"

#: A trimmed copy of real ``mcp-scanner --analyzers yara --raw static`` output (version 4.8.4).
REAL_OUTPUT = [
    {
        "status": "completed",
        "is_safe": False,
        "findings": {
            "yara_analyzer": {
                "severity": "HIGH",
                "threat_names": ["PROMPT INJECTION", "DATA EXFILTRATION"],
                "threat_summary": "Detected 2 threats: prompt injection, data exfiltration",
                "total_findings": 2,
                "mcp_taxonomies": [
                    {
                        "scanner_category": "PROMPT INJECTION",
                        "aitech": "AITech-1.1",
                        "aitech_name": "Direct Prompt Injection",
                    },
                    {
                        "scanner_category": "SECURITY VIOLATION",
                        "aitech": "AITech-8.2",
                        "aitech_name": "Data Exfiltration / Exposure",
                    },
                ],
            }
        },
        "tool_name": "get_calendar_summary",
        "tool_description": "Returns a short summary ...",
        "item_type": "tool",
    },
    {
        "status": "completed",
        "is_safe": True,
        "findings": {
            "yara_analyzer": {
                "severity": "SAFE",
                "threat_names": [],
                "threat_summary": "No threats detected",
                "total_findings": 0,
            }
        },
        "tool_name": "list_meeting_rooms",
        "item_type": "tool",
    },
]

FAKE_SCANNER = """#!{python}
import json, os, sys
args = sys.argv[1:]
assert args[:2] == ["--analyzers", "yara"] and "static" in args, args
if os.environ.get("FAKE_ENV_DUMP"):
    json.dump(sorted(os.environ), open(os.environ["FAKE_ENV_DUMP"], "w"))
if os.environ.get("FAKE_FAIL"):
    sys.stderr.write("boom")
    sys.exit(3)
tools = json.load(open(args[args.index("--tools") + 1]))["tools"]
rows = []
for t in tools:
    text = (t.get("description") or "") + json.dumps(t.get("inputSchema", {{}}))
    hit = "ignore previous instructions" in text.lower()
    rows.append({{"status": "completed", "is_safe": not hit, "tool_name": t["name"], "item_type": "tool",
        "findings": {{"yara_analyzer": {{"severity": "HIGH" if hit else "SAFE",
            "threat_names": ["PROMPT INJECTION"] if hit else [],
            "threat_summary": "Detected 1 threat: prompt injection" if hit else "No threats detected"}}}}}})
print("log line before the JSON")
print(json.dumps(rows))
"""


@pytest.fixture
def fake_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "mcp-scanner"
    script.write_text(FAKE_SCANNER.format(python=sys.executable), encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv(cisco.ENV_VAR, str(script))
    monkeypatch.setattr(cisco, "_cache", {})
    return script


async def bench(*ids: str) -> BenchmarkOutcome:
    cases = load_test_cases(CASES_DIR, allowed_root=CASES_DIR)
    return await Orchestrator(cases, load_policy()).run(
        BenchmarkConfig(adapters=(ADAPTER,), test_case_ids=ids)
    )


# ---------------------------------------------------------------- translation


def test_real_scanner_output_becomes_evidenced_findings_with_a_documented_mapping() -> None:
    findings = cisco.findings_from_output(REAL_OUTPUT, server_name="srv")
    assert [f.rule_id for f in findings] == ["CISCO-YARA:PROMPT_INJECTION", "CISCO-YARA:DATA_EXFILTRATION"]
    for f in findings:
        assert f.category is FindingCategory.TOOL_POISONING and f.severity is Severity.HIGH
        assert f.tool_name == "get_calendar_summary" and f.server_name == "srv" and f.has_evidence
        assert f.evidence["scanner"] == cisco.PACKAGE and f.evidence["confidence_reported"] is False


def test_unknown_threat_labels_can_never_inflate_detection() -> None:
    row = {
        "tool_name": "t",
        "findings": {"yara_analyzer": {"severity": "MEDIUM", "threat_names": ["NEW THING"]}},
    }
    (finding,) = cisco.findings_from_output([row], server_name=None)
    assert finding.category is cisco.UNKNOWN_THREAT_CATEGORY is FindingCategory.POLICY_VIOLATION


def test_malformed_or_failed_output_is_an_error_not_a_result() -> None:
    with pytest.raises(AdapterError, match="expected JSON"):
        cisco.parse_output("Traceback (most recent call last): ...")
    with pytest.raises(AdapterError, match="not a list"):
        cisco.parse_output('{"tools": []}')
    with pytest.raises(AdapterError, match="could not scan"):
        cisco.findings_from_output([{"tool_name": "t", "status": "failed"}], server_name=None)


def test_the_scanner_never_receives_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_SCANNER_API_KEY", "x")
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.setenv("SOME_SECRET", "x")
    env = cisco._scanner_env()
    assert not {"MCP_SCANNER_API_KEY", "OPENAI_API_KEY", "SOME_SECRET"} & set(env)
    assert env["LITELLM_LOCAL_MODEL_COST_MAP"] == "True" and "PATH" in env


# ---------------------------------------------------------------- availability


def test_missing_scanner_is_unavailable_with_install_instructions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(cisco.ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(AdapterUnavailableError, match="uv tool install"):
        cisco.locate_scanner()
    monkeypatch.setenv(cisco.ENV_VAR, str(tmp_path / "nope"))
    with pytest.raises(AdapterUnavailableError, match="not an executable"):
        cisco.locate_scanner()


async def test_cases_are_skipped_never_scored_when_the_scanner_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(cisco.ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    out = await bench("TP-001", "BN-001")
    assert all(r.status is ResultStatus.SKIPPED and "not found" in (r.error or "") for r in out.results)
    assert all(not r.detected and not r.findings for r in out.results)


# ---------------------------------------------------------------- end to end (fake scanner)


async def test_detection_is_scored_like_any_other_adapter_and_prevention_is_zero(
    fake_scanner: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "env.json"
    monkeypatch.setenv("FAKE_ENV_DUMP", str(dump))
    monkeypatch.setenv("GITHUB_TOKEN", "should-not-be-passed")
    out = await bench("TP-001", "BN-001", "RI-001")
    by_case = {r.test_case_id: r for r in out.results}
    assert all(r.status is ResultStatus.COMPLETED for r in out.results), [r.error for r in out.results]
    assert by_case["TP-001"].detected and not by_case["TP-001"].blocked, "an alert is not prevention"
    assert not by_case["BN-001"].detected and not by_case["BN-001"].false_positive
    assert not by_case["RI-001"].detected, "static metadata scanning cannot see responses"
    assert by_case["TP-001"].adapter_version.endswith("-unknown")
    assert "GITHUB_TOKEN" not in json.loads(dump.read_text())


async def test_a_relative_scanner_path_still_works_from_the_temporary_working_directory(
    fake_scanner: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: `make cisco-demo` passes a relative path, and the scanner runs in a temp dir."""
    monkeypatch.chdir(fake_scanner.parent.parent)
    monkeypatch.setenv(cisco.ENV_VAR, f"{fake_scanner.parent.name}/{fake_scanner.name}")
    assert Path(cisco.locate_scanner()).is_absolute()
    (r,) = (await bench("TP-001")).results
    assert r.status is ResultStatus.COMPLETED and r.detected, r.error


async def test_a_crashing_scanner_is_an_error_result(
    fake_scanner: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FAIL", "1")
    out = await bench("TP-001")
    (r,) = out.results
    assert r.status is ResultStatus.ERROR and not r.detected


# ---------------------------------------------------------------- the real scanner, when installed


@pytest.mark.skipif(
    not (os.environ.get(cisco.ENV_VAR) or shutil.which(cisco.EXECUTABLE)),
    reason="Cisco MCP Scanner not installed (run `make cisco-demo` to install it)",
)
async def test_the_real_scanner_runs_offline_and_matches_the_published_results() -> None:
    out = await bench("TP-001", "TP-002", "BN-001", "BN-003", "RI-001")
    by_case = {r.test_case_id: r for r in out.results}
    assert all(r.status is ResultStatus.COMPLETED for r in out.results), [r.error for r in out.results]
    assert by_case["TP-001"].detected and by_case["TP-002"].detected
    assert not any(by_case[c].detected for c in ("BN-001", "BN-003", "RI-001"))
