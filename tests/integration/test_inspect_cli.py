"""``guardbench inspect`` end to end against real MCP servers started over stdio.

The servers are this repository's own lab fixtures, launched through the stdio runner exactly
as an MCP client would launch any configured server. No network is used.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from guardbench.cli.main import app
from guardbench.mcp_lab.base import to_sdk_tool
from guardbench.mcp_lab.fixtures import create_fixture

runner = CliRunner()


def stdio_entry(fixture: str, **extra: Any) -> dict[str, Any]:
    return {
        "command": sys.executable,
        "args": ["-m", "guardbench.mcp_lab.server_runner", "--fixture", fixture],
        **extra,
    }


def config(tmp_path: Path, servers: dict[str, Any]) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


def tools_file(path: Path, fixture_name: str, *, advance: bool = False) -> Path:
    fixture = create_fixture(fixture_name)
    if advance:
        fixture.advance_state()
    tools = [
        to_sdk_tool(t).model_dump(by_alias=True, exclude_none=True, mode="json")
        for t in fixture.tool_definitions()
    ]
    path.write_text(json.dumps({"tools": tools}), encoding="utf-8")
    return path


def invoke(*args: str) -> Any:
    return runner.invoke(app, ["inspect", *args])


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)


def test_a_poisoned_server_fails_the_check_and_a_clean_one_passes(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        {"calendar": stdio_entry("poisoned_description_server"), "clean": stdio_entry("clean_server")},
    )
    result = invoke(str(cfg), "--json")
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    servers = {s["name"]: s for s in report["servers"]}
    assert servers["calendar"]["status"] == "ok" and servers["calendar"]["tool_count"] == 3
    assert (
        servers["clean"]["status"] == "ok"
        and servers["calendar"]["identity"]["name"] == "poisoned_description_server"
    )
    rules = {(f["server_name"], f["rule_id"]) for f in report["findings"]}
    assert ("calendar", "MA-001") in rules and report["summary"]["highest_severity"] == "critical"

    clean_only = invoke(str(cfg), "--server", "clean")
    assert clean_only.exit_code == 0, clean_only.output
    assert "read-only" in clean_only.output and "no tool is ever called" in clean_only.output


def test_fail_on_threshold_controls_the_exit_status(tmp_path: Path) -> None:
    cfg = config(tmp_path, {"calendar": stdio_entry("poisoned_description_server")})
    assert invoke(str(cfg), "--fail-on", "none").exit_code == 0
    assert invoke(str(cfg), "--fail-on", "critical").exit_code == 1


def test_configured_secrets_never_appear_in_any_output(tmp_path: Path) -> None:
    secret_arg, secret_env = "hunter2-arg-secret", "sk-test-0000000000000000000000"
    cfg = config(
        tmp_path,
        {
            # The runner rejects the unknown flag and echoes it on stderr; it must come out masked.
            "echoes": stdio_entry("clean_server", env={"API_TOKEN": secret_env})
            | {
                "args": [
                    "-m",
                    "guardbench.mcp_lab.server_runner",
                    "--fixture",
                    "clean_server",
                    "--api-key",
                    secret_arg,
                ]
            },
        },
    )
    for args in ((str(cfg),), (str(cfg), "--json")):
        result = invoke(*args)
        assert result.exit_code == 1
        assert secret_arg not in result.output and secret_env not in result.output
    text = invoke(str(cfg)).output
    assert "Could not inspect" in text and "--api-key ***" in text


def test_unreachable_servers_are_reported_without_hanging(tmp_path: Path) -> None:
    cfg = config(
        tmp_path,
        {
            "missing": {"command": "definitely-not-a-real-mcp-server-binary"},
            "silent": {"command": sys.executable, "args": ["-c", "import time; time.sleep(30)"]},
            "remote": {"url": "https://mcp.example.test/mcp"},
        },
    )
    result = invoke(str(cfg), "--timeout", "2", "--json")
    assert result.exit_code == 1
    errors = {s["name"]: s["error"] for s in json.loads(result.stdout)["servers"]}
    assert "command not found" in errors["missing"]
    assert "no answer within 2s" in errors["silent"]
    assert errors["remote"], "the test suite blocks the network, so this must fail cleanly"


def test_offline_tools_json_pinning_and_rug_pull_detection(tmp_path: Path) -> None:
    before = tools_file(tmp_path / "records.json", "drift_server")
    approved = invoke("--tools-json", str(before), "--update-pins")
    assert approved.exit_code == 0, approved.output
    assert "Pinned 1 server(s)" in approved.output and (tmp_path / "guardbench-pins.json").is_file()

    unchanged = invoke("--tools-json", str(before))
    assert unchanged.exit_code == 0 and "matches pin" in unchanged.output

    after = tools_file(tmp_path / "records.json", "drift_server", advance=True)
    changed = invoke("--tools-json", str(after))
    assert changed.exit_code == 1
    assert "CHANGED" in changed.output and "possible rug pull" in changed.output
    assert "capabilities escalated" in changed.output


def test_usage_errors_are_one_clear_line(tmp_path: Path) -> None:
    nothing = invoke()
    assert nothing.exit_code == 1 and "--discover" in nothing.output
    cfg = config(tmp_path, {"a": {"command": "x"}})
    unknown = invoke(str(cfg), "--server", "nope")
    assert unknown.exit_code == 1 and "unknown server name" in unknown.output
    assert invoke(str(tmp_path / "missing.json")).exit_code == 1


def test_discover_reads_well_known_client_configs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"clean": stdio_entry("clean_server")}}))
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    result = invoke("--discover")
    assert result.exit_code == 0, result.output
    assert "Claude Code (project)" in result.output and "clean" in result.output
