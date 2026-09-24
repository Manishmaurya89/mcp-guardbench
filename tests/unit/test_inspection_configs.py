"""Reading MCP client configs: every common shape, JSONC, variables, and secret masking."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardbench.domain.errors import InspectionError
from guardbench.inspection.configs import (
    ServerSpec,
    discover_configs,
    known_config_locations,
    load_config,
    load_json_file,
    mask_args,
    safe_url,
)


def write(tmp_path: Path, data: object, name: str = "mcp.json") -> Path:
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "table_key",
    [["mcpServers"], ["servers"], ["mcp", "servers"]],
    ids=["claude-cursor-windsurf", "vscode-mcp-json", "vscode-settings"],
)
def test_every_common_config_shape_is_read(tmp_path: Path, table_key: list[str]) -> None:
    servers = {
        "files": {"command": "npx", "args": ["-y", "pkg", "/tmp"]},
        "web": {"url": "https://example.test/mcp"},
    }
    data: dict[str, object] = {}
    node = data
    for key in table_key[:-1]:
        node[key] = {}
        node = node[key]  # type: ignore[assignment]
    node[table_key[-1]] = servers
    load = load_config(write(tmp_path, data), environ={})
    assert [(s.name, s.transport) for s in load.servers] == [("files", "stdio"), ("web", "http")]
    assert load.servers[0].args == ("-y", "pkg", "/tmp") and load.problems == []


def test_transport_types_and_windsurf_server_url(tmp_path: Path) -> None:
    load = load_config(
        write(
            tmp_path,
            {
                "mcpServers": {
                    "a": {"type": "sse", "url": "https://h.test/sse"},
                    "b": {"type": "streamable-http", "url": "https://h.test/mcp"},
                    "c": {"serverUrl": "https://h.test/mcp", "headers": {"Authorization": "Bearer x"}},
                    "d": {
                        "type": "stdio",
                        "command": "uvx",
                        "args": ["srv"],
                        "env": {"PORT": 8080, "ON": True},
                    },
                }
            },
        ),
        environ={},
    )
    kinds = {s.name: s.transport for s in load.servers}
    assert kinds == {"a": "sse", "b": "http", "c": "http", "d": "stdio"}
    d = next(s for s in load.servers if s.name == "d")
    assert d.env == {"PORT": "8080", "ON": "true"}


def test_disabled_entries_are_skipped_and_bad_entries_are_reported_not_fatal(tmp_path: Path) -> None:
    load = load_config(
        write(
            tmp_path,
            {
                "mcpServers": {
                    "off": {"command": "x", "disabled": True},
                    "off2": {"command": "x", "enabled": False},
                    "empty": {},
                    "bad-args": {"command": "x", "args": "not-a-list"},
                    "ftp": {"url": "ftp://h.test"},
                    "mixed": {"type": "sse", "command": "x"},
                    "good": {"command": "x"},
                }
            },
        ),
        environ={},
    )
    assert [s.name for s in load.servers] == ["good"]
    assert len(load.problems) == 4 and all(p.startswith("server '") for p in load.problems)


def test_jsonc_comments_and_trailing_commas_are_accepted_without_breaking_urls_in_strings(
    tmp_path: Path,
) -> None:
    text = """{
      // a line comment
      "servers": {
        /* a block comment */
        "web": {"url": "https://h.test/a//b", "headers": {"X": "not // a comment",},},
      },
    }"""
    load = load_config(write(tmp_path, text), environ={})
    web = load.servers[0]
    assert web.url == "https://h.test/a//b" and web.headers == {"X": "not // a comment"}


def test_invalid_json_and_missing_tables_raise_clear_errors_without_echoing_content(tmp_path: Path) -> None:
    with pytest.raises(InspectionError, match="not valid JSON"):
        load_config(write(tmp_path, '{"mcpServers": {"x": SECRET-VALUE-123'), environ={})
    with pytest.raises(InspectionError, match="no MCP server table"):
        load_config(write(tmp_path, {"other": 1}), environ={})
    with pytest.raises(InspectionError, match="cannot read"):
        load_json_file(tmp_path / "missing.json")


def test_env_variables_and_workspace_folder_are_expanded(tmp_path: Path) -> None:
    folder = tmp_path / "proj" / ".vscode"
    folder.mkdir(parents=True)
    load = load_config(
        write(
            folder,
            {
                "servers": {
                    "s": {
                        "command": "srv",
                        "args": ["${workspaceFolder}/data", "${env:HOME_DIR}", "${UNSET_VAR}"],
                        "env": {"TOKEN": "${MY_TOKEN}"},
                    }
                }
            },
        ),
        environ={"HOME_DIR": "/home/me", "MY_TOKEN": "tok-123456"},
    )
    spec = load.servers[0]
    assert spec.args == (f"{tmp_path / 'proj'}/data", "/home/me", "${UNSET_VAR}")
    assert spec.env == {"TOKEN": "tok-123456"}


def test_secret_looking_arguments_and_url_parts_are_masked_for_display() -> None:
    shown = mask_args(
        [
            "--api-key",
            "abc123",
            "--token=xyz789",
            "--port",
            "80",
            "postgres://user:pw@db.test:5432/x?sslkey=1",
        ]
    )
    assert shown == ["--api-key", "***", "--token=***", "--port", "80", "postgres://db.test:5432/x?..."]
    assert safe_url("https://u:p@h.test:8443/mcp?key=s3cret#frag") == "https://h.test:8443/mcp?..."
    spec = ServerSpec(name="s", transport="http", source="c", url="https://u:p@h.test/mcp?key=s3cret")
    assert "s3cret" not in spec.display_target() and "u:p" not in spec.display_target()


def test_scrub_removes_every_configured_secret_value_from_server_output() -> None:
    spec = ServerSpec(
        name="s",
        transport="stdio",
        source="c",
        command="srv",
        args=("--api-key", "hunter2secret", "--db=postgres://a:b@h/x"),
        env={"GITHUB_TOKEN": "ghs-not-a-real-token-0000"},
    )
    text = "usage error: --api-key hunter2secret, token ghs-not-a-real-token-0000"
    scrubbed = spec.scrub(text)
    assert "hunter2secret" not in scrubbed and "ghs-not-a-real-token-0000" not in scrubbed
    assert "***" in scrubbed
    assert "env" not in repr(spec) or "ghs-" not in repr(spec), "env never appears in repr"


def test_known_locations_cover_the_main_clients_on_each_platform(tmp_path: Path) -> None:
    for platform in ("darwin", "linux", "win32"):
        labels = {label for label, _ in known_config_locations(tmp_path, tmp_path, platform=platform)}
        assert {
            "Claude Desktop",
            "Claude Code (user)",
            "Cursor (user)",
            "VS Code (workspace)",
            "Windsurf",
        } <= labels
    mac = dict(known_config_locations(tmp_path, tmp_path, platform="darwin"))
    assert mac["Claude Desktop"] == (
        tmp_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    )


def test_discovery_returns_only_files_that_exist(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text("{}", encoding="utf-8")
    project.mkdir()
    (project / ".mcp.json").write_text("{}", encoding="utf-8")
    found = discover_configs(home, project, platform="linux")
    assert [label for label, _ in found] == ["Claude Code (project)", "Cursor (user)"]
