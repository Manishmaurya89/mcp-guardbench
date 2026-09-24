"""Security properties of ``guardbench inspect``, checked on its source.

The inspection package talks to servers the user configured, which may be hostile. It must only
ever *list* tools: no code path may call a tool, read a resource, get a prompt, or otherwise act.
"""

from __future__ import annotations

import ast
from pathlib import Path

import guardbench.inspection as inspection_pkg

PACKAGE_DIR = Path(inspection_pkg.__file__).resolve().parent
SOURCES = sorted(PACKAGE_DIR.glob("*.py"))

#: MCP client operations that do something beyond listing tools.
FORBIDDEN_OPERATIONS = {
    "call_tool",
    "read_resource",
    "list_resources",
    "list_resource_templates",
    "get_prompt",
    "list_prompts",
    "complete",
    "subscribe_resource",
    "unsubscribe_resource",
    "set_logging_level",
    "send_request",
    "send_notification",
    "send_roots_list_changed",
}


def names_used(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            used.add(node.attr)
        elif isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.alias):
            used.add(node.name.split(".")[-1])
    return used


def test_the_package_exists_and_is_scanned() -> None:
    assert {p.name for p in SOURCES} >= {"client.py", "configs.py", "pins.py", "render.py", "service.py"}


def test_no_code_path_calls_a_tool_or_touches_resources_or_prompts() -> None:
    for path in SOURCES:
        bad = names_used(path) & FORBIDDEN_OPERATIONS
        assert not bad, f"{path.name} uses {sorted(bad)}: inspection must stay read-only (tools/list only)"


def test_inspection_does_not_depend_on_the_hostile_lab_fixtures() -> None:
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert not any(m.startswith("guardbench.mcp_lab") for m in modules), path.name


def test_no_shell_is_ever_used_to_start_a_server() -> None:
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                raise AssertionError(f"{path.name} passes shell=...")
        assert "os.system" not in path.read_text(encoding="utf-8"), path.name
