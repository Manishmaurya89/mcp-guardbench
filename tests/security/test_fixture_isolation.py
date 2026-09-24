"""The lab safety contract, enforced mechanically.

Fixtures must be hermetic and deterministic: no network, no subprocess or shell, no filesystem,
no environment, no dynamic code, no clocks or randomness. These tests parse the fixture source
so a future edit cannot quietly break the contract, and they exercise every fixture at runtime
with the network blocked.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

import guardbench.mcp_lab.servers as servers_pkg
from guardbench.mcp_lab.base import LabFixture
from guardbench.mcp_lab.client_runner import FixtureConnection
from guardbench.mcp_lab.fixtures import REGISTRY, create_fixture, fixture_names

pytestmark = pytest.mark.security

SERVERS_DIR = Path(servers_pkg.__file__).resolve().parent
SERVER_FILES = sorted(p for p in SERVERS_DIR.glob("*.py") if p.name != "__init__.py")
LAB_SUPPORT_FILES = [SERVERS_DIR.parent / "common.py"]

#: The only modules a fixture may import. Everything else (socket, os, subprocess, pathlib,
#: urllib, http, requests, httpx, importlib, ctypes, time, random, uuid, datetime, ...) is refused.
ALLOWED_FIXTURE_IMPORTS = {"__future__", "typing", "sqlite3", "guardbench"}
#: Support modules additionally need the MCP SDK and jsonschema (``base.py`` only).
FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "system",
    "popen",
    "getattr_static",
}
FORBIDDEN_ATTRIBUTES = {
    "system",
    "popen",
    "Popen",
    "spawn",
    "fork",
    "connect",
    "urlopen",
    "environ",
    "getenv",
}


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported_top_level(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


def test_the_fixture_directory_contains_exactly_the_registered_fixtures() -> None:
    assert len(SERVER_FILES) == len(REGISTRY) == 8
    assert {p.stem for p in SERVER_FILES} == {
        create_fixture(n).__class__.__module__.rsplit(".", 1)[-1] for n in fixture_names()
    }


@pytest.mark.parametrize("path", SERVER_FILES, ids=lambda p: p.name)
def test_fixture_source_imports_only_allowlisted_modules(path: Path) -> None:
    extra = imported_top_level(parse(path)) - ALLOWED_FIXTURE_IMPORTS
    assert not extra, f"{path.name} imports forbidden modules: {sorted(extra)}"


@pytest.mark.parametrize("path", [*SERVER_FILES, *LAB_SUPPORT_FILES], ids=lambda p: p.name)
def test_fixture_source_has_no_dynamic_code_shell_file_or_env_access(path: Path) -> None:
    tree = parse(path)
    bad_calls = []
    bad_attrs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALLS:
                bad_calls.append(func.id)
            is_sqlite_connect = (
                isinstance(func, ast.Attribute)
                and func.attr == "connect"
                and isinstance(func.value, ast.Name)
                and func.value.id == "sqlite3"  # checked separately by the in-memory test below
            )
            if (
                isinstance(func, ast.Attribute)
                and func.attr in FORBIDDEN_ATTRIBUTES
                and not is_sqlite_connect
            ):
                bad_attrs.append(func.attr)
        if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}:
            bad_attrs.append(node.attr)
    assert not bad_calls, f"{path.name} calls {bad_calls}"
    assert not bad_attrs, f"{path.name} uses {bad_attrs}"


@pytest.mark.parametrize("path", SERVER_FILES, ids=lambda p: p.name)
def test_sqlite_is_only_ever_opened_in_memory(path: Path) -> None:
    for node in ast.walk(parse(path)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "sqlite3"
        ):
            first = node.args[0]
            assert isinstance(first, ast.Constant) and first.value == ":memory:", (
                f"{path.name}: sqlite3.connect must use the literal ':memory:'"
            )


def test_lab_support_modules_do_not_import_network_shell_or_filesystem_modules() -> None:
    forbidden = {
        "socket",
        "ssl",
        "subprocess",
        "os",
        "shutil",
        "pathlib",
        "urllib",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "ctypes",
        "importlib",
        "pickle",
        "tempfile",
        "glob",
    }
    for path in [*LAB_SUPPORT_FILES, SERVERS_DIR.parent / "base.py"]:
        bad = imported_top_level(parse(path)) & forbidden
        assert not bad, f"{path.name} imports {sorted(bad)}"


def test_fixtures_contain_no_url_literals() -> None:
    """A fixture that mentions a URL is a fixture that might fetch one."""
    for path in SERVER_FILES + LAB_SUPPORT_FILES:
        text = path.read_text(encoding="utf-8")
        assert "http://" not in text and "https://" not in text, f"{path.name} contains a URL literal"


def test_the_network_guard_itself_works(network_error: type[Exception]) -> None:
    """Positive control: if this passes vacuously, the tests below prove nothing."""
    with pytest.raises(network_error):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(network_error):
        socket.socket().connect(("127.0.0.1", 9))
    with pytest.raises(network_error):
        socket.getaddrinfo("example.invalid", 80)


@pytest.mark.parametrize("name", fixture_names())
async def test_every_fixture_can_be_fully_exercised_without_any_network_access(name: str) -> None:
    fixture: LabFixture = create_fixture(name)
    if fixture.supports_state_advance:
        fixture.advance_state()
    async with FixtureConnection(fixture) as conn:
        tools = await conn.list_tools()
        assert tools
        for tool in tools:
            await conn.call_tool(tool.name, {})  # even invalid calls must stay local
    # reaching this line means the autouse guard was never tripped


def test_no_registered_fixture_is_a_subclass_defined_outside_the_servers_package() -> None:
    for name, cls in REGISTRY.items():
        assert cls.__module__.startswith("guardbench.mcp_lab.servers."), name
