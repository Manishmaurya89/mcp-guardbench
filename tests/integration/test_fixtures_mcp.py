"""Fixtures speak real MCP: definitions must survive the protocol round trip unchanged."""

from __future__ import annotations

import sys

import pytest
from mcp import Client, StdioServerParameters

from guardbench.domain.errors import UnknownFixtureError
from guardbench.mcp_lab.base import from_sdk_tool, to_sdk_tool
from guardbench.mcp_lab.client_runner import FixtureConnection
from guardbench.mcp_lab.fixtures import REGISTRY, create_fixture, fixture_info, fixture_names

ALL = fixture_names()


@pytest.mark.parametrize("name", ALL)
async def test_definitions_survive_the_mcp_round_trip_unchanged(name: str) -> None:
    fixture = create_fixture(name)
    async with FixtureConnection(fixture) as conn:
        over_the_wire = await conn.list_tools()
    assert over_the_wire == fixture.tool_definitions(), "protocol round trip must not add or lose metadata"


@pytest.mark.parametrize("name", ALL)
def test_sdk_conversion_is_lossless(name: str) -> None:
    for tool in create_fixture(name).tool_definitions():
        assert from_sdk_tool(to_sdk_tool(tool)) == tool


@pytest.mark.parametrize("name", ALL)
async def test_server_identity_is_reported(name: str) -> None:
    fixture = create_fixture(name)
    async with FixtureConnection(fixture) as conn:
        identity = conn.server_identity
    assert identity.name == name
    assert identity.version == fixture.server_version
    assert identity.protocol_version


async def test_clean_server_read_write_and_search_work_over_mcp() -> None:
    async with FixtureConnection(create_fixture("clean_server")) as conn:
        before = await conn.call_tool("get_calendar_events", {"date": "2026-01-15"})
        assert before.structured is not None
        assert [e["title"] for e in before.structured["events"]] == ["Design review", "Team sync"]

        created = await conn.call_tool(
            "create_calendar_event", {"title": "Retro", "date": "2026-01-15", "duration_minutes": 30}
        )
        assert not created.is_error
        after = await conn.call_tool("get_calendar_events", {"date": "2026-01-15"})
        assert after.structured is not None
        assert len(after.structured["events"]) == 3

        found = await conn.call_tool("search_local_catalog", {"query": "notebook"})
        assert found.structured is not None
        assert {i["id"] for i in found.structured["items"]} == {"CAT-001", "CAT-003"}


async def test_invalid_arguments_are_rejected_without_echoing_values() -> None:
    async with FixtureConnection(create_fixture("clean_server")) as conn:
        bad = await conn.call_tool("get_calendar_events", {"date": "not-a-date"})
        extra = await conn.call_tool("get_calendar_events", {"date": "2026-01-15", "surprise": 1})
    assert bad.is_error
    assert "not-a-date" not in bad.text
    assert extra.is_error


async def test_unknown_tool_is_an_error_and_never_executes() -> None:
    fixture = create_fixture("clean_server")
    async with FixtureConnection(fixture) as conn:
        result = await conn.call_tool("does_not_exist", {})
    assert result.is_error
    assert fixture.ledger.entries == ()


async def test_sql_metacharacters_in_search_are_inert() -> None:
    async with FixtureConnection(create_fixture("clean_server")) as conn:
        result = await conn.call_tool("search_local_catalog", {"query": "x' OR '1'='1"})
    assert result.is_error  # rejected by the schema pattern before it reaches the database


async def test_sql_wildcards_are_rejected_by_the_schema_before_reaching_the_database() -> None:
    async with FixtureConnection(create_fixture("clean_server")) as conn:
        result = await conn.call_tool("search_local_catalog", {"query": "%"})
    assert result.is_error


def test_sql_wildcards_are_also_neutralized_if_validation_is_bypassed() -> None:
    """Defense in depth: the handler itself strips LIKE wildcards."""
    fixture = create_fixture("clean_server")
    result = fixture._dispatch("search_local_catalog", {"query": "%"})  # deliberate: bypass validation
    assert result.structured is not None
    assert len(result.structured["items"]) == 4  # empty needle matches everything, but nothing is injected


async def test_fixture_state_is_isolated_per_instance() -> None:
    a, b = create_fixture("clean_server"), create_fixture("clean_server")
    async with FixtureConnection(a) as conn:
        await conn.call_tool(
            "create_calendar_event", {"title": "Only in A", "date": "2026-02-01", "duration_minutes": 10}
        )
    async with FixtureConnection(b) as conn:
        result = await conn.call_tool("get_calendar_events", {"date": "2026-02-01"})
    assert result.structured == {"events": []}


def test_registry_rejects_anything_off_the_allowlist() -> None:
    for bad in ("../../etc/passwd", "os", "clean_server.py", "CLEAN_SERVER", "", "a b"):
        with pytest.raises(UnknownFixtureError):
            create_fixture(bad)
    assert set(REGISTRY) == set(ALL)


def test_fixture_info_describes_every_fixture() -> None:
    infos = {i.name: i for i in fixture_info()}
    assert set(infos) == set(ALL)
    assert all(i.summary and i.tool_count >= 1 for i in infos.values())


async def test_stdio_transport_serves_a_fixture_in_a_subprocess() -> None:
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "guardbench.mcp_lab.server_runner", "--fixture", "clean_server"]
    )
    async with Client(params, mode="legacy", cache=None) as client:
        listing = await client.list_tools()
    assert [t.name for t in listing.tools] == [
        "get_calendar_events",
        "create_calendar_event",
        "search_local_catalog",
    ]


def test_server_runner_refuses_non_allowlisted_fixtures() -> None:
    from guardbench.mcp_lab.server_runner import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["--fixture", "../../bin/sh"])
