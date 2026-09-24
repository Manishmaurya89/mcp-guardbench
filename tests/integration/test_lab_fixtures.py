"""Behavior of each lab fixture, and the ground-truth ledger that scoring relies on."""

from __future__ import annotations

import pytest

from guardbench.domain.markers import SIMULATED_EXTERNAL_DESTINATION, TEST_SECRET
from guardbench.mcp_lab.base import LedgerKind
from guardbench.mcp_lab.client_runner import FixtureConnection
from guardbench.mcp_lab.fixtures import create_fixture, fixture_names
from guardbench.mcp_lab.servers.oversized_response_server import RESPONSE_BYTES
from guardbench.mcp_lab.servers.response_injection_server import INJECTION_TEXT


async def test_excessive_permission_tools_only_touch_the_private_test_table_or_simulate() -> None:
    fixture = create_fixture("excessive_permission_server")
    async with FixtureConnection(fixture) as conn:
        assert (await conn.call_tool("get_record", {"record_id": "REC-0001"})).text == "alpha"
        wrote = await conn.call_tool("write_record", {"record_id": "REC-0001", "value": "changed"})
        assert "updated 1" in wrote.text
        assert (await conn.call_tool("get_record", {"record_id": "REC-0001"})).text == "changed"
        deleted = await conn.call_tool("delete_record", {"record_id": "REC-0002"})
        assert "deleted 1" in deleted.text
        sent = await conn.call_tool(
            "send_message", {"destination": SIMULATED_EXTERNAL_DESTINATION, "body": "hi"}
        )
        assert "SIMULATED" in sent.text and "No network" in sent.text
        ran = await conn.call_tool("run_task", {"task_name": "cleanup"})
        assert "SIMULATED" in ran.text and "Nothing was executed" in ran.text

    kinds = [e.kind for e in fixture.ledger.entries if e.kind is not LedgerKind.TOOL_EXECUTED]
    assert kinds == [
        LedgerKind.SIMULATED_WRITE,
        LedgerKind.SIMULATED_DELETE,
        LedgerKind.SIMULATED_OUTBOUND,
        LedgerKind.SIMULATED_EXECUTE,
    ]


async def test_execute_task_names_are_restricted_to_an_enum() -> None:
    async with FixtureConnection(create_fixture("excessive_permission_server")) as conn:
        assert (await conn.call_tool("run_task", {"task_name": "rm -rf /"})).is_error
        assert (
            await conn.call_tool("send_message", {"destination": "real.example.com", "body": "x"})
        ).is_error


async def test_response_injection_fixture_returns_the_synthetic_instruction() -> None:
    fixture = create_fixture("response_injection_server")
    async with FixtureConnection(fixture) as conn:
        result = await conn.call_tool("fetch_report", {"report_id": "R-1"})
    assert INJECTION_TEXT in result.text
    assert not fixture.ledger.of_kind(LedgerKind.SIMULATED_OUTBOUND), "reading the report has no side effect"


async def test_secret_flow_source_returns_the_marker_and_the_sink_records_it() -> None:
    fixture = create_fixture("secret_flow_server")
    async with FixtureConnection(fixture) as conn:
        record = await conn.call_tool("read_private_record", {"record_id": "REC-SECRET-1"})
        assert TEST_SECRET in record.text
        await conn.call_tool(
            "send_notification", {"destination": SIMULATED_EXTERNAL_DESTINATION, "body": record.text}
        )
    outbound = fixture.ledger.of_kind(LedgerKind.SIMULATED_OUTBOUND)
    assert len(outbound) == 1
    assert outbound[0].markers == tuple(sorted({TEST_SECRET, SIMULATED_EXTERNAL_DESTINATION}))


async def test_a_clean_outbound_call_records_no_secret_marker() -> None:
    fixture = create_fixture("secret_flow_server")
    async with FixtureConnection(fixture) as conn:
        await conn.call_tool(
            "send_notification", {"destination": SIMULATED_EXTERNAL_DESTINATION, "body": "hello"}
        )
    assert TEST_SECRET not in fixture.ledger.of_kind(LedgerKind.SIMULATED_OUTBOUND)[0].markers


async def test_oversized_response_is_exactly_the_configured_size_and_harmless() -> None:
    async with FixtureConnection(create_fixture("oversized_response_server")) as conn:
        result = await conn.call_tool("generate_report", {})
    assert len(result.text.encode()) == RESPONSE_BYTES
    assert result.text.isascii()
    assert TEST_SECRET not in result.text and "ignore" not in result.text.lower()


async def test_drift_fixture_changes_behavior_only_after_the_explicit_advance() -> None:
    fixture = create_fixture("drift_server")
    async with FixtureConnection(fixture) as conn:
        assert (await conn.call_tool("lookup_record", {"record_id": "REC-0001"})).text == "alpha"
    assert not fixture.ledger.of_kind(LedgerKind.SIMULATED_DELETE)

    fixture.advance_state()
    async with FixtureConnection(fixture) as conn:
        assert (await conn.call_tool("lookup_record", {"record_id": "REC-0001"})).is_error, (
            "note is now required"
        )
        changed = await conn.call_tool("lookup_record", {"record_id": "REC-0001", "note": "x"})
        assert "removed REC-0001" in changed.text
    assert len(fixture.ledger.of_kind(LedgerKind.SIMULATED_DELETE)) == 1
    executed = fixture.ledger.of_kind(LedgerKind.TOOL_EXECUTED)
    assert executed[-1].detail["phase"] == 1, "the ledger records the phase, which is how drift use is scored"


def test_only_the_drift_fixture_supports_state_advance() -> None:
    supporting = [n for n in fixture_names() if create_fixture(n).supports_state_advance]
    assert supporting == ["drift_server"]


@pytest.mark.parametrize("name", fixture_names())
async def test_fixtures_are_deterministic_across_instances(name: str) -> None:
    async def transcript() -> list[str]:
        fixture = create_fixture(name)
        out = [repr(t) for t in fixture.tool_definitions()]
        async with FixtureConnection(fixture) as conn:
            for tool in fixture.tool_definitions():
                if not tool.input_schema.get("required"):
                    out.append((await conn.call_tool(tool.name, {})).text)
        return out

    assert await transcript() == await transcript()


@pytest.mark.parametrize("name", fixture_names())
def test_every_fixture_is_safe_to_instantiate_repeatedly_with_fresh_state(name: str) -> None:
    for _ in range(3):
        fixture = create_fixture(name)
        assert fixture.ledger.entries == ()
        assert fixture.phase == 0
        assert fixture.tool_definitions()


@pytest.mark.parametrize("name", fixture_names())
def test_ground_truth_labels_only_reference_real_tools(name: str) -> None:
    fixture = create_fixture(name)
    names = {t.name for t in fixture.tool_definitions()}
    assert fixture.poisoned_tools <= names
    assert fixture.sensitive_tools <= names
    assert fixture.drifted_tools <= names
