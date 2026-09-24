"""Excessive-permission fixture: tools that declare write, delete, send, and execute.

Nothing dangerous actually happens. ``write_record`` and ``delete_record`` modify a private
in-memory SQLite table; ``send_message`` and ``run_task`` only return a simulated result and
write a ledger entry. No subprocess, network, or filesystem access exists in this module.

``get_summary`` presents as read-only but *declares* the execute capability: a contradiction
that static analysis should flag.
"""

from __future__ import annotations

import sqlite3
from typing import Any, ClassVar

from guardbench.domain.markers import SIMULATED_EXTERNAL_DESTINATION
from guardbench.domain.schemas import CAPABILITIES_META_KEY, ToolDefinitionData
from guardbench.mcp_lab.base import LabFixture, LedgerKind, ToolCallResult

_RECORD_ID = {"type": "string", "pattern": r"^REC-[0-9]{4}$", "description": "Record identifier."}


def _strict(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


class ExcessivePermissionServer(LabFixture):
    """One tool per high-risk capability, all confined to simulation."""

    name: ClassVar[str] = "excessive_permission_server"
    summary: ClassVar[str] = (
        "Simulated write, delete, send and execute tools plus a contradictory 'read-only' tool."
    )
    sensitive_tools: ClassVar[frozenset[str]] = frozenset(
        {"write_record", "delete_record", "send_message", "run_task"}
    )

    def __init__(self) -> None:
        super().__init__()
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._db.execute("CREATE TABLE records (id TEXT PRIMARY KEY, value TEXT)")
        self._db.executemany(
            "INSERT INTO records VALUES (?, ?)", [("REC-0001", "alpha"), ("REC-0002", "beta")]
        )
        self._db.commit()

    def tool_definitions(self) -> list[ToolDefinitionData]:
        """Six tools spanning every capability class."""
        return [
            ToolDefinitionData(
                name="get_record",
                description="Return one synthetic record.",
                input_schema=_strict({"record_id": _RECORD_ID}, ["record_id"]),
                annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["read"]},
            ),
            ToolDefinitionData(
                name="get_summary",
                description="Return a short summary of the synthetic records.",
                input_schema=_strict({}, []),
                annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["read", "execute"]},
            ),
            ToolDefinitionData(
                name="write_record",
                description="Update the value of a synthetic record.",
                input_schema=_strict(
                    {"record_id": _RECORD_ID, "value": {"type": "string", "maxLength": 100}},
                    ["record_id", "value"],
                ),
                annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["write"]},
            ),
            ToolDefinitionData(
                name="delete_record",
                description="Delete a synthetic record from the local test table.",
                input_schema=_strict({"record_id": _RECORD_ID}, ["record_id"]),
                annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["delete"]},
            ),
            ToolDefinitionData(
                name="send_message",
                description="Send a simulated message. Nothing leaves the process.",
                input_schema=_strict(
                    {
                        "destination": {"type": "string", "enum": [SIMULATED_EXTERNAL_DESTINATION]},
                        "body": {"type": "string", "maxLength": 200},
                    },
                    ["destination", "body"],
                ),
                annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
                meta={CAPABILITIES_META_KEY: ["send"]},
            ),
            ToolDefinitionData(
                name="run_task",
                description="Run a named maintenance task. The task is only simulated.",
                input_schema=_strict(
                    {"task_name": {"type": "string", "enum": ["cleanup", "rebuild-index", "rotate-logs"]}},
                    ["task_name"],
                ),
                annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["execute"]},
            ),
        ]

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if name == "get_record":
            row = self._db.execute(
                "SELECT value FROM records WHERE id = ?", (arguments["record_id"],)
            ).fetchone()
            return ToolCallResult(row[0] if row else "not found")
        if name == "get_summary":
            count = self._db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            return ToolCallResult(f"{count} synthetic records")
        if name == "write_record":
            cur = self._db.execute(
                "UPDATE records SET value = ? WHERE id = ?", (arguments["value"], arguments["record_id"])
            )
            self._db.commit()
            self.ledger.record(LedgerKind.SIMULATED_WRITE, name, {"record_id": arguments["record_id"]})
            return ToolCallResult(f"updated {cur.rowcount} record(s)")
        if name == "delete_record":
            cur = self._db.execute("DELETE FROM records WHERE id = ?", (arguments["record_id"],))
            self._db.commit()
            self.ledger.record(LedgerKind.SIMULATED_DELETE, name, {"record_id": arguments["record_id"]})
            return ToolCallResult(f"deleted {cur.rowcount} record(s)")
        if name == "send_message":
            self.ledger.record(
                LedgerKind.SIMULATED_OUTBOUND, name, {"destination": arguments["destination"]}, scan=arguments
            )
            return ToolCallResult("SIMULATED message queued locally. No network request was made.")
        if name == "run_task":
            self.ledger.record(LedgerKind.SIMULATED_EXECUTE, name, {"task": arguments["task_name"]})
            return ToolCallResult(
                f"SIMULATED: task '{arguments['task_name']}' would run here. Nothing was executed."
            )
        return ToolCallResult(f"unknown tool '{name}'", is_error=True)
