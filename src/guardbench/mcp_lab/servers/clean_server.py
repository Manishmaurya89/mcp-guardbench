"""Clean control fixture: a normal, well-specified calendar-and-catalog server.

Used as the benign baseline. A good security control should leave it alone (no false
positives). State lives in an in-memory SQLite database created per instance.
"""

from __future__ import annotations

import sqlite3
from typing import Any, ClassVar

from guardbench.domain.schemas import CAPABILITIES_META_KEY, ToolDefinitionData
from guardbench.mcp_lab.base import LabFixture, LedgerKind, ToolCallResult
from guardbench.mcp_lab.common import DATE_PATTERN

_EVENTS = [
    ("EVT-001", "2026-01-15", "Design review", 60),
    ("EVT-002", "2026-01-15", "Team sync", 30),
    ("EVT-003", "2026-01-16", "Planning", 45),
]
_CATALOG = [
    ("CAT-001", "Notebook", "stationery"),
    ("CAT-002", "Desk lamp", "office"),
    ("CAT-003", "Notebook stand", "office"),
    ("CAT-004", "Pen set", "stationery"),
]


class CleanServer(LabFixture):
    """A benign server with read and write tools and strict schemas."""

    name: ClassVar[str] = "clean_server"
    summary: ClassVar[str] = "Benign calendar and catalog tools with strict schemas (control)."

    def __init__(self) -> None:
        super().__init__()
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._db.execute("CREATE TABLE events (id TEXT PRIMARY KEY, date TEXT, title TEXT, minutes INTEGER)")
        self._db.execute("CREATE TABLE catalog (id TEXT PRIMARY KEY, name TEXT, category TEXT)")
        self._db.executemany("INSERT INTO events VALUES (?, ?, ?, ?)", _EVENTS)
        self._db.executemany("INSERT INTO catalog VALUES (?, ?, ?)", _CATALOG)
        self._db.commit()

    def tool_definitions(self) -> list[ToolDefinitionData]:
        """Three ordinary tools: two read-only, one that adds a calendar event."""
        date_schema = {"type": "string", "pattern": DATE_PATTERN, "description": "Date in YYYY-MM-DD form."}
        return [
            ToolDefinitionData(
                name="get_calendar_events",
                description="Return the calendar events scheduled on a given date.",
                input_schema={
                    "type": "object",
                    "properties": {"date": date_schema},
                    "required": ["date"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "events": {
                            "type": "array",
                            "items": {"type": "object", "additionalProperties": True},
                            "description": "Events on the requested date.",
                        }
                    },
                    "required": ["events"],
                    "additionalProperties": False,
                },
                annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["read"]},
            ),
            ToolDefinitionData(
                name="create_calendar_event",
                description="Create a new calendar event with a title, date, and duration.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 120,
                            "description": "Event title.",
                        },
                        "date": date_schema,
                        "duration_minutes": {"type": "integer", "minimum": 5, "maximum": 480},
                    },
                    "required": ["title", "date", "duration_minutes"],
                    "additionalProperties": False,
                },
                annotations={
                    "readOnlyHint": False,
                    "destructiveHint": False,
                    "idempotentHint": False,
                    "openWorldHint": False,
                },
                meta={CAPABILITIES_META_KEY: ["write"]},
            ),
            ToolDefinitionData(
                name="search_local_catalog",
                description="Search the local product catalog by keyword.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "pattern": r"^[A-Za-z0-9 \-]+$",
                            "description": "Keyword to look for.",
                        },
                        "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"type": "object", "additionalProperties": True},
                            "description": "Matching catalog entries.",
                        }
                    },
                    "required": ["items"],
                    "additionalProperties": False,
                },
                annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["read"]},
            ),
        ]

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if name == "get_calendar_events":
            rows = self._db.execute(
                "SELECT id, date, title, minutes FROM events WHERE date = ? ORDER BY id", (arguments["date"],)
            ).fetchall()
            events = [{"id": r[0], "date": r[1], "title": r[2], "duration_minutes": r[3]} for r in rows]
            return ToolCallResult(
                f"{len(events)} event(s) on {arguments['date']}", structured={"events": events}
            )
        if name == "create_calendar_event":
            count = self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            event_id = f"EVT-{count + 1:03d}"
            self._db.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?)",
                (event_id, arguments["date"], arguments["title"], arguments["duration_minutes"]),
            )
            self._db.commit()
            self.ledger.record(LedgerKind.SIMULATED_WRITE, name, {"event_id": event_id})
            return ToolCallResult(f"Created {event_id}")
        if name == "search_local_catalog":
            needle = arguments["query"].replace("%", "").replace("_", "")
            rows = self._db.execute(
                "SELECT id, name, category FROM catalog WHERE name LIKE ? ORDER BY id LIMIT ?",
                (f"%{needle}%", arguments.get("limit", 5)),
            ).fetchall()
            items = [{"id": r[0], "name": r[1], "category": r[2]} for r in rows]
            return ToolCallResult(f"{len(items)} item(s) found", structured={"items": items})
        return ToolCallResult(f"unknown tool '{name}'", is_error=True)
