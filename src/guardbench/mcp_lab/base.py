"""Foundation for lab fixtures: intentionally vulnerable, fully synthetic MCP servers.

Safety contract every fixture honors (verified by ``tests/security``):

* deterministic: no clocks, randomness, or environment reads;
* hermetic: no network, no subprocesses, no shell, no filesystem access;
* state lives in memory (or in-memory SQLite) and is created fresh per instance;
* "dangerous" tools only write to a private in-memory store or record a *simulated* effect.

Each fixture keeps a :class:`FixtureLedger`, the ground truth of what actually executed.
The benchmark scores prevention from this ledger, never from a control's own claim.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

from jsonschema import Draft202012Validator
from mcp import types
from mcp.server import Server, ServerRequestContext

from guardbench.domain.errors import GuardBenchError
from guardbench.domain.markers import ENCODED_MARKER_FORMS, MARKER_VALUES
from guardbench.domain.schemas import ServerIdentity, ToolDefinitionData

MAX_VALIDATION_ERRORS = 3


@dataclass(frozen=True, slots=True)
class ToolCallResult:
    """What a fixture tool returns."""

    text: str
    is_error: bool = False
    structured: dict[str, Any] | None = None


class LedgerKind(StrEnum):
    """Kinds of ground-truth records a fixture can write."""

    TOOL_EXECUTED = "tool_executed"
    SIMULATED_OUTBOUND = "simulated_outbound"
    SIMULATED_WRITE = "simulated_write"
    SIMULATED_DELETE = "simulated_delete"
    SIMULATED_EXECUTE = "simulated_execute"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One thing that really happened inside a fixture."""

    kind: LedgerKind
    tool: str
    detail: dict[str, Any] = field(default_factory=dict)
    markers: tuple[str, ...] = ()


class FixtureLedger:
    """Append-only ground truth of executed tools and simulated side effects."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    def record(
        self, kind: LedgerKind, tool: str, detail: dict[str, Any] | None = None, *, scan: Any = None
    ) -> None:
        """Append an entry; ``scan`` (any JSON-like value) is searched for synthetic markers."""
        found = (
            tuple(sorted(m for m in MARKER_VALUES if _contains_marker(scan, m))) if scan is not None else ()
        )
        self._entries.append(LedgerEntry(kind, tool, dict(detail or {}), found))

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        """All entries, oldest first."""
        return tuple(self._entries)

    def of_kind(self, kind: LedgerKind) -> list[LedgerEntry]:
        """Entries of one kind."""
        return [e for e in self._entries if e.kind is kind]

    def executed(self, tool: str) -> bool:
        """Whether ``tool`` actually ran."""
        return any(e.kind is LedgerKind.TOOL_EXECUTED and e.tool == tool for e in self._entries)


def _contains_marker(value: Any, marker: str, _depth: int = 0) -> bool:
    if _depth > 8:
        return False
    if isinstance(value, str):
        # Ground truth also recognizes encoded forms: an encoded leak is still a leak.
        encoded = ENCODED_MARKER_FORMS.get(marker, ())
        return marker.lower() in value.lower() or any(form in value for form in encoded)
    if isinstance(value, dict):
        return any(_contains_marker(v, marker, _depth + 1) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_marker(v, marker, _depth + 1) for v in value)
    return False


def to_sdk_tool(tool: ToolDefinitionData) -> types.Tool:
    """Convert a domain tool definition to the MCP SDK's ``Tool`` type."""
    return types.Tool(
        name=tool.name,
        title=tool.title,
        description=tool.description,
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        annotations=types.ToolAnnotations.model_validate(tool.annotations) if tool.annotations else None,
        meta=tool.meta or None,
    )


def from_sdk_tool(tool: types.Tool) -> ToolDefinitionData:
    """Convert an MCP SDK ``Tool`` to the domain type (the untrusted-input boundary)."""
    return ToolDefinitionData(
        name=tool.name,
        title=tool.title,
        description=tool.description,
        input_schema=dict(tool.input_schema),
        output_schema=dict(tool.output_schema) if tool.output_schema is not None else None,
        annotations=tool.annotations.model_dump(by_alias=True, exclude_none=True) if tool.annotations else {},
        meta=dict(tool.meta) if tool.meta else {},
    )


def validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> list[str]:
    """Validate ``arguments`` against ``schema``. Messages never echo argument values."""
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.absolute_path))
    return [
        f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.validator} constraint failed"
        for e in errors[:MAX_VALIDATION_ERRORS]
    ]


class LabFixture(ABC):
    """A deterministic, intentionally vulnerable, fully local MCP server."""

    name: ClassVar[str]
    summary: ClassVar[str]
    server_version: ClassVar[str] = "1.0.0"
    #: Ground-truth labels. Analyzers never see these; scoring does.
    poisoned_tools: ClassVar[frozenset[str]] = frozenset()
    sensitive_tools: ClassVar[frozenset[str]] = frozenset()
    drifted_tools: ClassVar[frozenset[str]] = frozenset()
    #: Text that marks hostile content in metadata or responses (ground-truth label).
    injection_marker: ClassVar[str | None] = None
    supports_state_advance: ClassVar[bool] = False

    def __init__(self) -> None:
        self.ledger = FixtureLedger()
        self.phase = 0

    # -- to implement ------------------------------------------------------------------

    @abstractmethod
    def tool_definitions(self) -> list[ToolDefinitionData]:
        """The tools advertised in the current state."""

    @abstractmethod
    def _dispatch(self, name: str, arguments: dict[str, Any]) -> ToolCallResult:
        """Run a validated call. Must be deterministic and side-effect-free outside the fixture."""

    # -- shared behavior ---------------------------------------------------------------

    def current_version(self) -> str:
        """Version reported at the MCP handshake. Drift-style fixtures change it with their state."""
        return self.server_version

    def identity(self) -> ServerIdentity:
        """Self-reported identity (not proof of trust)."""
        return ServerIdentity(name=self.name, version=self.current_version())

    def advance_state(self) -> None:
        """Move to the next deterministic state (only drift-style fixtures support this)."""
        raise GuardBenchError(f"fixture '{self.name}' has no state to advance")

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        """Validate and execute a tool call, recording it in the ledger."""
        args = arguments or {}
        tool = next((t for t in self.tool_definitions() if t.name == name), None)
        if tool is None:
            return ToolCallResult(f"unknown tool '{name}'", is_error=True)
        problems = validate_arguments(tool.input_schema, args)
        if problems:
            return ToolCallResult("invalid arguments: " + "; ".join(problems), is_error=True)
        self.ledger.record(LedgerKind.TOOL_EXECUTED, name, {"phase": self.phase}, scan=args)
        return self._dispatch(name, args)

    def build_server(self) -> Server[Any]:
        """Expose this fixture as a real MCP server using the SDK's public lowlevel API."""

        async def on_list_tools(
            _ctx: ServerRequestContext[Any], _params: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=[to_sdk_tool(t) for t in self.tool_definitions()])

        async def on_call_tool(
            _ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            result = self.call_tool(params.name, params.arguments)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=result.text)],
                structured_content=result.structured,
                is_error=result.is_error,
            )

        return Server(
            self.name,
            version=self.current_version(),
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )
