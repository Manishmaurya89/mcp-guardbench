"""In-process MCP client for lab fixtures, built on the SDK's public ``Client``.

Talks real MCP JSON-RPC (``mode="legacy"`` forces the initialize handshake) over in-memory
streams: no sockets, no subprocesses. Client-side caching is disabled on purpose: a
scanner must observe what the server says *now*, or drift detection would be blind.
"""

from __future__ import annotations

from contextlib import AsyncExitStack
from types import TracebackType
from typing import Any

from mcp import Client, MCPError, types

from guardbench.domain.errors import GuardBenchError
from guardbench.domain.schemas import ServerIdentity, ToolDefinitionData
from guardbench.mcp_lab.base import LabFixture, ToolCallResult, from_sdk_tool

MAX_LIST_PAGES = 10
MAX_TOOLS = 500
MAX_ERROR_CHARS = 200


class FixtureConnection:
    """Async context manager connecting the MCP SDK client to one fixture."""

    def __init__(self, fixture: LabFixture) -> None:
        self._fixture = fixture
        self._stack = AsyncExitStack()
        self._client: Client | None = None

    async def __aenter__(self) -> FixtureConnection:
        client = Client(self._fixture.build_server(), mode="legacy", cache=None)
        self._client = await self._stack.enter_async_context(client)
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self._stack.aclose()
        self._client = None

    @property
    def client(self) -> Client:
        """The connected SDK client."""
        if self._client is None:
            raise GuardBenchError("connection is not open; use 'async with FixtureConnection(...)'")
        return self._client

    @property
    def server_identity(self) -> ServerIdentity:
        """Identity the server reported during the handshake (self-reported, not verified)."""
        info = self.client.server_info
        return ServerIdentity(
            name=info.name if info else self._fixture.name,
            version=(info.version or None) if info else None,
            protocol_version=self.client.protocol_version,
        )

    async def list_tools(self) -> list[ToolDefinitionData]:
        """List all tools, following pagination with hard bounds against a hostile server."""
        tools: list[ToolDefinitionData] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            page = await self.client.list_tools(cursor=cursor)
            tools.extend(from_sdk_tool(t) for t in page.tools)
            if len(tools) > MAX_TOOLS:
                raise GuardBenchError(f"server advertised more than {MAX_TOOLS} tools")
            cursor = page.next_cursor
            if not cursor:
                return tools
        raise GuardBenchError(f"server paginated tools/list beyond {MAX_LIST_PAGES} pages")

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> ToolCallResult:
        """Call a tool over MCP and normalize the result."""
        try:
            result = await self.client.call_tool(name, arguments or {})
        except MCPError as exc:
            return ToolCallResult(f"protocol error: {str(exc)[:MAX_ERROR_CHARS]}", is_error=True)
        text = "\n".join(c.text for c in result.content if isinstance(c, types.TextContent))
        structured = result.structured_content if isinstance(result.structured_content, dict) else None
        return ToolCallResult(text, is_error=result.is_error, structured=structured)
