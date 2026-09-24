"""List the tools of a user-configured MCP server, and nothing else.

The only requests this module sends are the connection handshake and ``tools/list``. It has no
code path that calls a tool, reads a resource, or gets a prompt (``tests/security`` checks that by
inspecting this package's source). Every server is treated as hostile: listings are bounded, the
whole exchange runs under a timeout, and the server's stderr is captured, not shown, unless it
fails.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Any, TextIO, cast

import anyio
import httpx2
from mcp import Client
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import Implementation

from guardbench import __version__
from guardbench.domain.errors import InspectionError
from guardbench.domain.schemas import ServerIdentity, ToolDefinitionData
from guardbench.inspection.configs import ServerSpec

MAX_LIST_PAGES = 20
MAX_TOOLS = 1000
MAX_INSTRUCTIONS_CHARS = 20_000
MAX_STDERR_TAIL = 300  # the end of stderr is where the cause usually is
CLIENT_INFO = Implementation(name="mcp-guardbench-inspect", version=__version__)


@dataclass(frozen=True, slots=True)
class ServerListing:
    """What a server said about itself: identity, tools, and optional instructions."""

    identity: ServerIdentity
    tools: list[ToolDefinitionData]
    instructions: str | None = None


def _mapping(raw: Any, key: str) -> dict[str, Any] | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InspectionError(f"tool field '{key}' must be an object")
    return value


def tool_from_mapping(raw: Any) -> ToolDefinitionData:
    """Build a tool definition from MCP ``tools/list`` JSON (camelCase keys, ``_meta``)."""
    if not isinstance(raw, dict):
        raise InspectionError("each tool must be a JSON object")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise InspectionError("each tool needs a non-empty string 'name'")
    for key in ("title", "description"):
        if raw.get(key) is not None and not isinstance(raw[key], str):
            raise InspectionError(f"tool {name!r}: '{key}' must be a string")
    try:
        return ToolDefinitionData(
            name=name,
            title=raw.get("title"),
            description=raw.get("description"),
            input_schema=_mapping(raw, "inputSchema") or _mapping(raw, "input_schema") or {"type": "object"},
            output_schema=_mapping(raw, "outputSchema") or _mapping(raw, "output_schema"),
            annotations=_mapping(raw, "annotations") or {},
            meta=_mapping(raw, "_meta") or _mapping(raw, "meta") or {},
        )
    except ValueError as exc:
        raise InspectionError(f"tool {name!r} is not a valid tool definition") from exc


def tools_from_listing(data: Any) -> list[ToolDefinitionData]:
    """Accept a ``tools/list`` result (``{"tools": [...]}``), a JSON-RPC response, or a bare list."""
    if isinstance(data, dict) and isinstance(data.get("result"), dict):
        data = data["result"]
    if isinstance(data, dict):
        data = data.get("tools")
    if not isinstance(data, list):
        raise InspectionError('expected a tools/list result: {"tools": [...]} or a JSON list of tools')
    if len(data) > MAX_TOOLS:
        raise InspectionError(f"more than {MAX_TOOLS} tools")
    tools = [tool_from_mapping(t) for t in data]
    names = [t.name for t in tools]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise InspectionError(f"duplicate tool names: {duplicates}")
    return tools


def _transport(spec: ServerSpec, errlog: IO[str]) -> Any:
    if spec.transport == "stdio":
        assert spec.command is not None
        params = StdioServerParameters(
            command=spec.command, args=list(spec.args), env=dict(spec.env) or None, cwd=spec.cwd
        )
        return stdio_client(params, errlog=cast(TextIO, errlog))
    assert spec.url is not None
    if spec.transport == "sse":
        return sse_client(spec.url, headers=dict(spec.headers) or None)
    http_client = httpx2.AsyncClient(headers=dict(spec.headers), follow_redirects=False)
    return streamable_http_client(spec.url, http_client=http_client)


def _stderr_tail(errlog: IO[str], spec: ServerSpec) -> str:
    """The end of the server's stderr, with configured secrets masked (servers often echo their arguments)."""
    try:
        errlog.seek(0)
        text = spec.scrub(errlog.read())[-MAX_STDERR_TAIL:]
    except (OSError, ValueError):
        return ""
    return "".join(ch if ch.isprintable() or ch == "\n" else "?" for ch in text).strip()


async def _list(spec: ServerSpec, errlog: IO[str]) -> ServerListing:
    async with Client(_transport(spec, errlog), mode="auto", cache=None, client_info=CLIENT_INFO) as client:
        tools: list[ToolDefinitionData] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            page = await client.list_tools(cursor=cursor)
            tools.extend(
                tool_from_mapping(t.model_dump(by_alias=True, exclude_none=True, mode="json"))
                for t in page.tools
            )
            if len(tools) > MAX_TOOLS:
                raise InspectionError(f"server advertised more than {MAX_TOOLS} tools")
            cursor = page.next_cursor
            if not cursor:
                break
        else:
            raise InspectionError(f"server paginated tools/list beyond {MAX_LIST_PAGES} pages")
        info = client.server_info
        instructions = client.instructions
        return ServerListing(
            identity=ServerIdentity(
                name=info.name if info else spec.name,
                version=(info.version or None) if info else None,
                protocol_version=client.protocol_version,
            ),
            tools=tools,
            instructions=instructions[:MAX_INSTRUCTIONS_CHARS] if instructions else None,
        )


def _describe(exc: BaseException, spec: ServerSpec) -> str:
    if isinstance(exc, BaseExceptionGroup):
        leaves = [e for e in exc.exceptions if not isinstance(e, anyio.get_cancelled_exc_class())]
        return _describe(leaves[0], spec) if leaves else "cancelled"
    if isinstance(exc, FileNotFoundError):
        return spec.scrub(f"command not found: {exc.filename or 'unknown'}")
    message = str(exc).strip().splitlines()[0][:300] if str(exc).strip() else ""
    return spec.scrub(f"{type(exc).__name__}: {message}" if message else type(exc).__name__)


async def list_server_tools(spec: ServerSpec, *, timeout: float) -> ServerListing:
    """Connect, request ``tools/list``, disconnect. Raises :class:`InspectionError` with a clear reason."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as errlog:
        try:
            with anyio.fail_after(timeout):
                return await _list(spec, errlog)
        except TimeoutError as exc:
            reason = f"no answer within {timeout:g}s"
            tail = _stderr_tail(errlog, spec)
            raise InspectionError(f"{reason}; server stderr: {tail}" if tail else reason) from exc
        except InspectionError:
            raise
        except Exception as exc:
            tail = _stderr_tail(errlog, spec)
            reason = _describe(exc, spec)
            raise InspectionError(f"{reason}; server stderr: {tail}" if tail else reason) from exc


async def list_many(
    specs: Sequence[ServerSpec], *, timeout: float, concurrency: int = 4
) -> Mapping[str, ServerListing | InspectionError]:
    """List servers concurrently (bounded). Keyed by server name; failures are returned, not raised."""
    results: dict[str, ServerListing | InspectionError] = {}
    limiter = anyio.CapacityLimiter(concurrency)

    async def one(spec: ServerSpec) -> None:
        async with limiter:
            try:
                results[spec.name] = await list_server_tools(spec, timeout=timeout)
            except InspectionError as exc:
                results[spec.name] = exc

    async with anyio.create_task_group() as group:
        for spec in specs:
            group.start_soon(one, spec)
    return results
