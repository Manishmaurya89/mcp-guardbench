"""Read MCP client configuration files into :class:`ServerSpec` objects.

Supported shapes, which cover the MCP clients in common use:

* ``{"mcpServers": {name: {...}}}``: Claude Desktop, Claude Code (``.mcp.json``, ``~/.claude.json``),
  Cursor, Windsurf, Cline, and most other clients;
* ``{"servers": {name: {...}}}``: VS Code ``mcp.json``;
* ``{"mcp": {"servers": {name: {...}}}}``: VS Code ``settings.json``.

An entry with ``command`` is a stdio server. An entry with ``url`` (Windsurf: ``serverUrl``) is a
Streamable HTTP server, or legacy SSE when its ``type``/``transport`` says ``sse``. Entries marked
``"disabled": true`` are skipped. JSON with comments and trailing commas (JSONC) is accepted.

``env`` values and HTTP ``headers`` are handed to the server exactly as configured, because the
server needs them to start. They often hold real credentials, so they are never printed, logged,
or written to a pin file; :meth:`ServerSpec.display_target` masks secret-looking arguments too.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from guardbench.domain.errors import InspectionError
from guardbench.runtime.redaction import Redactor

Transport = Literal["stdio", "http", "sse"]

MAX_CONFIG_BYTES = 20 * 1024 * 1024  # ~/.claude.json also stores history and can be several MB
MAX_SERVERS = 200
_SECRETISH = re.compile(r"(?i)(token|secret|passw(or)?d|api[-_]?key|auth|credential|bearer)")
_VAR = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}")
_MASK = "***"
_redactor = Redactor()


@dataclass(frozen=True, slots=True)
class ServerSpec:
    """One MCP server as configured by the user. ``env`` and ``headers`` never leave this object."""

    name: str
    transport: Transport
    source: str
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict, repr=False)
    cwd: str | None = None
    url: str | None = field(default=None, repr=False)
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)

    def display_target(self) -> str:
        """What will be started or contacted, safe to print: secrets in arguments and URLs are masked."""
        if self.transport == "stdio":
            return " ".join([self.command or "", *mask_args(self.args)]).strip()
        return safe_url(self.url or "")

    def secret_values(self) -> list[str]:
        """Configured values that must never appear in output: env values, header values, masked arguments,
        and URL userinfo/query. Used to scrub a server's own error output, which may echo them."""
        values = [*self.env.values(), *self.headers.values()]
        values.extend(arg for arg, shown in zip(self.args, mask_args(self.args), strict=True) if arg != shown)
        if self.url:
            parts = urlsplit(self.url)
            values.extend(v for v in (parts.password, parts.username, parts.query) if v)
        for value in list(values):
            if "=" in value:
                values.append(value.split("=", 1)[1])
        return sorted({v for v in values if len(v) >= 4}, key=len, reverse=True)

    def scrub(self, text: str) -> str:
        """``text`` with every configured secret value and credential shape masked."""
        for value in self.secret_values():
            text = text.replace(value, _MASK)
        return _redactor.scrub_credentials_text(text)


@dataclass(frozen=True, slots=True)
class ConfigLoad:
    """The servers read from one config file, plus entries that could not be understood."""

    source: str
    client: str
    servers: list[ServerSpec]
    problems: list[str]


# --------------------------------------------------------------------------- masking


def mask_args(args: tuple[str, ...] | list[str]) -> list[str]:
    """Mask values that look like secrets: ``--token=x``, ``--api-key x``, credential shapes, URL userinfo."""
    masked: list[str] = []
    hide_next = False
    for arg in args:
        if hide_next:
            masked.append(_MASK)
            hide_next = False
            continue
        if arg.startswith("-") and "=" in arg and _SECRETISH.search(arg.split("=", 1)[0]):
            masked.append(arg.split("=", 1)[0] + "=" + _MASK)
            continue
        if arg.startswith("-") and _SECRETISH.search(arg):
            masked.append(arg)
            hide_next = True
            continue
        if "://" in arg:
            arg = safe_url(arg)
        masked.append(_redactor.scrub_credentials_text(arg))
    return masked


def safe_url(url: str) -> str:
    """``url`` without userinfo, query, or fragment (any of which can carry a credential)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparsable URL>"
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    tail = "?..." if parts.query else ""
    return (
        f"{parts.scheme}://{host}{parts.path}{tail}"
        if parts.scheme
        else _redactor.scrub_credentials_text(url)
    )


# --------------------------------------------------------------------------- JSONC


def _strip_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments outside of strings."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_str = c != '"'
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise InspectionError("unterminated /* comment")
            i = end + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    """Remove a comma directly before ``}`` or ``]`` (whitespace allowed), outside of strings."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_str = c != '"'
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def load_json_file(path: Path, *, what: str = "file") -> Any:
    """Read a JSON (or JSONC) file with a size limit. Errors never echo the file's content."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InspectionError(f"cannot read {what} {path}: {exc.strerror or type(exc).__name__}") from exc
    if size > MAX_CONFIG_BYTES:
        raise InspectionError(f"{what} {path} is larger than {MAX_CONFIG_BYTES // (1024 * 1024)} MB")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise InspectionError(f"cannot read {what} {path}: {type(exc).__name__}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_strip_trailing_commas(_strip_comments(text)))
    except json.JSONDecodeError as exc:
        raise InspectionError(
            f"{what} {path} is not valid JSON (line {exc.lineno}, column {exc.colno})"
        ) from exc


# --------------------------------------------------------------------------- parsing


def _expand(value: str, variables: Mapping[str, str]) -> str:
    """Expand ``${VAR}`` and ``${env:VAR}``; unknown variables are left as written."""
    return _VAR.sub(lambda m: variables.get(m.group(1), m.group(0)), value)


def _string_map(raw: Any, what: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise InspectionError(f"'{what}' must be an object")
    out: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(value, str | int | float | bool):
            raise InspectionError(f"'{what}.{key}' must be a string")
        out[str(key)] = str(value).lower() if isinstance(value, bool) else str(value)
    return out


def parse_entry(name: str, raw: Any, source: str, variables: Mapping[str, str]) -> ServerSpec | None:
    """Turn one config entry into a :class:`ServerSpec`; ``None`` for a disabled entry."""
    if not isinstance(raw, dict):
        raise InspectionError("entry must be an object")
    if raw.get("disabled") is True or raw.get("enabled") is False:
        return None
    kind = str(raw.get("type") or raw.get("transport") or "").lower().replace("_", "-")
    command, url = raw.get("command"), raw.get("url") or raw.get("serverUrl")

    if command is not None:
        if not isinstance(command, str) or not command.strip():
            raise InspectionError("'command' must be a non-empty string")
        if kind not in {"", "stdio"}:
            raise InspectionError(f"has a 'command' but its type is {kind!r}")
        args = raw.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str | int | float) for a in args):
            raise InspectionError("'args' must be a list of strings")
        cwd = raw.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise InspectionError("'cwd' must be a string")
        return ServerSpec(
            name=name,
            transport="stdio",
            source=source,
            command=_expand(command, variables),
            args=tuple(_expand(str(a), variables) for a in args),
            env={k: _expand(v, variables) for k, v in _string_map(raw.get("env"), "env").items()},
            cwd=_expand(cwd, variables) if cwd else None,
        )

    if url is not None:
        if not isinstance(url, str):
            raise InspectionError("'url' must be a string")
        url = _expand(url, variables)
        if urlsplit(url).scheme not in {"http", "https"}:
            raise InspectionError("'url' must be an http:// or https:// URL")
        if kind not in {"", "http", "streamable-http", "streamablehttp", "sse"}:
            raise InspectionError(f"unsupported transport type {kind!r}")
        headers = {k: _expand(v, variables) for k, v in _string_map(raw.get("headers"), "headers").items()}
        return ServerSpec(
            name=name, transport="sse" if kind == "sse" else "http", source=source, url=url, headers=headers
        )

    raise InspectionError("has neither 'command' (stdio) nor 'url' (HTTP)")


def _server_table(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    for candidate in (data.get("mcpServers"), data.get("servers")):
        if isinstance(candidate, dict):
            return candidate
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        servers: dict[str, Any] = mcp["servers"]
        return servers
    return None


def load_config(
    path: Path, *, client: str = "config", environ: Mapping[str, str] | None = None
) -> ConfigLoad:
    """Read every server from one MCP client config file.

    A config with no recognizable server table raises :class:`InspectionError`. Individual entries
    that cannot be understood are reported in ``problems`` so the other servers are still inspected.
    """
    source = str(path)
    table = _server_table(load_json_file(path, what="MCP config"))
    if table is None:
        raise InspectionError(
            f"{path} has no MCP server table (expected 'mcpServers', 'servers', or 'mcp.servers')"
        )
    if len(table) > MAX_SERVERS:
        raise InspectionError(f"{path} defines more than {MAX_SERVERS} servers")
    workspace = path.resolve().parent
    if workspace.name in {".vscode", ".cursor"}:
        workspace = workspace.parent
    variables = {**(os.environ if environ is None else environ), "workspaceFolder": str(workspace)}

    servers: list[ServerSpec] = []
    problems: list[str] = []
    for name, raw in table.items():
        try:
            spec = parse_entry(str(name), raw, source, variables)
        except InspectionError as exc:
            problems.append(f"server {name!r}: {exc}")
            continue
        if spec is not None:
            servers.append(spec)
    return ConfigLoad(source=source, client=client, servers=servers, problems=problems)


# --------------------------------------------------------------------------- discovery


def known_config_locations(
    home: Path, cwd: Path, *, platform: str = sys.platform, appdata: str | None = None
) -> list[tuple[str, Path]]:
    """Well-known MCP client config files for this platform (whether or not they exist)."""
    if platform == "darwin":
        app_support = home / "Library" / "Application Support"
        claude_desktop, vscode_user = app_support / "Claude", app_support / "Code" / "User"
    elif platform.startswith("win"):
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
        claude_desktop, vscode_user = base / "Claude", base / "Code" / "User"
    else:
        claude_desktop, vscode_user = home / ".config" / "Claude", home / ".config" / "Code" / "User"
    return [
        ("Claude Desktop", claude_desktop / "claude_desktop_config.json"),
        ("Claude Code (user)", home / ".claude.json"),
        ("Claude Code (project)", cwd / ".mcp.json"),
        ("Cursor (user)", home / ".cursor" / "mcp.json"),
        ("Cursor (project)", cwd / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("VS Code (user)", vscode_user / "mcp.json"),
        ("VS Code (workspace)", cwd / ".vscode" / "mcp.json"),
    ]


def discover_configs(
    home: Path | None = None, cwd: Path | None = None, *, platform: str = sys.platform
) -> list[tuple[str, Path]]:
    """The well-known config files that exist on this machine."""
    locations = known_config_locations(
        home or Path.home(), cwd or Path.cwd(), platform=platform, appdata=os.environ.get("APPDATA")
    )
    return [(client, path) for client, path in locations if path.is_file()]
