"""Run one allowlisted fixture as a real MCP server over stdio.

Usage::

    python -m guardbench.mcp_lab.server_runner --fixture clean_server

The fixture name is validated by ``argparse`` against the static allowlist, so it can never
be a path, module name, or command. The server speaks only over the process's own
stdin/stdout; it opens no sockets.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

import anyio
from mcp.server.stdio import stdio_server

from guardbench.mcp_lab.fixtures import create_fixture, fixture_names


async def serve_stdio(fixture_name: str) -> None:
    """Serve ``fixture_name`` until the client disconnects."""
    server = create_fixture(fixture_name).build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def build_parser() -> argparse.ArgumentParser:
    """Argument parser exposing only the fixture allowlist."""
    parser = argparse.ArgumentParser(
        prog="guardbench.mcp_lab.server_runner",
        description="Serve a local GuardBench lab fixture over MCP stdio. Synthetic data only.",
    )
    parser.add_argument("--fixture", required=True, choices=fixture_names(), help="Allowlisted fixture name")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    args = build_parser().parse_args(argv)
    anyio.run(serve_stdio, args.fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
