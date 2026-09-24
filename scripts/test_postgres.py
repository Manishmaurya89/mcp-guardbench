#!/usr/bin/env python3
"""Run the database-backed tests against a real PostgreSQL, with no Docker required.

Starts an embedded PostgreSQL (the ``pgserver`` package bundles the binaries) inside a temporary
directory, points ``GUARDBENCH_TEST_DATABASE_URL`` at it, runs pytest, and stops the server.

    pip install 'mcp-guardbench[pgtest]'
    python scripts/test_postgres.py [pytest args...]

Everything stays local: the server listens on a Unix socket in a temp directory.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def main(argv: list[str]) -> int:
    """Start Postgres, run the tests, always clean up."""
    try:
        import pgserver
    except ImportError:
        sys.stderr.write("pgserver is not installed. Run: pip install 'mcp-guardbench[pgtest]'\n")
        return 2
    import pytest

    with tempfile.TemporaryDirectory(prefix="guardbench-pg-") as data_dir:
        server = pgserver.get_server(Path(data_dir), cleanup_mode="stop")
        try:
            os.environ["GUARDBENCH_TEST_DATABASE_URL"] = server.get_uri()
            args = argv or ["tests/integration", "tests/security", "tests/unit/test_config_and_db.py", "-q"]
            return int(pytest.main(args))
        finally:
            server.cleanup()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
