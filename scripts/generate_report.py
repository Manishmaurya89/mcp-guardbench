#!/usr/bin/env python3
"""Print the latest run's Markdown report and write all formats to ``reports/latest/``.

Usage: ``python scripts/generate_report.py [RUN_ID]`` (defaults to the most recent finished run).
"""

from __future__ import annotations

import sys

from guardbench.cli.main import app


def main(argv: list[str]) -> int:
    """Write JSON, Markdown, and CSV reports, then print the Markdown."""
    selector = ["--run-id", argv[0]] if argv else ["--latest"]
    for fmt in ("json", "markdown", "csv"):
        code = app(
            ["report", *selector, "--format", fmt, "--output", "reports/latest/"], standalone_mode=False
        )
        if code:
            return int(code)
    return int(app(["report", *selector, "--format", "markdown"], standalone_mode=False) or 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
