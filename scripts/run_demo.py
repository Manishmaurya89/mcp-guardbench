#!/usr/bin/env python3
"""Run the demo benchmark and write reports to ``reports/demo-run/``.

Equivalent to::

    guardbench benchmark run --project demo --cases test_cases/ \\
        --adapter no-defense-baseline --adapter reference-static --adapter reference-runtime \\
        --output reports/demo-run/

Results come from the local reference fixtures. No external server is scanned.
"""

from __future__ import annotations

import sys

from guardbench.cli.main import app

ARGS = [
    "benchmark", "run", "--project", "demo", "--cases", "test_cases/",
    "--adapter", "no-defense-baseline", "--adapter", "reference-static", "--adapter", "reference-runtime",
    "--output", "reports/demo-run/",
]  # fmt: skip

if __name__ == "__main__":
    sys.exit(app(ARGS, standalone_mode=True) or 0)
