#!/usr/bin/env python3
"""Seed the local demo data (equivalent to ``guardbench seed-demo``). Synthetic fixtures only."""

from __future__ import annotations

import sys

from guardbench.cli.main import app

if __name__ == "__main__":
    sys.exit(app(["seed-demo"], standalone_mode=True) or 0)
