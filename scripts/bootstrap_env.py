#!/usr/bin/env python3
"""Create ``.env`` from ``.env.example`` with freshly generated random credentials.

    python scripts/bootstrap_env.py [--force]

* The API key and the PostgreSQL password are generated locally with :mod:`secrets`; nothing is
  fetched or sent anywhere, and the values are never printed.
* An existing ``.env`` is never overwritten unless ``--force`` is given.
* The file is created with mode 0600 (owner read/write only) and is git-ignored.
* Every value is a throwaway credential for this local lab. None of them is a real secret.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATED = {
    "GUARDBENCH_API_KEY": lambda: secrets.token_urlsafe(32),
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(24),
}


def render(template: str) -> str:
    """Return ``template`` with the generated credentials filled in (one line each)."""
    for name, make_value in GENERATED.items():
        template, count = re.subn(
            rf"^{name}=.*$", lambda _match, n=name, v=make_value: f"{n}={v()}", template, flags=re.MULTILINE
        )
        if count != 1:
            raise SystemExit(f".env.example must contain exactly one {name}= line (found {count})")
    return template


def bootstrap(root: Path = ROOT, *, force: bool = False) -> bool:
    """Write ``root/.env``. Returns ``False`` (and changes nothing) if it exists and ``force`` is off."""
    target = root / ".env"
    if target.exists() and not force:
        return False
    text = render((root / ".env.example").read_text(encoding="utf-8"))
    # O_EXCL-style safety without a race: create with 0600 from the start, never widen afterwards.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    descriptor = os.open(target, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    target.chmod(0o600)
    return True


def main(argv: list[str], root: Path | None = None) -> int:
    """CLI entry point (``root`` is injectable so tests never touch the real repository)."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    args = parser.parse_args(argv)
    if bootstrap(root or ROOT, force=args.force):
        sys.stdout.write(".env created with generated local-lab credentials (mode 0600, git-ignored).\n")
    else:
        sys.stdout.write(".env already exists; left unchanged (use --force to regenerate).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
