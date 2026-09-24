"""The pin file: tool fingerprints the user approved, used to catch later changes (rug pulls).

A pin file is plain, diff-friendly JSON meant to be committed next to the MCP config it
describes, like a lockfile. It holds only what the *server* advertised (normalized tool
definitions, their SHA-256 hashes, the server's self-reported identity), never the command,
environment, URL, or headers from the config.

Pinning records a decision; it is not a safety check. A server that was malicious when it was
pinned produces a perfectly stable fingerprint (see ``docs/limitations.md``).
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardbench import __version__
from guardbench.analysis.fingerprinting import hash_normalized_tool, hash_tool_set
from guardbench.domain.clock import utc_now
from guardbench.domain.errors import InspectionError
from guardbench.domain.schemas import ToolSnapshotData
from guardbench.inspection.configs import load_json_file


class PinnedServer(BaseModel):
    """One approved server snapshot."""

    model_config = ConfigDict(extra="forbid")

    pinned_at: datetime
    snapshot: ToolSnapshotData


class PinFile(BaseModel):
    """All approved snapshots, keyed by server name."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["mcp-guardbench-pins"] = "mcp-guardbench-pins"
    version: Literal[1] = 1
    generated_by: str = f"mcp-guardbench {__version__}"
    servers: dict[str, PinnedServer] = Field(default_factory=dict)

    def pin(self, snapshot: ToolSnapshotData) -> None:
        """Approve ``snapshot`` as the new baseline for its server."""
        self.servers[snapshot.server_name] = PinnedServer(pinned_at=utc_now(), snapshot=snapshot)


def _check_integrity(name: str, snapshot: ToolSnapshotData) -> None:
    """Recompute every hash; a hand-edited or corrupted pin must not silently become the baseline."""
    for tool, normalized in snapshot.normalized_tools.items():
        if hash_normalized_tool(normalized) != snapshot.tool_hashes.get(tool):
            raise InspectionError(
                f"pin for server {name!r} is inconsistent: tool {tool!r} does not match its hash"
            )
    if set(snapshot.tool_hashes) != set(snapshot.normalized_tools):
        raise InspectionError(f"pin for server {name!r} is inconsistent: tool list and hashes differ")
    if hash_tool_set(snapshot.tool_hashes) != snapshot.snapshot_hash:
        raise InspectionError(f"pin for server {name!r} is inconsistent: tool-set hash does not match")


def load_pins(path: Path) -> PinFile | None:
    """Read and verify a pin file; ``None`` if it does not exist."""
    if not path.exists():
        return None
    try:
        pins = PinFile.model_validate(load_json_file(path, what="pin file"))
    except ValidationError as exc:
        raise InspectionError(
            f"pin file {path} is not a valid MCP-GuardBench pin file ({exc.error_count()} error(s))"
        ) from exc
    for name, pinned in pins.servers.items():
        _check_integrity(name, pinned.snapshot)
    return pins


def save_pins(pins: PinFile, path: Path) -> None:
    """Write atomically (temp file + rename) as stable, sorted, indented JSON."""
    text = json.dumps(pins.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    directory = path.resolve().parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pins-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
