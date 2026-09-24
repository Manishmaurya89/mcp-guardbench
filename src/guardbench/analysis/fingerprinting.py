"""Canonical JSON normalization and SHA-256 fingerprints for tool definitions.

A fingerprint answers exactly one question: *has this definition changed since the one
I pinned?* It does **not** prove the server is trustworthy: a malicious first snapshot
hashes just as cleanly as a benign one. Trust must be established out of band.

Normalization rules
-------------------
* Object keys are sorted; output uses compact separators and no NaN/Infinity.
* Unicode is NFC-normalized and whitespace runs collapse to one space, but only in
  human-readable prose fields (``description``, ``title``, ``$comment``). Other strings
  (``enum``, ``pattern``, ``const``, ``default``, ``examples``) are preserved exactly.
* Set-like arrays (``required``, scalar ``enum``, list-valued ``type``) are sorted so
  reordering alone is not reported as a change. Every other array keeps its order.
* Observation timestamps, database IDs, and server IDs never enter a hash.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

from guardbench.domain.schemas import ServerIdentity, ToolDefinitionData, ToolSnapshotData

#: Keys whose string values are prose: whitespace is normalized, not semantically relevant.
PROSE_KEYS = frozenset({"description", "title", "$comment"})
#: Keys whose array values are unordered sets.
SET_LIKE_KEYS = frozenset({"required", "enum", "type"})

_WS_RE = re.compile(r"\s+")
MAX_NORMALIZE_DEPTH = 64


def normalize_text(text: str) -> str:
    """NFC-normalize and collapse whitespace runs (prose fields only)."""
    return _WS_RE.sub(" ", unicodedata.normalize("NFC", text)).strip()


def canonical_json(value: Any) -> str:
    """Serialize ``value`` deterministically: sorted keys, compact, UTF-8 friendly, no NaN."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(text: str) -> str:
    """Hex SHA-256 of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sort_key(item: Any) -> str:
    return canonical_json(item)


def normalize_schema(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Recursively normalize a JSON-Schema-like value per the rules in the module docstring."""
    if depth > MAX_NORMALIZE_DEPTH:
        raise ValueError(f"schema nesting exceeds {MAX_NORMALIZE_DEPTH} levels")
    if isinstance(value, dict):
        # Property *names* under "properties" are data, not schema keywords: never treat them as prose keys.
        return {
            str(k): normalize_schema(v, key=str(k) if not _is_property_map(key) else None, depth=depth + 1)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, list):
        items = [normalize_schema(v, key=None, depth=depth + 1) for v in value]
        if key in SET_LIKE_KEYS and all(isinstance(v, str | int | float | bool) or v is None for v in items):
            return sorted(items, key=_sort_key)
        return items
    if isinstance(value, str):
        return normalize_text(value) if key in PROSE_KEYS else unicodedata.normalize("NFC", value)
    return value


def _is_property_map(key: str | None) -> bool:
    return key in {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}


def normalize_tool(tool: ToolDefinitionData) -> dict[str, Any]:
    """Canonical dict for one tool. Contains no timestamps or identifiers."""
    return {
        "name": unicodedata.normalize("NFC", tool.name),
        "title": normalize_text(tool.title) if tool.title else None,
        "description": normalize_text(tool.description) if tool.description else None,
        "input_schema": normalize_schema(tool.input_schema),
        "output_schema": normalize_schema(tool.output_schema) if tool.output_schema is not None else None,
        "annotations": normalize_schema(tool.annotations),
        "meta": normalize_schema(tool.meta),
    }


def hash_tool(tool: ToolDefinitionData) -> str:
    """SHA-256 fingerprint of one tool's canonical definition."""
    return sha256_hex(canonical_json(normalize_tool(tool)))


def hash_normalized_tool(normalized: dict[str, Any]) -> str:
    """Fingerprint of an already-normalized tool dict (used when re-reading stored snapshots)."""
    return sha256_hex(canonical_json(normalized))


def hash_tool_set(tool_hashes: dict[str, str]) -> str:
    """Fingerprint of a server's complete tool set, independent of listing order."""
    return sha256_hex(canonical_json({"tools": tool_hashes}))


def build_snapshot(
    server_name: str,
    tools: list[ToolDefinitionData],
    identity: ServerIdentity | None = None,
) -> ToolSnapshotData:
    """Normalize and hash ``tools`` into a snapshot.

    Raises ``ValueError`` on duplicate tool names: a server advertising two tools with the
    same name is ambiguous and must not be silently collapsed.
    """
    names = [t.name for t in tools]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ValueError(f"duplicate tool names in one listing: {duplicates}")

    normalized = {t.name: normalize_tool(t) for t in tools}
    tool_hashes = {name: hash_normalized_tool(n) for name, n in normalized.items()}
    return ToolSnapshotData(
        server_name=server_name,
        identity=identity or ServerIdentity(name=server_name),
        normalized_tools=normalized,
        tool_hashes=tool_hashes,
        snapshot_hash=hash_tool_set(tool_hashes),
    )
