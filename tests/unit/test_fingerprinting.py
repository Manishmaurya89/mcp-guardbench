"""Canonical JSON, normalization, and hashing of tool definitions."""

from __future__ import annotations

import math

import pytest

from guardbench.analysis.fingerprinting import (
    build_snapshot,
    canonical_json,
    hash_tool,
    hash_tool_set,
    normalize_schema,
    normalize_text,
    normalize_tool,
)
from guardbench.domain.schemas import ServerIdentity, ToolDefinitionData


def tool(**overrides: object) -> ToolDefinitionData:
    base: dict[str, object] = {
        "name": "get_events",
        "description": "Return events.",
        "input_schema": {
            "type": "object",
            "properties": {"day": {"type": "string", "description": "A day."}},
            "required": ["day"],
        },
    }
    base.update(overrides)
    return ToolDefinitionData(**base)  # type: ignore[arg-type]


def test_canonical_json_sorts_keys_and_is_compact() -> None:
    assert canonical_json({"b": 1, "a": {"d": 2, "c": [3, 1]}}) == '{"a":{"c":[3,1],"d":2},"b":1}'


def test_canonical_json_rejects_nan_so_hashes_stay_stable() -> None:
    with pytest.raises(ValueError, match="Out of range"):
        canonical_json({"x": math.nan})


def test_key_order_does_not_change_the_hash() -> None:
    a = tool(
        input_schema={"type": "object", "properties": {"x": {"type": "string"}, "y": {"type": "integer"}}}
    )
    b = tool(
        input_schema={"properties": {"y": {"type": "integer"}, "x": {"type": "string"}}, "type": "object"}
    )
    assert hash_tool(a) == hash_tool(b)


def test_whitespace_in_prose_is_normalized_but_not_in_semantic_values() -> None:
    assert hash_tool(tool(description="Return   events.\n")) == hash_tool(tool(description="Return events."))
    schema_a = {
        "type": "object",
        "properties": {"d": {"type": "string", "pattern": "^a b$", "description": "x  y"}},
    }
    schema_b = {
        "type": "object",
        "properties": {"d": {"type": "string", "pattern": "^a  b$", "description": "x y"}},
    }
    # the description differs only by whitespace (ignored) but the pattern differs by a space (relevant)
    assert hash_tool(tool(input_schema=schema_a)) != hash_tool(tool(input_schema=schema_b))
    schema_c = {
        "type": "object",
        "properties": {"d": {"type": "string", "pattern": "^a b$", "description": "x y"}},
    }
    assert hash_tool(tool(input_schema=schema_a)) == hash_tool(tool(input_schema=schema_c))


def test_enum_values_preserve_internal_whitespace() -> None:
    a = normalize_schema({"enum": ["a b", "c"]})
    b = normalize_schema({"enum": ["a  b", "c"]})
    assert a != b


def test_set_like_arrays_are_order_insensitive_but_other_arrays_are_not() -> None:
    assert normalize_schema({"required": ["b", "a"]}) == normalize_schema({"required": ["a", "b"]})
    assert normalize_schema({"enum": ["y", "x"]}) == normalize_schema({"enum": ["x", "y"]})
    assert normalize_schema({"oneOf": [{"const": 1}, {"const": 2}]}) != normalize_schema(
        {"oneOf": [{"const": 2}, {"const": 1}]}
    )


def test_property_named_description_is_not_treated_as_prose() -> None:
    schema = {"type": "object", "properties": {"description": {"type": "string", "enum": ["a  b"]}}}
    assert normalize_schema(schema)["properties"]["description"]["enum"] == ["a  b"]


def test_every_semantic_field_change_changes_the_hash() -> None:
    base = hash_tool(tool(annotations={"readOnlyHint": True}, meta={"guardbench/capabilities": ["read"]}))
    variants = [
        tool(
            name="get_event", annotations={"readOnlyHint": True}, meta={"guardbench/capabilities": ["read"]}
        ),
        tool(
            description="Return all events.",
            annotations={"readOnlyHint": True},
            meta={"guardbench/capabilities": ["read"]},
        ),
        tool(title="Events", annotations={"readOnlyHint": True}, meta={"guardbench/capabilities": ["read"]}),
        tool(annotations={"readOnlyHint": False}, meta={"guardbench/capabilities": ["read"]}),
        tool(annotations={"readOnlyHint": True}, meta={"guardbench/capabilities": ["read", "write"]}),
        tool(
            output_schema={"type": "object"},
            annotations={"readOnlyHint": True},
            meta={"guardbench/capabilities": ["read"]},
        ),
        tool(
            input_schema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True},
            meta={"guardbench/capabilities": ["read"]},
        ),
    ]
    hashes = {hash_tool(v) for v in variants}
    assert base not in hashes
    assert len(hashes) == len(variants)


def test_unicode_composition_is_normalized_but_lookalikes_are_not() -> None:
    # Built from explicit code points so the difference is visible in review.
    composed = "caf" + chr(0x00E9)  # e-acute as a single code point
    decomposed = "cafe" + chr(0x0301)  # e followed by a combining acute accent
    assert composed != decomposed
    assert hash_tool(tool(description=composed)) == hash_tool(tool(description=decomposed))
    lookalike = "p" + chr(0x0430) + "ypal"  # Cyrillic small a
    assert hash_tool(tool(description="paypal")) != hash_tool(tool(description=lookalike))


def test_normalize_text_collapses_whitespace() -> None:
    assert normalize_text("  a \t b\n\nc ") == "a b c"


def test_normalized_tool_contains_no_timestamps_or_ids() -> None:
    keys = set(normalize_tool(tool()))
    assert keys == {"name", "title", "description", "input_schema", "output_schema", "annotations", "meta"}


def test_hash_is_stable_across_repeated_calls_and_is_sha256_hex() -> None:
    t = tool()
    assert hash_tool(t) == hash_tool(t.model_copy(deep=True))
    assert len(hash_tool(t)) == 64
    int(hash_tool(t), 16)


def test_snapshot_hash_ignores_listing_order_and_creation_time() -> None:
    a, b = tool(name="a_tool"), tool(name="b_tool")
    s1 = build_snapshot("srv", [a, b])
    s2 = build_snapshot("srv", [b, a])
    assert s1.snapshot_hash == s2.snapshot_hash
    # the snapshot hash is a function of the per-tool hashes alone: no timestamp can leak in
    assert s1.snapshot_hash == hash_tool_set(s1.tool_hashes)
    assert set(s1.tool_hashes) == {"a_tool", "b_tool"}


def test_snapshot_hash_changes_when_any_tool_changes_or_is_removed() -> None:
    a, b = tool(name="a_tool"), tool(name="b_tool")
    full = build_snapshot("srv", [a, b]).snapshot_hash
    assert build_snapshot("srv", [a]).snapshot_hash != full
    assert build_snapshot("srv", [a, b.model_copy(update={"description": "changed"})]).snapshot_hash != full


def test_duplicate_tool_names_are_rejected_not_collapsed() -> None:
    with pytest.raises(ValueError, match="duplicate tool names"):
        build_snapshot("srv", [tool(), tool(description="different")])


def test_snapshot_records_server_identity_separately_from_the_tool_hash() -> None:
    v1 = build_snapshot("srv", [tool()], ServerIdentity(name="srv", version="1.0.0"))
    v2 = build_snapshot("srv", [tool()], ServerIdentity(name="srv", version="2.0.0"))
    assert v1.snapshot_hash == v2.snapshot_hash
    assert v1.identity.version != v2.identity.version


def test_overly_deep_schema_is_rejected() -> None:
    deep: dict[str, object] = {}
    node = deep
    for _ in range(100):
        child: dict[str, object] = {}
        node["properties"] = {"x": child}
        node = child
    with pytest.raises(ValueError, match="nesting"):
        normalize_schema(deep)
