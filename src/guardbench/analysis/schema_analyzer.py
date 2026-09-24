"""Schema traversal: enumerate every piece of text and every parameter in a tool definition.

Tool descriptions and schemas are *untrusted data*. This module never resolves ``$ref``,
never evaluates anything, and bounds depth and node count so a hostile schema cannot
exhaust the analyzer.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from guardbench.domain.schemas import ToolDefinitionData

MAX_DEPTH = 32
MAX_NODES = 5000
MAX_SCAN_CHARS = 20_000

#: String-valued keywords that carry structure, not human-readable content.
STRUCTURAL_STRING_KEYS = frozenset(
    {
        "type",
        "format",
        "$ref",
        "$schema",
        "$id",
        "$anchor",
        "$dynamicRef",
        "contentEncoding",
        "contentMediaType",
    }
)
PROSE_KEYS = frozenset({"description", "title", "$comment", "markdownDescription"})
ENUM_DESCRIPTION_KEYS = frozenset({"enumDescriptions", "x-enum-descriptions", "enumNames", "x-enum-varnames"})
PROPERTY_MAP_KEYS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
SUBSCHEMA_LIST_KEYS = frozenset({"oneOf", "anyOf", "allOf", "prefixItems"})

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class TextSite:
    """One piece of text found in a tool definition, with where it came from."""

    location: str
    kind: str
    text: str
    region: str  # "tool", "input", "output", "annotations", "meta"


@dataclass(frozen=True, slots=True)
class ParamInfo:
    """One named parameter of an object schema."""

    name: str
    location: str
    schema: dict[str, Any]
    required: bool


@dataclass(frozen=True, slots=True)
class ObjectSchemaInfo:
    """An object-typed schema node."""

    location: str
    schema: dict[str, Any]
    is_root: bool


def format_location(parts: tuple[str | int, ...]) -> str:
    """Render a path like ``inputSchema.properties['a b'].description``."""
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        elif _IDENT_RE.match(part) or part.startswith("$"):
            out += f".{part}" if out else part
        else:
            out += f"[{part!r}]"
    return out


class _Budget:
    """Shared node counter so one hostile schema cannot run away."""

    def __init__(self, limit: int = MAX_NODES) -> None:
        self.remaining = limit

    def spend(self) -> bool:
        self.remaining -= 1
        return self.remaining >= 0


def _kind_for(key: str, region: str, in_property: bool) -> str:
    if key in PROSE_KEYS:
        if region == "output":
            return "output_description"
        return "param_description" if in_property else "schema_description"
    return {
        "default": "default_value",
        "const": "const_value",
        "examples": "example_value",
        "example": "example_value",
    }.get(key, "schema_extension")


def iter_text_sites(tool: ToolDefinitionData) -> Iterator[TextSite]:
    """Yield every text-bearing location in ``tool``: name, prose, schemas, annotations, meta."""
    yield TextSite("name", "tool_name", tool.name, "tool")
    if tool.title:
        yield TextSite("title", "tool_title", tool.title, "tool")
    if tool.description:
        yield TextSite("description", "tool_description", tool.description, "tool")

    budget = _Budget()
    yield from _walk_schema(tool.input_schema, ("inputSchema",), "input", budget, 0, False)
    if tool.output_schema is not None:
        yield from _walk_schema(tool.output_schema, ("outputSchema",), "output", budget, 0, False)
    yield from _walk_free(tool.annotations, ("annotations",), "annotations", budget, 0)
    yield from _walk_free(tool.meta, ("_meta",), "meta", budget, 0)


def _walk_schema(
    node: Any,
    path: tuple[str | int, ...],
    region: str,
    budget: _Budget,
    depth: int,
    in_property: bool,
) -> Iterator[TextSite]:
    if depth > MAX_DEPTH or not budget.spend():
        return
    if isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_schema(item, (*path, i), region, budget, depth + 1, in_property)
        return
    if not isinstance(node, dict):
        return

    for key, value in node.items():
        key = str(key)
        child = (*path, key)
        if key in PROPERTY_MAP_KEYS and isinstance(value, dict):
            for prop_name, prop_schema in value.items():
                prop_path = (*child, str(prop_name))
                yield TextSite(format_location(prop_path), "param_name", str(prop_name), region)
                yield from _walk_schema(prop_schema, prop_path, region, budget, depth + 2, True)
        elif key == "enum" and isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, str):
                    yield TextSite(format_location((*child, i)), "enum_value", item, region)
        elif key in ENUM_DESCRIPTION_KEYS:
            for i, item in enumerate(value if isinstance(value, list) else [value]):
                if isinstance(item, str):
                    yield TextSite(format_location((*child, i)), "enum_description", item, region)
        elif key == "required" and isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, str):
                    yield TextSite(format_location((*child, i)), "required_name", item, region)
        elif isinstance(value, str):
            if key not in STRUCTURAL_STRING_KEYS and key != "pattern":
                kind = _kind_for(key, region, in_property)
                if kind == "param_description" and _looks_like_enum_option(node):
                    kind = "enum_description"
                yield TextSite(format_location(child), kind, value, region)
        elif isinstance(value, dict | list):
            yield from _walk_schema(value, child, region, budget, depth + 1, in_property)
        elif key in {"default", "const", "examples", "example"}:
            continue  # non-string scalar values carry no prose


def _looks_like_enum_option(node: dict[str, Any]) -> bool:
    """A ``{"const": ..., "description": ...}`` entry, the standard "enum with descriptions" idiom."""
    return "const" in node


def _walk_free(
    node: Any, path: tuple[str | int, ...], region: str, budget: _Budget, depth: int
) -> Iterator[TextSite]:
    """Walk annotations / _meta: every key and every string value is text."""
    if depth > MAX_DEPTH or not budget.spend():
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child = (*path, str(key))
            yield TextSite(format_location(child), f"{region}_key", str(key), region)
            yield from _walk_free(value, child, region, budget, depth + 1)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_free(item, (*path, i), region, budget, depth + 1)
    elif isinstance(node, str):
        yield TextSite(format_location(path), f"{region}_value", node, region)


def iter_object_schemas(schema: dict[str, Any], base: str = "inputSchema") -> Iterator[ObjectSchemaInfo]:
    """Yield every object-typed schema node (the root first), bounded by depth and node count."""
    yield from _object_nodes(schema, (base,), _Budget(), 0, True)


def _is_object_schema(node: dict[str, Any]) -> bool:
    node_type = node.get("type")
    return (
        node_type == "object"
        or (isinstance(node_type, list) and "object" in node_type)
        or "properties" in node
    )


def _object_nodes(
    node: Any, path: tuple[str | int, ...], budget: _Budget, depth: int, is_root: bool
) -> Iterator[ObjectSchemaInfo]:
    if depth > MAX_DEPTH or not budget.spend() or not isinstance(node, dict):
        return
    if _is_object_schema(node):
        yield ObjectSchemaInfo(format_location(path), node, is_root)
    props = node.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            yield from _object_nodes(sub, (*path, "properties", str(name)), budget, depth + 1, False)
    items = node.get("items")
    if isinstance(items, dict):
        yield from _object_nodes(items, (*path, "items"), budget, depth + 1, False)
    for key in SUBSCHEMA_LIST_KEYS:
        subs = node.get(key)
        if isinstance(subs, list):
            for i, sub in enumerate(subs):
                yield from _object_nodes(sub, (*path, key, i), budget, depth + 1, False)


def iter_parameters(schema: dict[str, Any], base: str = "inputSchema") -> Iterator[ParamInfo]:
    """Yield every declared parameter of every object schema in ``schema``."""
    for obj in iter_object_schemas(schema, base):
        props = obj.schema.get("properties")
        if not isinstance(props, dict):
            continue
        required = obj.schema.get("required")
        required_names = {r for r in required if isinstance(r, str)} if isinstance(required, list) else set()
        for name, sub in props.items():
            if isinstance(sub, dict):
                loc = (
                    f"{obj.location}.properties[{name!r}]"
                    if not _IDENT_RE.match(str(name))
                    else (f"{obj.location}.properties.{name}")
                )
                yield ParamInfo(str(name), loc, sub, str(name) in required_names)


def schema_string_types(schema: dict[str, Any]) -> bool:
    """True when the schema is a plain string (``type: string`` or a list containing it)."""
    node_type = schema.get("type")
    return node_type == "string" or (isinstance(node_type, list) and "string" in node_type)


def has_value_restriction(schema: dict[str, Any]) -> bool:
    """True when the string is constrained by enum, const, pattern, or a known format."""
    if any(k in schema for k in ("enum", "const", "pattern")):
        return True
    if any(k in schema for k in ("oneOf", "anyOf")):
        return True
    return schema.get("format") in {"date", "date-time", "time", "uuid", "email", "ipv4", "ipv6"}


def exceeds_depth(node: Any, limit: int = MAX_DEPTH) -> bool:
    """True when ``node`` nests deeper than ``limit`` (iterative, so hostile depth cannot recurse)."""
    stack: list[tuple[Any, int]] = [(node, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if depth > limit:
            return True
        if visited > MAX_NODES * 4:
            return False  # too wide to keep counting; the node budget elsewhere bounds analysis
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values() if isinstance(v, dict | list))
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current if isinstance(v, dict | list))
    return False


def truncate_for_scan(text: str) -> str:
    """Bound the text a regex will scan so pathological descriptions cannot stall analysis."""
    return text if len(text) <= MAX_SCAN_CHARS else text[:MAX_SCAN_CHARS]
