"""Schema traversal, severity calibration, and capability inference."""

from __future__ import annotations

from typing import Any

import pytest

from guardbench.analysis.capabilities import (
    domains_in_text,
    effective_capabilities,
    infer_from_name,
    profile_tool,
    tokenize_name,
)
from guardbench.analysis.schema_analyzer import (
    MAX_DEPTH,
    exceeds_depth,
    format_location,
    has_value_restriction,
    iter_object_schemas,
    iter_parameters,
    iter_text_sites,
    schema_string_types,
)
from guardbench.analysis.severity import aggregate, calibrate, is_actionable, max_severity, shift
from guardbench.domain.enums import Capability, FindingCategory, Severity
from guardbench.domain.schemas import CAPABILITIES_META_KEY, Finding, ToolDefinitionData


def finding(category: FindingCategory, severity: Severity) -> Finding:
    return Finding(rule_id="R", title="t", category=category, severity=severity, confidence=0.9)


# ---------------------------------------------------------------- severity


def test_shift_clamps_at_both_ends() -> None:
    assert shift(Severity.CRITICAL, 3) is Severity.CRITICAL
    assert shift(Severity.INFO, -3) is Severity.INFO
    assert shift(Severity.LOW, 1) is Severity.MEDIUM
    assert shift(Severity.HIGH, -2) is Severity.LOW


@pytest.mark.parametrize(
    ("base", "confidence", "expected"),
    [
        (Severity.HIGH, 0.95, Severity.HIGH),
        (Severity.HIGH, 0.5, Severity.HIGH),
        (Severity.HIGH, 0.49, Severity.MEDIUM),
        (Severity.HIGH, 0.29, Severity.LOW),
        (Severity.LOW, 0.1, Severity.INFO),
        (Severity.INFO, 0.0, Severity.INFO),
    ],
)
def test_calibrate_lowers_severity_as_confidence_falls(
    base: Severity, confidence: float, expected: Severity
) -> None:
    assert calibrate(base, confidence) is expected


def test_max_severity_and_default() -> None:
    assert max_severity([Severity.LOW, Severity.HIGH, Severity.MEDIUM]) is Severity.HIGH
    assert max_severity([]) is Severity.INFO
    assert max_severity([], default=Severity.LOW) is Severity.LOW


def test_aggregate_escalates_only_for_independent_categories() -> None:
    same_category = [finding(FindingCategory.TOOL_POISONING, Severity.HIGH)] * 2
    assert aggregate(same_category) is Severity.HIGH
    independent = [
        finding(FindingCategory.TOOL_POISONING, Severity.HIGH),
        finding(FindingCategory.EXCESSIVE_PERMISSION, Severity.MEDIUM),
    ]
    assert aggregate(independent) is Severity.CRITICAL
    weak_second = [
        finding(FindingCategory.TOOL_POISONING, Severity.HIGH),
        finding(FindingCategory.SCHEMA_RISK, Severity.LOW),
    ]
    assert aggregate(weak_second) is Severity.HIGH
    assert aggregate([]) is Severity.INFO


def test_is_actionable_uses_a_threshold() -> None:
    assert is_actionable(Severity.MEDIUM)
    assert not is_actionable(Severity.LOW)
    assert is_actionable(Severity.LOW, threshold=Severity.LOW)


# ---------------------------------------------------------------- schema traversal


def test_format_location_quotes_awkward_names() -> None:
    assert format_location(("inputSchema", "properties", "title", "description")) == (
        "inputSchema.properties.title.description"
    )
    assert format_location(("inputSchema", "enum", 2)) == "inputSchema.enum[2]"
    assert format_location(("_meta", "guardbench/note")) == "_meta['guardbench/note']"


def test_text_sites_cover_every_region() -> None:
    tool = ToolDefinitionData(
        name="n",
        title="T",
        description="D",
        input_schema={
            "type": "object",
            "properties": {
                "p": {
                    "type": "string",
                    "description": "PD",
                    "enum": ["e1"],
                    "default": "dv",
                    "x-hint": "ext",
                },
                "q": {"oneOf": [{"const": "c", "description": "OD"}]},
            },
            "required": ["p"],
        },
        output_schema={"type": "object", "properties": {"o": {"type": "string", "description": "OUT"}}},
        annotations={"title": "AT"},
        meta={"k": "MV"},
    )
    kinds = {(s.kind, s.text) for s in iter_text_sites(tool)}
    expected = {
        ("tool_name", "n"),
        ("tool_title", "T"),
        ("tool_description", "D"),
        ("param_name", "p"),
        ("param_description", "PD"),
        ("enum_value", "e1"),
        ("default_value", "dv"),
        ("schema_extension", "ext"),
        ("enum_description", "OD"),
        ("required_name", "p"),
        ("output_description", "OUT"),
        ("annotations_value", "AT"),
        ("meta_value", "MV"),
        ("meta_key", "k"),
    }
    assert expected <= kinds


def test_structural_string_keywords_are_not_text() -> None:
    tool = ToolDefinitionData(
        name="n",
        input_schema={
            "type": "object",
            "properties": {"d": {"type": "string", "format": "date", "$ref": "#/x"}},
        },
    )
    texts = {s.text for s in iter_text_sites(tool)}
    assert "date" not in texts
    assert "#/x" not in texts
    assert "object" not in texts


def test_a_property_named_description_is_a_name_not_prose() -> None:
    tool = ToolDefinitionData(
        name="n",
        input_schema={
            "type": "object",
            "properties": {"description": {"type": "string", "description": "real"}},
        },
    )
    sites = list(iter_text_sites(tool))
    assert any(s.kind == "param_name" and s.text == "description" for s in sites)
    assert any(s.kind == "param_description" and s.text == "real" for s in sites)


def test_ref_cycles_are_never_resolved() -> None:
    tool = ToolDefinitionData(
        name="n",
        input_schema={
            "type": "object",
            "properties": {"a": {"$ref": "#/$defs/a"}},
            "$defs": {"a": {"$ref": "#/$defs/a", "description": "loop"}},
        },
    )
    assert any(s.text == "loop" for s in iter_text_sites(tool))  # finishes, no recursion into $ref


def test_traversal_depth_is_bounded() -> None:
    deep: dict[str, Any] = {"description": "leaf"}
    for _ in range(MAX_DEPTH * 3):
        deep = {"properties": {"x": deep}}
    tool = ToolDefinitionData(name="n", input_schema={"type": "object", **deep})
    assert not any(s.text == "leaf" for s in iter_text_sites(tool))
    assert exceeds_depth(tool.input_schema)


def test_exceeds_depth_is_false_for_ordinary_schemas() -> None:
    assert not exceeds_depth({"type": "object", "properties": {"a": {"type": "object", "properties": {}}}})


def test_parameters_include_nested_objects_and_required_flags() -> None:
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "opts": {"type": "object", "properties": {"b": {"type": "integer"}}, "required": ["b"]},
        },
        "required": ["a"],
    }
    params = {p.name: p for p in iter_parameters(schema)}
    assert set(params) == {"a", "opts", "b"}
    assert params["a"].required
    assert not params["opts"].required
    assert params["b"].required
    assert params["b"].location == "inputSchema.properties.opts.properties.b"


def test_object_schema_iteration_marks_the_root() -> None:
    schema = {"type": "object", "properties": {"opts": {"type": "object", "properties": {}}}}
    nodes = list(iter_object_schemas(schema))
    assert nodes[0].is_root
    assert not nodes[1].is_root


def test_value_restriction_detection() -> None:
    assert has_value_restriction({"type": "string", "enum": ["a"]})
    assert has_value_restriction({"type": "string", "pattern": "^a$"})
    assert has_value_restriction({"type": "string", "format": "date"})
    assert not has_value_restriction({"type": "string"})
    assert not has_value_restriction({"type": "string", "maxLength": 5})
    assert schema_string_types({"type": ["string", "null"]})
    assert not schema_string_types({"type": "integer"})


# ---------------------------------------------------------------- capabilities


def test_tokenize_name_handles_camel_snake_and_kebab() -> None:
    assert tokenize_name("createCalendarEvent") == ["create", "calendar", "event"]
    assert tokenize_name("get_calendar-events") == ["get", "calendar", "events"]


def test_capability_inference_from_name_and_schema() -> None:
    assert infer_from_name("delete_record") == {Capability.DELETE}
    assert infer_from_name("send_and_save") == {Capability.SEND, Capability.WRITE}
    assert infer_from_name("frobnicate") == set()
    tool = ToolDefinitionData(
        name="helper",
        input_schema={
            "type": "object",
            "properties": {"command": {"type": "string"}, "webhook": {"type": "string"}},
        },
    )
    assert profile_tool(tool).inferred_from_schema == {Capability.EXECUTE, Capability.SEND}


def test_effective_capabilities_are_the_most_restrictive_union() -> None:
    tool = ToolDefinitionData(
        name="get_status",
        annotations={"readOnlyHint": True, "destructiveHint": True},
        meta={CAPABILITIES_META_KEY: ["read", "execute"]},
    )
    assert effective_capabilities(tool) == {Capability.READ, Capability.EXECUTE, Capability.DELETE}
    assert profile_tool(tool).claims_read_only


def test_unknown_capability_is_reported_as_unknown() -> None:
    assert not profile_tool(ToolDefinitionData(name="frobnicate")).is_known


def test_domain_detection_uses_whole_words_only() -> None:
    assert domains_in_text("read the calendar") == {"calendar"}
    assert domains_in_text("recalendarize") == set()
    assert domains_in_text("secret santa") == set()  # ambiguous words are deliberately excluded
    assert "credentials" in domains_in_text("ask for the password")
