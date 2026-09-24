"""YAML test-case validation, the corpus, and path confinement."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from guardbench.benchmark.test_case_loader import (
    MAX_CASE_BYTES,
    corpus_hash,
    load_test_case_file,
    load_test_cases,
    parse_test_case,
)
from guardbench.domain.enums import AttackStage, FindingCategory, Severity
from guardbench.domain.errors import PathNotAllowedError, TestCaseError
from guardbench.safe_paths import confine, resolve_within

TEST_CASES_DIR = Path(__file__).resolve().parents[2] / "test_cases"

BASE: dict[str, Any] = {
    "id": "TP-900",
    "name": "Hidden instruction in tool description",
    "category": "tool_poisoning",
    "severity": "high",
    "description": "A tool description contains an instruction unrelated to its purpose.",
    "attack_stage": "tools_list",
    "server_fixture": "poisoned_description_server",
    "synthetic_markers": ["TEST_SECRET_123"],
    "expected": {
        "should_detect": True,
        "should_block": True,
        "should_call_sensitive_tool": False,
        "required_evidence": ["tool_description", "detection_rule", "policy_decision"],
    },
    "safe_behavior": ["no_external_network", "no_real_secret", "no_destructive_action"],
    "tags": ["metadata", "prompt_injection"],
}


def dump(**changes: Any) -> str:
    doc = copy.deepcopy(BASE)
    for key, value in changes.items():
        if value is _DROP:
            doc.pop(key, None)
        else:
            doc[key] = value
    return yaml.safe_dump(doc)


_DROP = object()


def parse(**changes: Any):  # type: ignore[no-untyped-def]
    return parse_test_case(dump(**changes), source="t.yaml")


# ---------------------------------------------------------------- the shipped corpus


def test_the_shipped_corpus_loads_and_covers_every_required_case() -> None:
    cases = load_test_cases(TEST_CASES_DIR, allowed_root=TEST_CASES_DIR)
    ids = [c.spec.id for c in cases]
    assert ids == sorted(ids)
    assert {"TP-001", "TP-002", "RI-001", "RD-001", "DF-001", "PA-001", "RS-001"} <= set(ids)
    assert {c.spec.id for c in cases if not c.spec.is_attack_case} == {"BN-001", "BN-002"}


def test_every_shipped_case_declares_the_baseline_safety_constraints_and_uses_only_synthetic_markers() -> (
    None
):
    for case in load_test_cases(TEST_CASES_DIR, allowed_root=TEST_CASES_DIR):
        spec = case.spec
        assert {b.value for b in spec.safe_behavior} == {
            "no_external_network",
            "no_real_secret",
            "no_destructive_action",
        }
        assert set(spec.synthetic_markers) <= {
            "TEST_SECRET_123",
            "TEST_PRIVATE_RECORD",
            "SIMULATED_EXTERNAL_DESTINATION",
        }


def test_tp_001_matches_the_documented_format() -> None:
    spec = load_test_case_file(TEST_CASES_DIR / "TP-001-tool-description-injection.yaml").spec
    assert spec.category is FindingCategory.TOOL_POISONING
    assert spec.severity is Severity.HIGH
    assert spec.attack_stage is AttackStage.TOOLS_LIST
    assert spec.server_fixture == "poisoned_description_server"
    assert spec.expected.should_detect and spec.expected.should_block
    assert not spec.expected.should_call_sensitive_tool
    assert [e.value for e in spec.expected.required_evidence] == [
        "tool_description",
        "detection_rule",
        "policy_decision",
    ]


def test_every_attack_case_names_a_stage_a_category_and_evidence() -> None:
    for case in load_test_cases(TEST_CASES_DIR, allowed_root=TEST_CASES_DIR):
        if case.spec.is_attack_case:
            assert case.spec.expected.required_evidence, case.spec.id
            assert case.spec.scenario, case.spec.id


def test_the_corpus_hash_is_stable_and_changes_with_content(tmp_path: Path) -> None:
    cases = load_test_cases(TEST_CASES_DIR, allowed_root=TEST_CASES_DIR)
    assert corpus_hash(cases) == corpus_hash(list(reversed(cases)))
    folder = tmp_path / "cases"
    folder.mkdir()
    (folder / "a.yaml").write_text(dump(), encoding="utf-8")
    before = corpus_hash(load_test_cases(folder, allowed_root=tmp_path))
    (folder / "a.yaml").write_text(dump(name="Renamed hidden instruction case"), encoding="utf-8")
    assert corpus_hash(load_test_cases(folder, allowed_root=tmp_path)) != before


# ---------------------------------------------------------------- valid variations


def test_a_minimal_valid_case_parses() -> None:
    assert parse().id == "TP-900"


def test_the_fixture_key_is_accepted_as_an_alias() -> None:
    doc = yaml.safe_load(dump())
    doc["fixture"] = doc.pop("server_fixture")
    assert parse_test_case(yaml.safe_dump(doc)).server_fixture == "poisoned_description_server"


def test_a_benign_control_needs_no_evidence() -> None:
    spec = parse(
        category="benign_control",
        expected={"should_detect": False},
        synthetic_markers=[],
    )
    assert not spec.is_attack_case


def test_detection_categories_default_to_the_case_category_and_can_be_overridden() -> None:
    assert parse().effective_detection_categories == {FindingCategory.TOOL_POISONING}
    widened = parse(expected={**BASE["expected"], "detection_categories": ["tool_poisoning", "schema_risk"]})
    assert widened.effective_detection_categories == {
        FindingCategory.TOOL_POISONING,
        FindingCategory.SCHEMA_RISK,
    }


# ---------------------------------------------------------------- invalid cases


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        ({"id": "tp-1"}, "id"),
        ({"id": "TOOLPOISON-001"}, "id"),
        ({"category": "made_up"}, "category"),
        ({"severity": "extreme"}, "severity"),
        ({"attack_stage": "somewhere"}, "attack_stage"),
        ({"server_fixture": _DROP}, "server_fixture"),
        ({"server_fixture": "os"}, "allowlist"),
        ({"server_fixture": "../../etc/passwd"}, "identifier"),
        ({"server_fixture": "Clean_Server"}, "identifier"),
        ({"synthetic_markers": ["REAL_SECRET_999"]}, "unknown synthetic markers"),
        ({"safe_behavior": ["no_external_network"]}, "baseline constraint"),
        ({"safe_behavior": []}, "baseline constraint"),
        ({"expected": _DROP}, "expected"),
        ({"expected": {"should_detect": True}}, "required_evidence"),
        ({"expected": {"should_detect": False}}, "should_detect: true"),
        ({"expected": {**BASE["expected"], "surprise": 1}}, "surprise"),
        ({"expected": {**BASE["expected"], "required_evidence": ["invented_evidence"]}}, "required_evidence"),
        ({"surprise_key": 1}, "surprise_key"),
        ({"tags": ["Has Space"]}, "invalid tag"),
        ({"name": "x"}, "name"),
        ({"description": "short"}, "description"),
        ({"description": "token AKIA" + "ABCDEFGHIJKLMNOP is in here"}, "credential"),
    ],
)
def test_invalid_cases_are_rejected_with_a_useful_message(changes: dict[str, Any], fragment: str) -> None:
    with pytest.raises(TestCaseError, match=fragment):
        parse(**changes)


def test_a_benign_case_may_not_expect_a_reaction() -> None:
    with pytest.raises(TestCaseError, match="benign_control"):
        parse(category="benign_control", expected={"should_detect": False, "should_block": True})


def test_a_benign_case_may_not_expect_detection() -> None:
    with pytest.raises(TestCaseError):
        parse(
            category="benign_control",
            expected={"should_detect": True, "required_evidence": ["detection_rule"]},
        )


@pytest.mark.parametrize(
    ("scenario", "fragment"),
    [
        ([{"action": "call_tool"}], "require a 'tool'"),
        ([{"action": "list_tools", "tool": "x"}], "take no tool"),
        ([{"action": "advance_fixture_state", "arguments": {"a": 1}}], "take no tool"),
        ([{"action": "call_tool", "tool": "t", "pin_baseline": True}], "pin_baseline"),
        ([{"action": "explode"}], "action"),
        ([{"action": "list_tools"}] * 21, "limit"),
        (
            [{"action": "call_tool", "tool": "t", "arguments": {"k": "AKIA" + "ABCDEFGHIJKLMNOP"}}],
            "real-credential",
        ),
        ([{"action": "call_tool", "tool": "t", "arguments": {"h": "Bearer " + "a" * 30}}], "real-credential"),
    ],
)
def test_scenario_steps_are_validated(scenario: list[dict[str, Any]], fragment: str) -> None:
    with pytest.raises(TestCaseError, match=fragment):
        parse(scenario=scenario)


def test_scenarios_may_use_the_last_result_token_and_synthetic_markers() -> None:
    spec = parse(
        scenario=[
            {"action": "list_tools", "pin_baseline": True},
            {
                "action": "call_tool",
                "tool": "t",
                "arguments": {"body": "$LAST_RESULT", "d": "SIMULATED_EXTERNAL_DESTINATION"},
            },
        ]
    )
    assert spec.scenario[1].arguments["body"] == "$LAST_RESULT"


def test_malformed_and_non_mapping_and_oversized_yaml_are_rejected() -> None:
    with pytest.raises(TestCaseError, match="invalid YAML"):
        parse_test_case("id: [unclosed", source="bad.yaml")
    with pytest.raises(TestCaseError, match="mapping"):
        parse_test_case("- just\n- a list\n", source="list.yaml")
    with pytest.raises(TestCaseError, match="larger than"):
        parse_test_case(b"#" * (MAX_CASE_BYTES + 1), source="big.yaml")


def test_yaml_cannot_execute_python_objects() -> None:
    evil = "id: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(TestCaseError):
        parse_test_case(evil, source="evil.yaml")


def test_error_messages_name_the_file() -> None:
    with pytest.raises(TestCaseError, match=r"broken\.yaml"):
        parse_test_case(dump(severity="nope"), source="broken.yaml")


# ---------------------------------------------------------------- loader and paths


def test_the_loader_rejects_directories_outside_the_allowed_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.yaml").write_text(dump(), encoding="utf-8")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    with pytest.raises(PathNotAllowedError):
        load_test_cases(outside, allowed_root=allowed)
    with pytest.raises(PathNotAllowedError):
        load_test_cases(allowed / ".." / "outside", allowed_root=allowed)


def test_a_symlinked_case_that_points_outside_the_root_is_refused(tmp_path: Path) -> None:
    secret_dir = tmp_path / "elsewhere"
    secret_dir.mkdir()
    (secret_dir / "x.yaml").write_text(dump(), encoding="utf-8")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    os.symlink(secret_dir / "x.yaml", allowed / "link.yaml")
    with pytest.raises(PathNotAllowedError):
        load_test_cases(allowed, allowed_root=allowed)


def test_a_missing_directory_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(TestCaseError, match="does not exist"):
        load_test_cases(tmp_path / "nope", allowed_root=tmp_path)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(dump(), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(dump(name="Same id, different file name here"), encoding="utf-8")
    with pytest.raises(TestCaseError, match="duplicate test case id TP-900"):
        load_test_cases(tmp_path, allowed_root=tmp_path)


def test_one_bad_file_fails_the_whole_load_loudly_rather_than_being_skipped(tmp_path: Path) -> None:
    (tmp_path / "good.yaml").write_text(dump(), encoding="utf-8")
    (tmp_path / "bad.yaml").write_text(dump(id="nope"), encoding="utf-8")
    with pytest.raises(TestCaseError, match=r"bad\.yaml"):
        load_test_cases(tmp_path, allowed_root=tmp_path)


def test_non_yaml_files_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(dump(), encoding="utf-8")
    (tmp_path / "notes.md").write_text("# hi", encoding="utf-8")
    (tmp_path / "script.py").write_text("raise SystemExit(1)", encoding="utf-8")
    assert [c.spec.id for c in load_test_cases(tmp_path, allowed_root=tmp_path)] == ["TP-900"]


def test_confine_and_resolve_within(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.yaml").write_text("x", encoding="utf-8")
    assert confine(root / "ok.yaml", root) == (root / "ok.yaml").resolve()
    assert resolve_within(root, "ok.yaml") == (root / "ok.yaml").resolve()
    for bad in ("../outside.yaml", "/etc/passwd", "sub/../../x", "a\x00b"):
        with pytest.raises(PathNotAllowedError):
            resolve_within(root, bad)
    with pytest.raises(PathNotAllowedError):
        confine(tmp_path, root)
    assert confine(root, root) == root.resolve()
