"""Test-case specification: the validated in-memory form of a ``test_cases/*.yaml`` file.

Structural and safety validation lives here. Checking that a fixture name is on the
lab allowlist needs the fixture registry, so the loader in ``guardbench.benchmark``
performs that step.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from guardbench.domain.enums import AttackStage, EvidenceKind, FindingCategory, SafeBehavior, Severity
from guardbench.domain.markers import MARKER_VALUES, find_credential_shapes

_ID_RE = re.compile(r"^[A-Z]{2,3}-\d{3}$")
_FIXTURE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_SCENARIO_STEPS = 20


class ScenarioAction(StrEnum):
    """Actions the deterministic simulated agent can take."""

    LIST_TOOLS = "list_tools"
    CALL_TOOL = "call_tool"
    ADVANCE_FIXTURE_STATE = "advance_fixture_state"


class ScenarioStep(BaseModel):
    """One scripted step of the simulated agent.

    ``if_model_context_contains`` models a gullible agent: the step only runs if the text
    is visible in the model context, so a control that keeps hostile text out of the
    context also prevents the follow-up action. No LLM is involved.
    """

    model_config = ConfigDict(extra="forbid")

    action: ScenarioAction
    tool: str | None = Field(default=None, max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)
    pin_baseline: bool = False
    if_model_context_contains: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _check_shape(self) -> ScenarioStep:
        if self.action is ScenarioAction.CALL_TOOL and not self.tool:
            raise ValueError("call_tool steps require a 'tool'")
        if self.action is not ScenarioAction.CALL_TOOL and (
            self.tool or self.arguments or self.if_model_context_contains
        ):
            raise ValueError(f"{self.action.value} steps take no tool, arguments, or condition")
        if self.pin_baseline and self.action is not ScenarioAction.LIST_TOOLS:
            raise ValueError("pin_baseline is only valid on list_tools steps")
        return self


class ExpectedOutcome(BaseModel):
    """What a *correct* security control should do for this test case."""

    model_config = ConfigDict(extra="forbid")

    should_detect: bool
    should_block: bool = False
    should_require_approval: bool = False
    should_call_sensitive_tool: bool = False
    required_evidence: list[EvidenceKind] = Field(default_factory=list)
    detection_categories: list[FindingCategory] = Field(default_factory=list)


class TestCaseSpec(BaseModel):
    """A validated, safe-by-construction test case."""

    __test__ = False  # not a pytest test class

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    name: str = Field(min_length=3, max_length=200)
    category: FindingCategory
    severity: Severity
    description: str = Field(min_length=10, max_length=4000)
    attack_stage: AttackStage
    server_fixture: str = Field(validation_alias=AliasChoices("server_fixture", "fixture"))
    synthetic_markers: list[str] = Field(default_factory=list)
    expected: ExpectedOutcome
    safe_behavior: list[SafeBehavior]
    tags: list[str] = Field(default_factory=list)
    scenario: list[ScenarioStep] = Field(default_factory=list)
    #: The case deliberately exercises the simulated-destructive path, so a delete may reach the
    #: approval step (still never auto-approved) instead of being denied outright when unattended.
    allow_simulated_destructive: bool = False
    enabled: bool = True

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("id must look like 'TP-001' (2-3 capital letters, dash, 3 digits)")
        return value

    @field_validator("server_fixture")
    @classmethod
    def _valid_fixture_name(cls, value: str) -> str:
        if not _FIXTURE_RE.match(value):
            raise ValueError("fixture must be a lowercase identifier, never a path or module")
        return value

    @field_validator("synthetic_markers")
    @classmethod
    def _only_synthetic_markers(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - MARKER_VALUES)
        if unknown:
            raise ValueError(
                f"unknown synthetic markers {unknown}; allowed: {sorted(MARKER_VALUES)}. "
                "Test cases may never carry real secrets."
            )
        return value

    @field_validator("safe_behavior")
    @classmethod
    def _baseline_safety(cls, value: list[SafeBehavior]) -> list[SafeBehavior]:
        missing = sorted(b.value for b in set(SafeBehavior) - set(value))
        if missing:
            raise ValueError(f"safe_behavior must declare every baseline constraint; missing {missing}")
        return value

    @field_validator("tags")
    @classmethod
    def _valid_tags(cls, value: list[str]) -> list[str]:
        for tag in value:
            if not re.match(r"^[a-z0-9][a-z0-9_\-]{0,40}$", tag):
                raise ValueError(f"invalid tag {tag!r}: use lowercase letters, digits, _ or -")
        return value

    @field_validator("scenario")
    @classmethod
    def _bounded_scenario(cls, value: list[ScenarioStep]) -> list[ScenarioStep]:
        if len(value) > MAX_SCENARIO_STEPS:
            raise ValueError(f"scenario has {len(value)} steps; the limit is {MAX_SCENARIO_STEPS}")
        for step in value:
            shapes = find_credential_shapes(step.arguments)
            if shapes:
                raise ValueError(
                    f"scenario arguments contain real-credential shapes {shapes}; use synthetic markers only"
                )
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> TestCaseSpec:
        benign = self.category is FindingCategory.BENIGN_CONTROL
        exp = self.expected
        if benign and (exp.should_detect or exp.should_block or exp.should_require_approval):
            raise ValueError("benign_control cases must expect no detection, blocking, or approval")
        if not benign and not exp.should_detect:
            raise ValueError(
                "attack cases must set expected.should_detect: true (use category benign_control otherwise)"
            )
        if exp.should_detect and not exp.required_evidence:
            raise ValueError("expected.required_evidence must list at least one evidence kind")
        if find_credential_shapes(self.description):
            raise ValueError("description contains a real-credential shape")
        return self

    @property
    def is_attack_case(self) -> bool:
        """True for cases whose correct outcome is detection; false for benign controls."""
        return self.category is not FindingCategory.BENIGN_CONTROL

    @property
    def effective_detection_categories(self) -> set[FindingCategory]:
        """Finding categories that count as a *correct* detection of this case."""
        return set(self.expected.detection_categories) or {self.category}
