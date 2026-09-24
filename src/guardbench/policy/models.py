"""Typed policy configuration and the runtime facts the engine decides on."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from guardbench.domain.enums import Capability, PolicyDecisionType, RunMode, Severity
from guardbench.domain.errors import PolicyError
from guardbench.domain.markers import SIMULATED_EXTERNAL_DESTINATION

DEFAULT_POLICY_PATH = Path(__file__).with_name("default_policy.yaml")
MAX_POLICY_BYTES = 64 * 1024

_STRICTNESS = {
    PolicyDecisionType.ALLOW: 0,
    PolicyDecisionType.ALLOW_WITH_WARNING: 1,
    PolicyDecisionType.REQUIRE_APPROVAL: 2,
    PolicyDecisionType.QUARANTINE: 3,
    PolicyDecisionType.DENY: 4,
}


def strictest(decisions: list[PolicyDecisionType]) -> PolicyDecisionType:
    """The most restrictive of ``decisions`` (deny > quarantine > require_approval > warn > allow)."""
    return max(decisions, key=_STRICTNESS.__getitem__, default=PolicyDecisionType.ALLOW)


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CapabilityRule(_Cfg):
    """What to do with a tool that has a given capability."""

    decision: PolicyDecisionType
    #: Decision used instead of ``decision`` when the run is unattended (nobody can approve).
    unattended_decision: PolicyDecisionType | None = None


class DriftPolicy(_Cfg):
    """How to treat a tool whose definition no longer matches its approved hash."""

    #: Decision when the drift is at or above ``quarantine_at``.
    on_high_severity: PolicyDecisionType = PolicyDecisionType.QUARANTINE
    #: Decision for lower-severity drift.
    on_low_severity: PolicyDecisionType = PolicyDecisionType.REQUIRE_APPROVAL
    quarantine_at: Severity = Severity.HIGH


class SecretPolicy(_Cfg):
    """Synthetic-marker handling."""

    block_outbound: bool = True
    #: Marker classes considered sensitive.
    sensitive_classes: list[str] = Field(default_factory=lambda: ["secret", "private_record"])


class ResponsePolicy(_Cfg):
    """Handling of tool responses before they reach the model context."""

    max_bytes: int = Field(default=4096, ge=256, le=1_000_000)
    quarantine_on_injection: bool = True


class PolicyConfig(_Cfg):
    """The complete, versioned runtime policy."""

    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    version: int = Field(ge=1)
    description: str = ""
    max_calls_per_trace: int = Field(default=10, ge=1, le=1000)
    synthetic_destinations: list[str] = Field(default_factory=lambda: [SIMULATED_EXTERNAL_DESTINATION])
    unknown_tool: PolicyDecisionType = PolicyDecisionType.DENY
    unapproved_tool: PolicyDecisionType = PolicyDecisionType.REQUIRE_APPROVAL
    unknown_capability: PolicyDecisionType = PolicyDecisionType.REQUIRE_APPROVAL
    #: ``server:tool`` entries explicitly allowed to write without approval.
    allow_write_tools: list[str] = Field(default_factory=list)
    capabilities: dict[Capability, CapabilityRule]
    drift: DriftPolicy = Field(default_factory=DriftPolicy)
    secrets: SecretPolicy = Field(default_factory=SecretPolicy)
    responses: ResponsePolicy = Field(default_factory=ResponsePolicy)

    @model_validator(mode="after")
    def _least_privilege(self) -> PolicyConfig:
        missing = sorted(c.value for c in set(Capability) - set(self.capabilities))
        if missing:
            raise ValueError(f"capabilities must define a rule for every capability; missing {missing}")
        for cap in (Capability.EXECUTE, Capability.DELETE):
            rule = self.capabilities[cap]
            for decision in (rule.decision, rule.unattended_decision):
                if decision in (PolicyDecisionType.ALLOW, PolicyDecisionType.ALLOW_WITH_WARNING):
                    raise ValueError(f"policy may not unconditionally allow the '{cap.value}' capability")
        if self.unknown_tool in (PolicyDecisionType.ALLOW, PolicyDecisionType.ALLOW_WITH_WARNING):
            raise ValueError("unknown tools must not be allowed; the default is deny")
        return self

    def canonical_hash(self) -> str:
        """SHA-256 of the canonical policy, recorded in reports for reproducibility."""
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def rule_for(self, capability: Capability, mode: RunMode) -> PolicyDecisionType:
        """The decision for ``capability`` given whether anyone can approve."""
        rule = self.capabilities[capability]
        if mode is RunMode.UNATTENDED and rule.unattended_decision is not None:
            return rule.unattended_decision
        return rule.decision


def load_policy(path: Path | None = None) -> PolicyConfig:
    """Load and validate a policy file (default: the bundled one). Uses ``yaml.safe_load`` only."""
    target = path or DEFAULT_POLICY_PATH
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {target}: {exc.strerror}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy file is larger than {MAX_POLICY_BYTES} bytes")
    try:
        data: Any = yaml.safe_load(raw)
        return PolicyConfig.model_validate(data)
    except (yaml.YAMLError, ValidationError) as exc:
        raise PolicyError(f"invalid policy {target.name}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ToolTrust:
    """What the runtime knows about one registered tool."""

    server_name: str
    tool_name: str
    capabilities: frozenset[Capability]
    approved: bool = False
    approved_hash: str | None = None
    current_hash: str | None = None
    quarantined: bool = False
    quarantine_reason: str | None = None
    drift_severity: Severity | None = None

    @property
    def key(self) -> str:
        """``server:tool`` identity used across the policy engine."""
        return f"{self.server_name}:{self.tool_name}"

    @property
    def drifted(self) -> bool:
        """An approved tool whose current definition no longer matches its pinned hash."""
        return self.approved_hash is not None and self.current_hash != self.approved_hash


@dataclass(slots=True)
class TrustStore:
    """The runtime registry of known tools. Instance-scoped and explicit: no globals."""

    _tools: dict[str, ToolTrust] = field(default_factory=dict)

    def register(self, tool: ToolTrust) -> None:
        """Add or replace a tool's trust record."""
        self._tools[tool.key] = tool

    def get(self, server_name: str, tool_name: str) -> ToolTrust | None:
        """The trust record for ``server_name:tool_name``, or ``None`` if never registered."""
        return self._tools.get(f"{server_name}:{tool_name}")

    def all(self) -> list[ToolTrust]:
        """All registered tools, sorted by key."""
        return [self._tools[k] for k in sorted(self._tools)]
