"""Pydantic v2 domain models: the normalized security concepts of GuardBench.

These are transport- and storage-agnostic. The database layer maps to and from
them; the API layer exposes them. Nothing here performs I/O.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardbench.domain.clock import utc_now
from guardbench.domain.enums import (
    ApprovalStatus,
    Capability,
    EvidenceKind,
    FindingCategory,
    FindingStatus,
    PolicyDecisionType,
    ResultStatus,
    RunMode,
    RunStatus,
    Severity,
    SourceType,
    TransportKind,
    TrustStatus,
)

#: ``_meta`` key under which fixtures declare a tool's capability classes.
CAPABILITIES_META_KEY = "guardbench/capabilities"

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\- ]{0,127}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")


class _Model(BaseModel):
    """Base with strict-ish defaults shared by all domain models."""

    model_config = ConfigDict(extra="forbid", from_attributes=True, use_enum_values=False)


# --------------------------------------------------------------------------- #
# Tool definitions and identity
# --------------------------------------------------------------------------- #


class ToolDefinitionData(_Model):
    """A tool exactly as a server advertised it. Always treated as untrusted data."""

    name: str = Field(min_length=1, max_length=256)
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)

    @property
    def declared_capabilities(self) -> list[Capability]:
        """Capabilities the server explicitly declared in ``_meta`` (unknown values dropped)."""
        raw = self.meta.get(CAPABILITIES_META_KEY, [])
        if not isinstance(raw, list):
            return []
        valid = {c.value for c in Capability}
        return sorted({Capability(v) for v in raw if isinstance(v, str) and v in valid})


class ServerIdentity(_Model):
    """Identity a server reported about itself. Self-reported, so not proof of trust."""

    name: str
    version: str | None = None
    protocol_version: str | None = None


class ToolSnapshotData(_Model):
    """Canonical, hashable picture of a server's complete tool set at one moment."""

    server_name: str
    identity: ServerIdentity
    normalized_tools: dict[str, dict[str, Any]]
    tool_hashes: dict[str, str]
    snapshot_hash: str
    created_at: datetime = Field(default_factory=utc_now)


# --------------------------------------------------------------------------- #
# Findings, decisions, events
# --------------------------------------------------------------------------- #


class Finding(_Model):
    """A normalized, explainable security finding with its evidence."""

    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str = ""
    location: str | None = None
    matched_evidence: str | None = None
    remediation: str = ""
    deterministic: bool = True
    server_name: str | None = None
    tool_name: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    evidence: dict[str, Any] = Field(default_factory=dict)
    evidence_event_ids: list[str] = Field(default_factory=list)
    detected_by: str | None = None
    test_case_id: str | None = None

    @property
    def has_evidence(self) -> bool:
        """A finding counts as evidenced if it points at a location or holds matched content."""
        return bool(self.matched_evidence or self.evidence or self.evidence_event_ids)


class PolicyDecision(_Model):
    """One deterministic runtime policy verdict, with everything needed to audit it."""

    policy_id: str
    decision: PolicyDecisionType
    reason: str
    matched_rule: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)
    trace_id: str

    @field_validator("trace_id")
    @classmethod
    def _valid_trace_id(cls, value: str) -> str:
        if not _TRACE_ID_RE.match(value):
            raise ValueError("trace_id must be 32 lowercase hex characters (OpenTelemetry format)")
        return value


class Event(_Model):
    """One normalized evidence event. Field names follow the OpenTelemetry-style trace model."""

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID | None = None
    trace_id: str
    span_id: str | None = None
    parent_event_id: UUID | None = None
    sequence: int = 0
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: str
    source: str
    server_name: str | None = None
    tool_name: str | None = None
    payload_json: dict[str, Any] = Field(default_factory=dict)
    redacted_payload_json: dict[str, Any] = Field(default_factory=dict)
    risk_tags: list[str] = Field(default_factory=list)
    decision: PolicyDecisionType | None = None

    @field_validator("trace_id")
    @classmethod
    def _valid_trace_id(cls, value: str) -> str:
        if not _TRACE_ID_RE.match(value):
            raise ValueError("trace_id must be 32 lowercase hex characters")
        return value

    @field_validator("span_id")
    @classmethod
    def _valid_span_id(cls, value: str | None) -> str | None:
        if value is not None and not _SPAN_ID_RE.match(value):
            raise ValueError("span_id must be 16 lowercase hex characters")
        return value

    def to_otel_attributes(self) -> dict[str, Any]:
        """Flatten to OpenTelemetry-style semantic attributes (redacted content only)."""
        attrs: dict[str, Any] = {
            "guardbench.event.type": self.event_type,
            "guardbench.event.source": self.source,
            "guardbench.event.sequence": self.sequence,
        }
        if self.server_name:
            attrs["mcp.server.name"] = self.server_name
        if self.tool_name:
            attrs["mcp.tool.name"] = self.tool_name
        if self.decision:
            attrs["guardbench.policy.decision"] = self.decision.value
        if self.risk_tags:
            attrs["guardbench.risk_tags"] = list(self.risk_tags)
        return attrs


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #


class FieldChange(_Model):
    """A change to one field of one tool between two snapshots."""

    tool_name: str
    field: str
    old_value: Any = None
    new_value: Any = None
    old_hash: str | None = None
    new_hash: str | None = None


class DriftReport(_Model):
    """Result of comparing a current tool snapshot with an approved one."""

    server_name: str
    drifted: bool
    old_hash: str
    new_hash: str
    added_tools: list[str] = Field(default_factory=list)
    removed_tools: list[str] = Field(default_factory=list)
    changed_descriptions: list[FieldChange] = Field(default_factory=list)
    changed_input_schemas: list[FieldChange] = Field(default_factory=list)
    changed_output_schemas: list[FieldChange] = Field(default_factory=list)
    changed_annotations: list[FieldChange] = Field(default_factory=list)
    changed_capabilities: list[FieldChange] = Field(default_factory=list)
    changed_identity: list[FieldChange] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    requires_review: bool = False
    recommended_action: str = "none"
    reasons: list[str] = Field(default_factory=list)
    suspicious_findings: list[Finding] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)


# --------------------------------------------------------------------------- #
# Adapter results and metrics
# --------------------------------------------------------------------------- #


class AdapterResult(_Model):
    """Common result every security adapter returns. Vendor scores are never compared."""

    adapter_name: str
    adapter_version: str
    test_case_id: str
    started_at: datetime
    completed_at: datetime
    status: ResultStatus = ResultStatus.COMPLETED
    detected: bool = False
    blocked: bool = False
    required_approval: bool = False
    false_positive: bool = False
    false_negative: bool = False
    findings: list[Finding] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    error: str | None = None
    limitations: list[str] = Field(default_factory=list)
    tool_calls: int = 0
    policy_denials: int = 0
    approvals_required: int = 0
    unsafe_outcomes: list[str] = Field(default_factory=list)
    evidence_kinds_present: list[EvidenceKind] = Field(default_factory=list)
    expectation_met: bool | None = None
    claim_mismatches: list[str] = Field(default_factory=list)


class MetricValue(_Model):
    """A metric that is explicit about being undefined when its denominator is zero."""

    name: str
    value: float | None
    unit: str = "ratio"
    numerator: float | None = None
    denominator: float | None = None
    undefined_reason: str | None = None
    dimensions: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# API / persistence entity schemas
# --------------------------------------------------------------------------- #


class PageParams(_Model):
    """Pagination parameters."""

    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class Page[T](BaseModel):
    """A page of results with the total count."""

    items: list[T]
    total: int
    limit: int
    offset: int


class ProjectCreate(_Model):
    """Request body for creating a project."""

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        if not _NAME_RE.match(value):
            raise ValueError("name must start alphanumeric and contain only letters, digits, space, _ . -")
        return value


class ProjectRead(_Model):
    """A project as returned by the API."""

    id: UUID
    name: str
    description: str
    created_at: datetime


class ServerCreate(_Model):
    """Register a local fixture server. Arbitrary URLs and commands are not accepted."""

    name: str = Field(min_length=1, max_length=128)
    fixture: str = Field(min_length=1, max_length=128, description="Name of an allowlisted lab fixture")
    transport: TransportKind = TransportKind.IN_MEMORY
    source_type: SourceType = SourceType.LOCAL_FIXTURE
    version: str | None = None

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        if not _NAME_RE.match(value):
            raise ValueError("name must start alphanumeric and contain only letters, digits, space, _ . -")
        return value


class ServerRead(_Model):
    """A registered server as returned by the API."""

    id: UUID
    project_id: UUID
    name: str
    transport: str
    endpoint: str
    source_type: str
    version: str | None
    trust_status: TrustStatus
    lab_phase: int = 0
    created_at: datetime


class ToolRead(_Model):
    """A stored tool definition as returned by the API."""

    id: UUID
    server_id: UUID
    name: str
    title: str | None = None
    description: str | None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]
    capabilities: list[str] = Field(default_factory=list)
    definition_hash: str
    approval_status: ApprovalStatus
    approved_hash: str | None = None
    #: True when an approved tool's current definition no longer matches its pinned hash.
    drifted: bool = False
    observed_at: datetime


class SnapshotRead(_Model):
    """A stored tool snapshot as returned by the API."""

    id: UUID
    server_id: UUID
    snapshot_hash: str
    tool_count: int
    is_approved_baseline: bool
    created_at: datetime


class TestCaseRead(_Model):
    """A loaded test case as returned by the API."""

    __test__ = False

    id: UUID
    external_id: str
    name: str
    category: str
    severity: Severity
    description: str
    yaml_path: str
    expected_behaviors: dict[str, Any]
    enabled: bool


class RunCreate(_Model):
    """Request body for creating a benchmark run."""

    project_id: UUID
    adapters: list[str] = Field(min_length=1, max_length=8)
    test_case_ids: list[str] | None = Field(default=None, max_length=200)
    seed: int = Field(default=0, ge=0, le=2**31 - 1)
    mode: RunMode = RunMode.UNATTENDED


class RunRead(_Model):
    """A benchmark run as returned by the API."""

    id: UUID
    project_id: UUID
    status: RunStatus
    started_at: datetime | None
    completed_at: datetime | None
    configuration_json: dict[str, Any]
    summary_json: dict[str, Any]


class EventRead(_Model):
    """An evidence event as exposed by the API. Raw payloads are never included."""

    id: UUID
    run_id: UUID | None
    trace_id: str
    span_id: str | None = None
    parent_event_id: UUID | None
    sequence: int
    timestamp: datetime
    event_type: str
    source: str
    server_name: str | None
    tool_name: str | None
    redacted_payload_json: dict[str, Any]
    risk_tags: list[str]
    decision: PolicyDecisionType | None


class FindingRead(_Model):
    """A persisted finding as returned by the API."""

    id: UUID
    run_id: UUID | None
    test_case_id: UUID | None
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float
    status: FindingStatus
    description: str
    evidence_json: dict[str, Any]
    remediation: str
    created_at: datetime


class MetricRead(_Model):
    """A persisted metric as returned by the API."""

    id: UUID
    run_id: UUID
    metric_name: str
    metric_value: float | None
    unit: str
    dimensions_json: dict[str, Any]


class DashboardSummary(_Model):
    """Headline numbers for the dashboard overview."""

    total_runs: int
    total_test_cases: int
    total_servers: int
    open_findings: int
    high_severity_findings: int
    detection_rate: float | None
    prevention_rate: float | None
    latest_run_id: UUID | None
    #: Headline rates of each adapter in the most recent completed run (``None`` = undefined).
    latest_run_headlines: dict[str, dict[str, float | None]] = Field(default_factory=dict)
    notice: str = (
        "Local security lab. Results are experimental and come from local reference fixtures. "
        "No external server has been scanned."
    )


_ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@ \-]{0,63}$")


class ActorBody(_Model):
    """Who is recording an approval decision. This is a real (human) decision, not a simulated one."""

    actor: str = "local-operator"

    @field_validator("actor")
    @classmethod
    def _valid_actor(cls, value: str) -> str:
        if not _ACTOR_RE.match(value):
            raise ValueError("actor must be 1-64 characters: letters, digits, space, _ . @ -")
        if value == "simulated-operator":
            raise ValueError("'simulated-operator' is reserved for clearly-labelled simulations")
        return value


class ScanResponse(_Model):
    """Result of scanning a registered server."""

    snapshot: SnapshotRead
    snapshot_changed: bool
    tools: list[ToolRead]
    findings: list[Finding]
    drift: DriftReport | None
    server_trust_status: TrustStatus


class ValidateTestCaseRequest(_Model):
    """Test-case YAML to validate. Nothing is stored and no path is accepted."""

    yaml: str = Field(min_length=1, max_length=65536)


class ValidateTestCaseResponse(_Model):
    """Outcome of validating a test case."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    spec: dict[str, Any] | None = None
