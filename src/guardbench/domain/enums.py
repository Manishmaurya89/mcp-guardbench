"""Normalized security vocabulary shared by every layer.

Nothing in this module imports FastAPI, SQLAlchemy, or the MCP SDK.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Ordered finding severity. Compare with :attr:`rank`, never by string."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric order: info=0 ... critical=4."""
        return _SEVERITY_ORDER.index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class FindingCategory(StrEnum):
    """What kind of weakness a finding (or a test case) is about."""

    TOOL_POISONING = "tool_poisoning"
    RESPONSE_INJECTION = "response_injection"
    TOOL_DEFINITION_DRIFT = "tool_definition_drift"
    SENSITIVE_DATA_FLOW = "sensitive_data_flow"
    EXCESSIVE_PERMISSION = "excessive_permission"
    OVERSIZED_RESPONSE = "oversized_response"
    SCHEMA_RISK = "schema_risk"
    PURPOSE_MISMATCH = "purpose_mismatch"
    CROSS_TOOL_REFERENCE = "cross_tool_reference"
    SHADOWING = "shadowing"
    POLICY_VIOLATION = "policy_violation"
    #: Test-case only: a benign control that must NOT trigger a security reaction.
    BENIGN_CONTROL = "benign_control"


class Capability(StrEnum):
    """Declared or inferred capability class of a tool."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND = "send"
    EXECUTE = "execute"


class PolicyDecisionType(StrEnum):
    """Outcome of a runtime policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW_WITH_WARNING = "allow_with_warning"
    QUARANTINE = "quarantine"

    @property
    def prevents_execution(self) -> bool:
        """True when the decision stops the guarded action from executing."""
        return self in {
            PolicyDecisionType.DENY,
            PolicyDecisionType.REQUIRE_APPROVAL,
            PolicyDecisionType.QUARANTINE,
        }


class EventType(StrEnum):
    """Normalized event kinds recorded in the evidence trail."""

    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"
    TOOLS_LISTED = "tools_listed"
    SNAPSHOT_TAKEN = "snapshot_taken"
    STATIC_FINDING = "static_finding"
    DRIFT_DETECTED = "drift_detected"
    TOOL_CALL_REQUESTED = "tool_call_requested"
    POLICY_DECISION = "policy_decision"
    TOOL_CALL_EXECUTED = "tool_call_executed"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    TOOL_RESPONSE = "tool_response"
    RESPONSE_TRUNCATED = "response_truncated"
    RESPONSE_QUARANTINED = "response_quarantined"
    MODEL_CONTEXT_UPDATE = "model_context_update"
    DATA_FLOW = "data_flow"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_RESOLVED = "approval_resolved"
    FIXTURE_SIDE_EFFECT = "fixture_side_effect"
    ERROR = "error"


class TrustStatus(StrEnum):
    """Operator trust state for a registered MCP server."""

    UNTRUSTED = "untrusted"
    PENDING_REVIEW = "pending_review"
    TRUSTED = "trusted"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class ApprovalStatus(StrEnum):
    """Approval state of a single tool definition."""

    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"


class TransportKind(StrEnum):
    """How a fixture server is reached. Remote transports are not accepted yet."""

    IN_MEMORY = "in_memory"
    STDIO = "stdio"


class SourceType(StrEnum):
    """Where a registered server comes from. Only local fixtures are accepted."""

    LOCAL_FIXTURE = "local_fixture"


class RunStatus(StrEnum):
    """Lifecycle of a benchmark run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(StrEnum):
    """Triage state of a finding."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AttackStage(StrEnum):
    """Where in the MCP lifecycle a test case injects its behavior."""

    REGISTRATION = "registration"
    TOOLS_LIST = "tools_list"
    TOOL_CALL = "tool_call"
    TOOL_RESPONSE = "tool_response"
    SERVER_UPDATE = "server_update"


class EvidenceKind(StrEnum):
    """Kinds of evidence a test case can require from a security control."""

    TOOL_DESCRIPTION = "tool_description"
    DETECTION_RULE = "detection_rule"
    POLICY_DECISION = "policy_decision"
    TOOL_DEFINITION_HASH = "tool_definition_hash"
    DRIFT_REPORT = "drift_report"
    DATA_FLOW_PATH = "data_flow_path"
    RESPONSE_EXCERPT = "response_excerpt"
    EVENT_TRACE = "event_trace"


class SafeBehavior(StrEnum):
    """Safety constraints every test case must declare and every fixture honors."""

    NO_EXTERNAL_NETWORK = "no_external_network"
    NO_REAL_SECRET = "no_real_secret"
    NO_DESTRUCTIVE_ACTION = "no_destructive_action"


class UnsafeOutcome(StrEnum):
    """Ground-truth unsafe results observed from the fixture, not claimed by a control."""

    POISONED_TOOL_EXPOSED = "poisoned_tool_exposed"
    SENSITIVE_TOOL_EXECUTED = "sensitive_tool_executed"
    MARKER_EXFILTRATED = "marker_exfiltrated"
    INJECTION_REACHED_MODEL = "injection_reached_model"
    DRIFTED_TOOL_USED = "drifted_tool_used"
    UNBOUNDED_RESPONSE_REACHED_MODEL = "unbounded_response_reached_model"


class ResultStatus(StrEnum):
    """Whether an adapter actually produced a result for a test case."""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    ERROR = "error"


class RunMode(StrEnum):
    """Approval semantics for a run."""

    UNATTENDED = "unattended"
    INTERACTIVE = "interactive"
