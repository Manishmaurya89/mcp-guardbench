"""ORM models. Identifiers are UUIDs; timestamps are aware UTC; JSON is JSONB on PostgreSQL."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardbench.db.base import Base, JSONType, UTCDateTime
from guardbench.domain.clock import utc_now
from guardbench.domain.enums import ApprovalStatus, RunStatus, TrustStatus


def _uuid_pk() -> Mapped[UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid4)


class Project(Base):
    """A named collection of servers and runs."""

    __tablename__ = "projects"

    id: Mapped[UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)

    servers: Mapped[list[MCPServer]] = relationship(back_populates="project", cascade="all, delete-orphan")
    runs: Mapped[list[BenchmarkRun]] = relationship(back_populates="project", cascade="all, delete-orphan")


class MCPServer(Base):
    """A registered local fixture server."""

    __tablename__ = "mcp_servers"
    __table_args__ = (UniqueConstraint("project_id", "name"),)

    id: Mapped[UUID] = _uuid_pk()
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    transport: Mapped[str] = mapped_column(String(32))
    endpoint: Mapped[str] = mapped_column(String(256))
    source_type: Mapped[str] = mapped_column(String(32))
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trust_status: Mapped[str] = mapped_column(String(32), default=TrustStatus.UNTRUSTED.value, index=True)
    #: Lab-only: which deterministic state a drift-capable fixture is in (0 = original definition).
    lab_phase: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)

    project: Mapped[Project] = relationship(back_populates="servers")
    tools: Mapped[list[ToolDefinition]] = relationship(back_populates="server", cascade="all, delete-orphan")
    snapshots: Mapped[list[ToolSnapshot]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )


class ToolDefinition(Base):
    """The latest observed definition of one tool, plus its approval pin."""

    __tablename__ = "tool_definitions"
    __table_args__ = (UniqueConstraint("server_id", "name"),)

    id: Mapped[UUID] = _uuid_pk()
    server_id: Mapped[UUID] = mapped_column(ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(256))
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    output_schema: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    annotations: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    capabilities: Mapped[list[str]] = mapped_column(JSONType, default=list)
    definition_hash: Mapped[str] = mapped_column(String(64), index=True)
    approval_status: Mapped[str] = mapped_column(String(16), default=ApprovalStatus.PENDING.value)
    approved_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)

    server: Mapped[MCPServer] = relationship(back_populates="tools")


class ToolSnapshot(Base):
    """An immutable, hashed picture of a server's whole tool set."""

    __tablename__ = "tool_snapshots"

    id: Mapped[UUID] = _uuid_pk()
    server_id: Mapped[UUID] = mapped_column(ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True)
    snapshot_hash: Mapped[str] = mapped_column(String(64), index=True)
    normalized_tools_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    tool_hashes_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    identity_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    is_approved_baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)

    server: Mapped[MCPServer] = relationship(back_populates="snapshots")


class TestCase(Base):
    """A test case loaded from ``test_cases/*.yaml``."""

    __test__ = False
    __tablename__ = "test_cases"

    id: Mapped[UUID] = _uuid_pk()
    external_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    description: Mapped[str] = mapped_column(Text)
    yaml_path: Mapped[str] = mapped_column(String(512))
    spec_hash: Mapped[str] = mapped_column(String(64), default="")
    expected_behaviors: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class BenchmarkRun(Base):
    """One execution of a set of test cases against a set of adapters."""

    __tablename__ = "benchmark_runs"

    id: Mapped[UUID] = _uuid_pk()
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.PENDING.value, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    configuration_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)

    project: Mapped[Project] = relationship(back_populates="runs")
    events: Mapped[list[Event]] = relationship(back_populates="run", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="run", cascade="all, delete-orphan")
    metrics: Mapped[list[Metric]] = relationship(back_populates="run", cascade="all, delete-orphan")


class Event(Base):
    """One normalized evidence event. ``payload_json`` never leaves the store via the API."""

    __tablename__ = "events"
    __table_args__ = (Index("ix_events_run_id_sequence", "run_id", "sequence"),)

    id: Mapped[UUID] = _uuid_pk()
    run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("benchmark_runs.id", ondelete="CASCADE"), index=True, nullable=True
    )
    trace_id: Mapped[str] = mapped_column(String(32), index=True)
    span_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parent_event_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    source: Mapped[str] = mapped_column(String(64))
    server_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    redacted_payload_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    risk_tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    decision: Mapped[str | None] = mapped_column(String(24), nullable=True)

    run: Mapped[BenchmarkRun | None] = relationship(back_populates="events")


class Finding(Base):
    """A persisted security finding with its evidence."""

    __tablename__ = "findings"

    id: Mapped[UUID] = _uuid_pk()
    run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("benchmark_runs.id", ondelete="CASCADE"), index=True, nullable=True
    )
    server_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True, nullable=True
    )
    test_case_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("test_cases.id", ondelete="SET NULL"), index=True, nullable=True
    )
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now, index=True)

    run: Mapped[BenchmarkRun | None] = relationship(back_populates="findings")


class Metric(Base):
    """One computed benchmark metric. ``metric_value`` is NULL when the metric is undefined."""

    __tablename__ = "metrics"

    id: Mapped[UUID] = _uuid_pk()
    run_id: Mapped[UUID] = mapped_column(ForeignKey("benchmark_runs.id", ondelete="CASCADE"), index=True)
    metric_name: Mapped[str] = mapped_column(String(96), index=True)
    metric_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    unit: Mapped[str] = mapped_column(String(24), default="ratio")
    dimensions_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    run: Mapped[BenchmarkRun] = relationship(back_populates="metrics")
