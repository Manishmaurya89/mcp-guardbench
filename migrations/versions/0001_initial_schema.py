"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-20 19:20:40.958804+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine[object]:
    """JSONB on PostgreSQL, plain JSON elsewhere (frozen copy of the app's column type)."""
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
        sa.UniqueConstraint("name", name=op.f("uq_projects_name")),
    )
    with op.batch_alter_table("projects", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_projects_created_at"), ["created_at"], unique=False)

    op.create_table(
        "test_cases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("yaml_path", sa.String(length=512), nullable=False),
        sa.Column("spec_hash", sa.String(length=64), nullable=False),
        sa.Column("expected_behaviors", _json(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_test_cases")),
    )
    with op.batch_alter_table("test_cases", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_test_cases_category"), ["category"], unique=False)
        batch_op.create_index(batch_op.f("ix_test_cases_external_id"), ["external_id"], unique=True)
        batch_op.create_index(batch_op.f("ix_test_cases_severity"), ["severity"], unique=False)

    op.create_table(
        "benchmark_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("configuration_json", _json(), nullable=False),
        sa.Column("summary_json", _json(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_benchmark_runs_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_benchmark_runs")),
    )
    with op.batch_alter_table("benchmark_runs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_benchmark_runs_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_benchmark_runs_project_id"), ["project_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_benchmark_runs_status"), ["status"], unique=False)

    op.create_table(
        "mcp_servers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("transport", sa.String(length=32), nullable=False),
        sa.Column("endpoint", sa.String(length=256), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("trust_status", sa.String(length=32), nullable=False),
        sa.Column("lab_phase", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_mcp_servers_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mcp_servers")),
        sa.UniqueConstraint("project_id", "name", name=op.f("uq_mcp_servers_project_id")),
    )
    with op.batch_alter_table("mcp_servers", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_mcp_servers_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_mcp_servers_project_id"), ["project_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_mcp_servers_trust_status"), ["trust_status"], unique=False)

    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("trace_id", sa.String(length=32), nullable=False),
        sa.Column("span_id", sa.String(length=16), nullable=True),
        sa.Column("parent_event_id", sa.Uuid(), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("server_name", sa.String(length=128), nullable=True),
        sa.Column("tool_name", sa.String(length=256), nullable=True),
        sa.Column("payload_json", _json(), nullable=False),
        sa.Column("redacted_payload_json", _json(), nullable=False),
        sa.Column("risk_tags", _json(), nullable=False),
        sa.Column("decision", sa.String(length=24), nullable=True),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["benchmark_runs.id"],
            name=op.f("fk_events_run_id_benchmark_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_events")),
    )
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_events_event_type"), ["event_type"], unique=False)
        batch_op.create_index(batch_op.f("ix_events_run_id"), ["run_id"], unique=False)
        batch_op.create_index("ix_events_run_id_sequence", ["run_id", "sequence"], unique=False)
        batch_op.create_index(batch_op.f("ix_events_timestamp"), ["timestamp"], unique=False)
        batch_op.create_index(batch_op.f("ix_events_trace_id"), ["trace_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("server_id", sa.Uuid(), nullable=True),
        sa.Column("test_case_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("category", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence_json", _json(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["benchmark_runs.id"],
            name=op.f("fk_findings_run_id_benchmark_runs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["mcp_servers.id"],
            name=op.f("fk_findings_server_id_mcp_servers"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["test_case_id"],
            ["test_cases.id"],
            name=op.f("fk_findings_test_case_id_test_cases"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_findings_category"), ["category"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_run_id"), ["run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_server_id"), ["server_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_severity"), ["severity"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_status"), ["status"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_test_case_id"), ["test_case_id"], unique=False)

    op.create_table(
        "metrics",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("metric_name", sa.String(length=96), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=True),
        sa.Column("unit", sa.String(length=24), nullable=False),
        sa.Column("dimensions_json", _json(), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["benchmark_runs.id"],
            name=op.f("fk_metrics_run_id_benchmark_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_metrics")),
    )
    with op.batch_alter_table("metrics", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_metrics_metric_name"), ["metric_name"], unique=False)
        batch_op.create_index(batch_op.f("ix_metrics_run_id"), ["run_id"], unique=False)

    op.create_table(
        "tool_definitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("server_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("input_schema", _json(), nullable=False),
        sa.Column("output_schema", _json(), nullable=True),
        sa.Column("annotations", _json(), nullable=False),
        sa.Column("meta", _json(), nullable=False),
        sa.Column("capabilities", _json(), nullable=False),
        sa.Column("definition_hash", sa.String(length=64), nullable=False),
        sa.Column("approval_status", sa.String(length=16), nullable=False),
        sa.Column("approved_hash", sa.String(length=64), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["mcp_servers.id"],
            name=op.f("fk_tool_definitions_server_id_mcp_servers"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_definitions")),
        sa.UniqueConstraint("server_id", "name", name=op.f("uq_tool_definitions_server_id")),
    )
    with op.batch_alter_table("tool_definitions", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_tool_definitions_definition_hash"), ["definition_hash"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_tool_definitions_observed_at"), ["observed_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_tool_definitions_server_id"), ["server_id"], unique=False)

    op.create_table(
        "tool_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("server_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("normalized_tools_json", _json(), nullable=False),
        sa.Column("tool_hashes_json", _json(), nullable=False),
        sa.Column("identity_json", _json(), nullable=False),
        sa.Column("is_approved_baseline", sa.Boolean(), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["mcp_servers.id"],
            name=op.f("fk_tool_snapshots_server_id_mcp_servers"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_snapshots")),
    )
    with op.batch_alter_table("tool_snapshots", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_tool_snapshots_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_tool_snapshots_server_id"), ["server_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_tool_snapshots_snapshot_hash"), ["snapshot_hash"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("tool_snapshots", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tool_snapshots_snapshot_hash"))
        batch_op.drop_index(batch_op.f("ix_tool_snapshots_server_id"))
        batch_op.drop_index(batch_op.f("ix_tool_snapshots_created_at"))

    op.drop_table("tool_snapshots")
    with op.batch_alter_table("tool_definitions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tool_definitions_server_id"))
        batch_op.drop_index(batch_op.f("ix_tool_definitions_observed_at"))
        batch_op.drop_index(batch_op.f("ix_tool_definitions_definition_hash"))

    op.drop_table("tool_definitions")
    with op.batch_alter_table("metrics", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_metrics_run_id"))
        batch_op.drop_index(batch_op.f("ix_metrics_metric_name"))

    op.drop_table("metrics")
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_test_case_id"))
        batch_op.drop_index(batch_op.f("ix_findings_status"))
        batch_op.drop_index(batch_op.f("ix_findings_severity"))
        batch_op.drop_index(batch_op.f("ix_findings_server_id"))
        batch_op.drop_index(batch_op.f("ix_findings_run_id"))
        batch_op.drop_index(batch_op.f("ix_findings_created_at"))
        batch_op.drop_index(batch_op.f("ix_findings_category"))

    op.drop_table("findings")
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_events_trace_id"))
        batch_op.drop_index(batch_op.f("ix_events_timestamp"))
        batch_op.drop_index("ix_events_run_id_sequence")
        batch_op.drop_index(batch_op.f("ix_events_run_id"))
        batch_op.drop_index(batch_op.f("ix_events_event_type"))

    op.drop_table("events")
    with op.batch_alter_table("mcp_servers", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_mcp_servers_trust_status"))
        batch_op.drop_index(batch_op.f("ix_mcp_servers_project_id"))
        batch_op.drop_index(batch_op.f("ix_mcp_servers_created_at"))

    op.drop_table("mcp_servers")
    with op.batch_alter_table("benchmark_runs", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_benchmark_runs_status"))
        batch_op.drop_index(batch_op.f("ix_benchmark_runs_project_id"))
        batch_op.drop_index(batch_op.f("ix_benchmark_runs_created_at"))

    op.drop_table("benchmark_runs")
    with op.batch_alter_table("test_cases", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_test_cases_severity"))
        batch_op.drop_index(batch_op.f("ix_test_cases_external_id"))
        batch_op.drop_index(batch_op.f("ix_test_cases_category"))

    op.drop_table("test_cases")
    with op.batch_alter_table("projects", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_projects_created_at"))

    op.drop_table("projects")
