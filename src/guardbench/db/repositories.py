"""Persistence functions. All queries are parameterized through SQLAlchemy; nothing is string-built.

Repositories flush but never commit: the caller (service or route) owns the transaction, so a
multi-step operation such as "scan and record findings" is atomic.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardbench.analysis.capabilities import effective_capabilities
from guardbench.db import models
from guardbench.domain.clock import utc_now
from guardbench.domain.enums import ApprovalStatus, TrustStatus
from guardbench.domain.errors import ConflictError, NotFoundError
from guardbench.domain.schemas import (
    Finding,
    ProjectCreate,
    ServerIdentity,
    SnapshotRead,
    ToolDefinitionData,
    ToolRead,
    ToolSnapshotData,
)
from guardbench.runtime.redaction import Redactor

_SCRUBBER = Redactor()  # stateless: strips credential-shaped strings before anything is stored


def get_or_raise[M](session: Session, model: type[M], entity_id: UUID, label: str) -> M:
    """Load an entity by primary key or raise :class:`NotFoundError`."""
    row = session.get(model, entity_id)
    if row is None:
        raise NotFoundError(f"{label} {entity_id} not found")
    return row


# --------------------------------------------------------------------------- projects


def create_project(session: Session, data: ProjectCreate) -> models.Project:
    """Create a project; duplicate names raise :class:`ConflictError`."""
    project = models.Project(name=data.name, description=data.description)
    session.add(project)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise ConflictError(f"a project named {data.name!r} already exists") from exc
    return project


def get_project_by_name(session: Session, name: str) -> models.Project | None:
    """Look up a project by its unique name."""
    return session.scalars(select(models.Project).where(models.Project.name == name)).first()


# --------------------------------------------------------------------------- servers


def add_server(
    session: Session,
    project_id: UUID,
    *,
    name: str,
    transport: str,
    endpoint: str,
    source_type: str,
    version: str | None,
) -> models.MCPServer:
    """Register a server; a duplicate name within the project raises :class:`ConflictError`."""
    get_or_raise(session, models.Project, project_id, "project")
    server = models.MCPServer(
        project_id=project_id,
        name=name,
        transport=transport,
        endpoint=endpoint,
        source_type=source_type,
        version=version,
        trust_status=TrustStatus.UNTRUSTED.value,
    )
    session.add(server)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise ConflictError(f"server {name!r} is already registered in this project") from exc
    return server


def set_trust(server: models.MCPServer, status: TrustStatus) -> None:
    """Change a server's trust state."""
    server.trust_status = status.value


# --------------------------------------------------------------------------- snapshots


def snapshot_to_data(row: models.ToolSnapshot, server_name: str) -> ToolSnapshotData:
    """Rebuild the domain snapshot from a stored row."""
    return ToolSnapshotData(
        server_name=server_name,
        identity=ServerIdentity.model_validate(row.identity_json),
        normalized_tools=dict(row.normalized_tools_json),
        tool_hashes={k: str(v) for k, v in row.tool_hashes_json.items()},
        snapshot_hash=row.snapshot_hash,
        created_at=row.created_at,
    )


def latest_snapshot(session: Session, server_id: UUID) -> models.ToolSnapshot | None:
    """The most recently stored snapshot."""
    return session.scalars(
        select(models.ToolSnapshot)
        .where(models.ToolSnapshot.server_id == server_id)
        .order_by(models.ToolSnapshot.created_at.desc(), models.ToolSnapshot.id)
        .limit(1)
    ).first()


def approved_baseline(session: Session, server_id: UUID) -> models.ToolSnapshot | None:
    """The snapshot an operator approved as the trusted baseline, if any."""
    return session.scalars(
        select(models.ToolSnapshot).where(
            models.ToolSnapshot.server_id == server_id, models.ToolSnapshot.is_approved_baseline.is_(True)
        )
    ).first()


def list_snapshots(session: Session, server_id: UUID) -> Sequence[models.ToolSnapshot]:
    """All snapshots, newest first."""
    return session.scalars(
        select(models.ToolSnapshot)
        .where(models.ToolSnapshot.server_id == server_id)
        .order_by(models.ToolSnapshot.created_at.desc())
    ).all()


def save_snapshot(session: Session, server_id: UUID, snapshot: ToolSnapshotData) -> models.ToolSnapshot:
    """Store ``snapshot`` unless it is identical to the latest one (same hash and identity)."""
    latest = latest_snapshot(session, server_id)
    if (
        latest is not None
        and latest.snapshot_hash == snapshot.snapshot_hash
        and latest.identity_json == snapshot.identity.model_dump()
    ):
        return latest
    row = models.ToolSnapshot(
        server_id=server_id,
        snapshot_hash=snapshot.snapshot_hash,
        normalized_tools_json=snapshot.normalized_tools,
        tool_hashes_json=dict(snapshot.tool_hashes),
        identity_json=snapshot.identity.model_dump(),
        created_at=snapshot.created_at,
    )
    session.add(row)
    session.flush()
    return row


def approve_snapshot(
    session: Session, server: models.MCPServer, snapshot: models.ToolSnapshot, by: str
) -> None:
    """Make ``snapshot`` the trusted baseline and pin the matching tool hashes.

    Only one baseline exists per server. Tools whose current definition equals the snapshot are
    approved; the server becomes ``trusted``. This records a human decision; it does not
    verify that the snapshot is safe.
    """
    if snapshot.server_id != server.id:
        raise ConflictError("snapshot does not belong to this server")
    now = utc_now()
    for other in list_snapshots(session, server.id):
        other.is_approved_baseline = False
    snapshot.is_approved_baseline = True
    snapshot.approved_at = now
    for tool in server.tools:
        if snapshot.tool_hashes_json.get(tool.name) == tool.definition_hash:
            _pin(tool, by, now)
    set_trust(server, TrustStatus.TRUSTED)
    session.flush()


# --------------------------------------------------------------------------- tools


def sync_tools(
    session: Session,
    server: models.MCPServer,
    tools: Sequence[ToolDefinitionData],
    snapshot: ToolSnapshotData,
) -> list[models.ToolDefinition]:
    """Upsert the observed tools; keep approval pins; drop tools the server no longer advertises."""
    existing = {t.name: t for t in server.tools}
    seen: set[str] = set()
    now = utc_now()
    for tool in tools:
        seen.add(tool.name)
        row = existing.get(tool.name)
        if row is None:
            row = models.ToolDefinition(server=server, name=tool.name, definition_hash="")
            session.add(row)
        row.title = tool.title
        row.description = tool.description
        row.input_schema = tool.input_schema
        row.output_schema = tool.output_schema
        row.annotations = tool.annotations
        row.meta = tool.meta
        row.capabilities = sorted(c.value for c in effective_capabilities(tool))
        row.definition_hash = snapshot.tool_hashes[tool.name]
        row.observed_at = now
    for name, row in existing.items():
        if name not in seen:
            session.delete(row)
    session.flush()
    return sorted((t for t in server.tools if t.name in seen), key=lambda t: t.name)


def _pin(tool: models.ToolDefinition, by: str, when: Any) -> None:
    tool.approval_status = ApprovalStatus.APPROVED.value
    tool.approved_hash = tool.definition_hash
    tool.approved_at = when
    tool.approved_by = by


def approve_tool(session: Session, tool: models.ToolDefinition, by: str) -> None:
    """Pin the tool's *current* definition hash as approved."""
    _pin(tool, by, utc_now())
    session.flush()


def revoke_tool(session: Session, tool: models.ToolDefinition) -> None:
    """Withdraw approval and forget the pinned hash."""
    tool.approval_status = ApprovalStatus.REVOKED.value
    tool.approved_hash = None
    tool.approved_at = None
    session.flush()


def tool_to_read(row: models.ToolDefinition) -> ToolRead:
    """API view of a stored tool, including whether an approved pin has drifted."""
    drifted = row.approved_hash is not None and row.approved_hash != row.definition_hash
    return ToolRead(
        id=row.id,
        server_id=row.server_id,
        name=row.name,
        title=row.title,
        description=row.description,
        input_schema=row.input_schema,
        output_schema=row.output_schema,
        annotations=row.annotations,
        capabilities=list(row.capabilities),
        definition_hash=row.definition_hash,
        approval_status=ApprovalStatus(row.approval_status),
        approved_hash=row.approved_hash,
        drifted=drifted,
        observed_at=row.observed_at,
    )


def snapshot_to_read(row: models.ToolSnapshot) -> SnapshotRead:
    """API view of a stored snapshot."""
    return SnapshotRead(
        id=row.id,
        server_id=row.server_id,
        snapshot_hash=row.snapshot_hash,
        tool_count=len(row.tool_hashes_json),
        is_approved_baseline=row.is_approved_baseline,
        created_at=row.created_at,
    )


def count(session: Session, model: Any) -> int:
    """Row count for a mapped class."""
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


def finding_to_row(
    finding: Finding,
    *,
    run_id: UUID | None = None,
    server_id: UUID | None = None,
    test_case_id: UUID | None = None,
) -> models.Finding:
    """Map a domain finding to a row, scrubbing credential-shaped content on the way in."""
    evidence = _SCRUBBER.scrub_credentials(
        {
            "rule_id": finding.rule_id,
            "location": finding.location,
            "matched_evidence": finding.matched_evidence,
            "deterministic": finding.deterministic,
            "server_name": finding.server_name,
            "tool_name": finding.tool_name,
            "detected_by": finding.detected_by,
            "test_case": finding.test_case_id,
            "evidence": finding.evidence,
            "evidence_event_ids": finding.evidence_event_ids,
        }
    )
    return models.Finding(
        run_id=run_id,
        server_id=server_id,
        test_case_id=test_case_id,
        title=_SCRUBBER.scrub_credentials_text(finding.title)[:300],
        category=finding.category.value,
        severity=finding.severity.value,
        confidence=finding.confidence,
        status=finding.status.value,
        description=_SCRUBBER.scrub_credentials_text(finding.description),
        evidence_json=evidence,
        remediation=finding.remediation,
    )
