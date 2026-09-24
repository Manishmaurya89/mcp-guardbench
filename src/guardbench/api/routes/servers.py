"""Server registration, scanning, snapshots, and drift."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from guardbench.api.dependencies import AuthDep, SessionDep
from guardbench.api.pagination import PageDep, count_rows
from guardbench.api.redaction import RedactingRoute
from guardbench.db import models, repositories
from guardbench.domain.enums import TrustStatus
from guardbench.domain.errors import NotFoundError
from guardbench.domain.schemas import (
    ActorBody,
    DriftReport,
    Page,
    ScanResponse,
    ServerCreate,
    ServerRead,
    SnapshotRead,
)
from guardbench.services import scan

router = APIRouter(tags=["servers"], dependencies=[AuthDep], route_class=RedactingRoute)


def _read(server: models.MCPServer) -> ServerRead:
    return ServerRead.model_validate(server)


@router.post("/projects/{project_id}/servers", response_model=ServerRead, status_code=status.HTTP_201_CREATED)
def register_server(project_id: UUID, body: ServerCreate, session: SessionDep) -> ServerRead:
    """Register a local lab fixture as a server. Only allowlisted fixtures are accepted; no URLs."""
    server = scan.register_server(session, project_id, body)
    session.commit()
    return _read(server)


@router.get("/servers", response_model=Page[ServerRead])
def list_servers(session: SessionDep, page: PageDep, project_id: UUID | None = None) -> Page[ServerRead]:
    """List registered servers, optionally for one project."""
    statement = select(models.MCPServer)
    if project_id is not None:
        statement = statement.where(models.MCPServer.project_id == project_id)
    rows = session.scalars(
        statement.order_by(models.MCPServer.created_at.desc(), models.MCPServer.name)
        .limit(page.limit)
        .offset(page.offset)
    ).all()
    return Page[ServerRead](
        items=[_read(r) for r in rows],
        total=count_rows(session, statement),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/servers/{server_id}", response_model=ServerRead)
def get_server(server_id: UUID, session: SessionDep) -> ServerRead:
    """Fetch one server."""
    return _read(repositories.get_or_raise(session, models.MCPServer, server_id, "server"))


@router.post("/servers/{server_id}/scan", response_model=ScanResponse)
def scan_server(server_id: UUID, session: SessionDep) -> ScanResponse:
    """Observe the fixture's tools, snapshot them, analyze them, and check drift against the baseline."""
    outcome = scan.scan_server(session, server_id)
    server = repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    response = ScanResponse(
        snapshot=repositories.snapshot_to_read(outcome.snapshot),
        snapshot_changed=outcome.snapshot_changed,
        tools=[repositories.tool_to_read(t) for t in outcome.tools],
        findings=outcome.findings,
        drift=outcome.drift,
        server_trust_status=TrustStatus(server.trust_status),
    )
    session.commit()
    return response


@router.get("/servers/{server_id}/snapshots", response_model=list[SnapshotRead])
def list_snapshots(server_id: UUID, session: SessionDep) -> list[SnapshotRead]:
    """Stored tool snapshots, newest first."""
    repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    return [repositories.snapshot_to_read(s) for s in repositories.list_snapshots(session, server_id)]


@router.get("/servers/{server_id}/drift", response_model=DriftReport)
def get_drift(server_id: UUID, session: SessionDep) -> DriftReport:
    """Compare the latest snapshot with the approved baseline. 404 if no baseline has been approved."""
    server = repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    report = scan.compute_drift(session, server)
    if report is None:
        raise NotFoundError("no approved baseline for this server; scan it and approve a snapshot first")
    return report


@router.post("/servers/{server_id}/approve", response_model=SnapshotRead)
def approve_baseline(server_id: UUID, body: ActorBody, session: SessionDep) -> SnapshotRead:
    """Approve the latest snapshot as the trusted baseline (a recorded human decision)."""
    snapshot = scan.approve_baseline(session, server_id, body.actor)
    session.commit()
    return repositories.snapshot_to_read(snapshot)


@router.post("/servers/{server_id}/lab/advance", response_model=ServerRead)
def advance_lab_state(server_id: UUID, session: SessionDep) -> ServerRead:
    """LAB CONTROL: move a drift-capable fixture to its changed state (a simulated rug pull)."""
    server = scan.advance_lab_state(session, server_id)
    session.commit()
    return _read(server)


@router.post("/servers/{server_id}/lab/reset", response_model=ServerRead)
def reset_lab_state(server_id: UUID, session: SessionDep) -> ServerRead:
    """LAB CONTROL: return a fixture to its original state."""
    server = scan.reset_lab_state(session, server_id)
    session.commit()
    return _read(server)
