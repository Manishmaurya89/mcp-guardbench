"""Server registration, scanning, snapshotting, approval, and drift evaluation.

Servers are only ever reached through the allowlisted fixture registry. The "observer" that
lists a server's tools is injectable, so the service is testable without an event loop and
the only real implementation (:func:`observe_fixture`) can only talk to local lab fixtures.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import delete
from sqlalchemy.orm import Session

from guardbench.analysis.drift_detector import compare_snapshots, drift_finding
from guardbench.analysis.fingerprinting import build_snapshot
from guardbench.analysis.metadata_analyzer import analyze_server
from guardbench.asyncio_utils import run_sync
from guardbench.db import models, repositories
from guardbench.domain.enums import Severity, TransportKind, TrustStatus
from guardbench.domain.errors import ConflictError, NotFoundError, UnknownFixtureError, ValidationFailure
from guardbench.domain.schemas import DriftReport, Finding, ServerCreate, ServerIdentity, ToolDefinitionData
from guardbench.mcp_lab.client_runner import FixtureConnection
from guardbench.mcp_lab.fixtures import create_fixture, is_allowed_fixture

FIXTURE_ENDPOINT_PREFIX = "fixture://"
STATIC_DETECTOR = "reference-static"

Observation = tuple[list[ToolDefinitionData], ServerIdentity]
Observer = Callable[[str, int], Observation]


def observe_fixture(fixture_name: str, phase: int = 0) -> Observation:
    """List the tools of a *fresh* allowlisted fixture at a deterministic phase, over real MCP."""
    fixture = create_fixture(fixture_name)
    for _ in range(phase):
        fixture.advance_state()

    async def observe() -> Observation:
        async with FixtureConnection(fixture) as conn:
            return await conn.list_tools(), conn.server_identity

    return run_sync(observe)


def fixture_name_of(server: models.MCPServer) -> str:
    """The fixture behind a registered server, re-validated against the allowlist."""
    name = server.endpoint.removeprefix(FIXTURE_ENDPOINT_PREFIX)
    if not server.endpoint.startswith(FIXTURE_ENDPOINT_PREFIX) or not is_allowed_fixture(name):
        raise UnknownFixtureError(f"server {server.name!r} does not reference an allowlisted fixture")
    return name


def register_server(session: Session, project_id: UUID, data: ServerCreate) -> models.MCPServer:
    """Register a local fixture as a server. Arbitrary URLs and commands are never accepted."""
    if not is_allowed_fixture(data.fixture):
        raise UnknownFixtureError(f"unknown fixture {data.fixture!r}")
    if data.transport is not TransportKind.IN_MEMORY:
        raise ValidationFailure(
            "only the in_memory transport can be registered in this version; "
            "stdio fixtures are available through 'python -m guardbench.mcp_lab.server_runner'"
        )
    version = data.version or create_fixture(data.fixture).server_version
    return repositories.add_server(
        session,
        project_id,
        name=data.name,
        transport=data.transport.value,
        endpoint=f"{FIXTURE_ENDPOINT_PREFIX}{data.fixture}",
        source_type=data.source_type.value,
        version=version,
    )


@dataclass(slots=True)
class ScanOutcome:
    """Everything a scan produced."""

    snapshot: models.ToolSnapshot
    tools: list[models.ToolDefinition]
    findings: list[Finding]
    drift: DriftReport | None
    snapshot_changed: bool


def scan_server(session: Session, server_id: UUID, *, observer: Observer = observe_fixture) -> ScanOutcome:
    """Observe, snapshot, analyze, and (if a baseline exists) check drift. Commits nothing."""
    server = repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    tools, identity = observer(fixture_name_of(server), server.lab_phase)

    previous = repositories.latest_snapshot(session, server.id)
    snapshot_data = build_snapshot(server.name, tools, identity)
    snapshot = repositories.save_snapshot(session, server.id, snapshot_data)
    tool_rows = repositories.sync_tools(session, server, tools, snapshot_data)
    server.version = identity.version or server.version

    findings = analyze_server(server.name, tools)
    drift = compute_drift(session, server)
    if drift is not None and drift.drifted:
        findings.append(drift_finding(drift, server.name, detected_by=STATIC_DETECTOR))
        repositories.set_trust(
            server, TrustStatus.QUARANTINED if drift.severity >= Severity.HIGH else TrustStatus.PENDING_REVIEW
        )
    elif drift is not None and server.trust_status != TrustStatus.TRUSTED.value:
        repositories.set_trust(server, TrustStatus.TRUSTED)

    _replace_scan_findings(session, server.id, findings)
    return ScanOutcome(
        snapshot=snapshot,
        tools=tool_rows,
        findings=findings,
        drift=drift,
        snapshot_changed=previous is None or previous.id != snapshot.id,
    )


def compute_drift(session: Session, server: models.MCPServer) -> DriftReport | None:
    """Compare the latest snapshot with the approved baseline; ``None`` when no baseline exists."""
    baseline = repositories.approved_baseline(session, server.id)
    latest = repositories.latest_snapshot(session, server.id)
    if baseline is None or latest is None:
        return None
    trusted = [t.name for t in server.tools if t.approved_hash is not None]
    return compare_snapshots(
        repositories.snapshot_to_data(baseline, server.name),
        repositories.snapshot_to_data(latest, server.name),
        trusted_tools=trusted or None,
    )


def approve_baseline(session: Session, server_id: UUID, by: str) -> models.ToolSnapshot:
    """Approve the latest snapshot as the trusted baseline (a recorded human decision)."""
    server = repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    latest = repositories.latest_snapshot(session, server.id)
    if latest is None:
        raise NotFoundError("nothing to approve: scan the server first")
    repositories.approve_snapshot(session, server, latest, by)
    return latest


def advance_lab_state(session: Session, server_id: UUID) -> models.MCPServer:
    """Lab control: move a drift-capable fixture to its next deterministic state (simulated rug pull)."""
    server = repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    if not create_fixture(fixture_name_of(server)).supports_state_advance:
        raise ConflictError(f"fixture behind {server.name!r} has no state to advance")
    server.lab_phase = 1
    session.flush()
    return server


def reset_lab_state(session: Session, server_id: UUID) -> models.MCPServer:
    """Lab control: return a fixture to its original state."""
    server = repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    server.lab_phase = 0
    session.flush()
    return server


def _replace_scan_findings(session: Session, server_id: UUID, findings: list[Finding]) -> None:
    """Scan findings (not tied to a run) are replaced by each new scan of the same server."""
    session.execute(
        delete(models.Finding).where(models.Finding.server_id == server_id, models.Finding.run_id.is_(None))
    )
    for finding in findings:
        session.add(repositories.finding_to_row(finding, server_id=server_id))
    session.flush()
