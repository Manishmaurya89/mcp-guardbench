"""Idempotent demo data: a project, every lab fixture registered and scanned, and a staged rug pull.

Everything here is local and synthetic. Running it twice is safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from guardbench.db import models, repositories
from guardbench.domain.schemas import ProjectCreate, ServerCreate
from guardbench.mcp_lab.fixtures import fixture_names
from guardbench.services import scan

DEMO_PROJECT = "demo"
DEMO_DESCRIPTION = "Local demo project: synthetic lab fixtures only. No external server is scanned."
#: Fixtures whose first snapshot is approved as a trusted baseline (the operator's decision, in the demo).
APPROVED_FIXTURES = ("clean_server", "drift_server")
#: Fixtures that get a simulated rug pull after approval so the drift views have something to show.
RUG_PULL_FIXTURES = ("drift_server",)


@dataclass(slots=True)
class DemoSeedResult:
    """What seeding did, for CLI output."""

    project: models.Project
    servers: list[models.MCPServer] = field(default_factory=list)
    scanned: int = 0
    approved: list[str] = field(default_factory=list)
    drifted: list[str] = field(default_factory=list)


def seed_demo(session: Session) -> DemoSeedResult:
    """Create or refresh the demo data. Commits at the end."""
    project = repositories.get_project_by_name(session, DEMO_PROJECT) or repositories.create_project(
        session, ProjectCreate(name=DEMO_PROJECT, description=DEMO_DESCRIPTION)
    )
    result = DemoSeedResult(project=project)
    existing = {s.name: s for s in project.servers}

    for fixture in fixture_names():
        server = existing.get(fixture) or scan.register_server(
            session, project.id, ServerCreate(name=fixture, fixture=fixture)
        )
        result.servers.append(server)
        scan.scan_server(session, server.id)  # phase 0: the definition an operator would review
        result.scanned += 1

        if fixture in APPROVED_FIXTURES and repositories.approved_baseline(session, server.id) is None:
            scan.approve_baseline(session, server.id, "demo-operator")
            result.approved.append(fixture)
        if fixture in RUG_PULL_FIXTURES and server.lab_phase == 0:
            scan.advance_lab_state(session, server.id)
            scan.scan_server(session, server.id)  # phase 1: the changed definition, now drifted
            result.drifted.append(fixture)
    session.commit()
    return result
