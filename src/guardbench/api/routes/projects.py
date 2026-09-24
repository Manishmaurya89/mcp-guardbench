"""Project endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from guardbench.api.dependencies import AuthDep, SessionDep
from guardbench.api.pagination import PageDep, count_rows
from guardbench.api.redaction import RedactingRoute
from guardbench.db import models, repositories
from guardbench.domain.schemas import Page, ProjectCreate, ProjectRead

router = APIRouter(prefix="/projects", tags=["projects"], dependencies=[AuthDep], route_class=RedactingRoute)


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(body: ProjectCreate, session: SessionDep) -> ProjectRead:
    """Create a project. Names are unique."""
    project = repositories.create_project(session, body)
    session.commit()
    return ProjectRead.model_validate(project)


@router.get("", response_model=Page[ProjectRead])
def list_projects(session: SessionDep, page: PageDep) -> Page[ProjectRead]:
    """List projects, newest first."""
    statement = select(models.Project)
    rows = session.scalars(
        statement.order_by(models.Project.created_at.desc()).limit(page.limit).offset(page.offset)
    ).all()
    return Page[ProjectRead](
        items=[ProjectRead.model_validate(r) for r in rows],
        total=count_rows(session, statement),
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: UUID, session: SessionDep) -> ProjectRead:
    """Fetch one project."""
    return ProjectRead.model_validate(
        repositories.get_or_raise(session, models.Project, project_id, "project")
    )
