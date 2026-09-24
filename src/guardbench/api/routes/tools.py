"""Tool inventory and approval pinning."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from guardbench.api.dependencies import AuthDep, SessionDep
from guardbench.api.redaction import RedactingRoute
from guardbench.db import models, repositories
from guardbench.domain.schemas import ActorBody, ToolRead

router = APIRouter(tags=["tools"], dependencies=[AuthDep], route_class=RedactingRoute)


@router.get("/servers/{server_id}/tools", response_model=list[ToolRead])
def list_tools(server_id: UUID, session: SessionDep) -> list[ToolRead]:
    """Tools last observed on a server, with their definition hashes and approval state."""
    repositories.get_or_raise(session, models.MCPServer, server_id, "server")
    rows = session.scalars(
        select(models.ToolDefinition)
        .where(models.ToolDefinition.server_id == server_id)
        .order_by(models.ToolDefinition.name)
    ).all()
    return [repositories.tool_to_read(r) for r in rows]


@router.get("/tools/{tool_id}", response_model=ToolRead)
def get_tool(tool_id: UUID, session: SessionDep) -> ToolRead:
    """Fetch one tool definition."""
    tool = repositories.get_or_raise(session, models.ToolDefinition, tool_id, "tool")
    return repositories.tool_to_read(tool)


@router.post("/tools/{tool_id}/approve", response_model=ToolRead)
def approve_tool(tool_id: UUID, body: ActorBody, session: SessionDep) -> ToolRead:
    """Pin the tool's *current* definition hash as approved (a decision, not a safety verification)."""
    tool = repositories.get_or_raise(session, models.ToolDefinition, tool_id, "tool")
    repositories.approve_tool(session, tool, body.actor)
    session.commit()
    return repositories.tool_to_read(tool)


@router.post("/tools/{tool_id}/revoke", response_model=ToolRead)
def revoke_tool(tool_id: UUID, session: SessionDep) -> ToolRead:
    """Withdraw approval and forget the pinned hash."""
    tool = repositories.get_or_raise(session, models.ToolDefinition, tool_id, "tool")
    repositories.revoke_tool(session, tool)
    session.commit()
    return repositories.tool_to_read(tool)
