"""Pagination and output-redaction helpers shared by the routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, Query
from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session


class PageQuery(BaseModel):
    """Validated ``limit`` / ``offset`` query parameters."""

    limit: int
    offset: int


def page_query(
    limit: Annotated[int, Query(ge=1, le=500, description="Page size")] = 50,
    offset: Annotated[int, Query(ge=0, description="Rows to skip")] = 0,
) -> PageQuery:
    """FastAPI dependency for pagination parameters."""
    return PageQuery(limit=limit, offset=offset)


PageDep = Annotated[PageQuery, Depends(page_query)]


def count_rows(session: Session, statement: Select[Any]) -> int:
    """Total rows the (unpaginated) statement would return."""
    return int(session.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0)
