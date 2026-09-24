"""FastAPI application factory.

Run with ``uvicorn guardbench.api.main:create_app --factory`` (or ``guardbench serve``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from guardbench import __version__
from guardbench.api.middleware import RequestGuardMiddleware, SecurityHeadersMiddleware
from guardbench.api.routes import (
    dashboard,
    findings,
    health,
    metrics,
    projects,
    runs,
    servers,
    test_cases,
    tools,
)
from guardbench.config import Settings, load_settings
from guardbench.db.migrate import upgrade_to_head
from guardbench.db.session import create_all_tables, create_db_engine, create_session_factory
from guardbench.domain.errors import (
    ConflictError,
    GuardBenchError,
    NotFoundError,
    PathNotAllowedError,
    ValidationFailure,
)
from guardbench.logging_config import configure_logging, get_logger
from guardbench.runtime.redaction import Redactor
from guardbench.services.runs import RunRegistry

log = get_logger("api")


def create_app(settings: Settings | None = None, *, engine: Engine | None = None) -> FastAPI:
    """Build the API. Pass ``engine`` to reuse an existing database (tests)."""
    settings = settings or load_settings()
    configure_logging(settings.log_level, json_output=settings.log_json)
    owns_database = engine is None
    engine = engine or create_db_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if settings.dev_mode:
            # Dev-mode convenience. When the app owns the database it applies the real migrations, so
            # a later `alembic upgrade` never collides with tables created behind Alembic's back.
            if owns_database:
                upgrade_to_head(settings.database_url, settings.alembic_ini)
            else:
                create_all_tables(engine)
        log.info("api_started", extra={"dev_mode": settings.dev_mode})
        yield

    app = FastAPI(
        title="MCP-GuardBench",
        version=__version__,
        description=(
            "Local security lab API. It evaluates security controls against intentionally "
            "vulnerable, synthetic MCP fixtures. It never contacts external servers."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    app.state.redactor = Redactor()
    app.state.run_registry = RunRegistry()

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestGuardMiddleware)
    _register_error_handlers(app)
    app.include_router(health.router)
    _include_feature_routers(app)
    return app


#: Every authenticated router. Each declares the API-key dependency and the redacting route class.
FEATURE_ROUTER_MODULES = (projects, servers, tools, test_cases, runs, findings, metrics, dashboard)


def _include_feature_routers(app: FastAPI) -> None:
    """Attach the authenticated routers (each router declares the API-key dependency itself)."""
    for module in FEATURE_ROUTER_MODULES:
        app.include_router(module.router)


def _register_error_handlers(app: FastAPI) -> None:
    def _handler(code: int) -> object:
        async def handle(request: Request, exc: Exception) -> JSONResponse:
            redactor: Redactor = request.app.state.redactor
            return JSONResponse(status_code=code, content={"detail": redactor.redact_text(str(exc))})

        return handle

    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        """422 without echoing the offending input (FastAPI's default reflects submitted values)."""
        redactor: Redactor = request.app.state.redactor
        problems = [
            {
                "loc": [str(part) for part in error.get("loc", ())],
                "msg": redactor.redact_text(str(error.get("msg", ""))),
                "type": str(error.get("type", "")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": problems})

    app.add_exception_handler(RequestValidationError, validation_error)  # type: ignore[arg-type]
    app.add_exception_handler(NotFoundError, _handler(status.HTTP_404_NOT_FOUND))  # type: ignore[arg-type]
    app.add_exception_handler(ConflictError, _handler(status.HTTP_409_CONFLICT))  # type: ignore[arg-type]
    app.add_exception_handler(PathNotAllowedError, _handler(status.HTTP_400_BAD_REQUEST))  # type: ignore[arg-type]
    app.add_exception_handler(ValidationFailure, _handler(422))  # type: ignore[arg-type]
    app.add_exception_handler(GuardBenchError, _handler(status.HTTP_400_BAD_REQUEST))  # type: ignore[arg-type]
