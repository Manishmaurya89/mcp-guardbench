"""The fixture allowlist.

Fixtures are resolved *only* through this static registry. A fixture name from a test
case, an API request, or the CLI is looked up as a dictionary key; it is never used to
build an import path, a file path, or a command line.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from guardbench.domain.errors import UnknownFixtureError
from guardbench.mcp_lab.base import LabFixture
from guardbench.mcp_lab.servers.clean_server import CleanServer
from guardbench.mcp_lab.servers.drift_server import DriftServer
from guardbench.mcp_lab.servers.excessive_permission_server import ExcessivePermissionServer
from guardbench.mcp_lab.servers.oversized_response_server import OversizedResponseServer
from guardbench.mcp_lab.servers.poisoned_description_server import PoisonedDescriptionServer
from guardbench.mcp_lab.servers.poisoned_schema_server import PoisonedSchemaServer
from guardbench.mcp_lab.servers.response_injection_server import ResponseInjectionServer
from guardbench.mcp_lab.servers.secret_flow_server import SecretFlowServer

_FIXTURE_CLASSES: tuple[type[LabFixture], ...] = (
    CleanServer,
    DriftServer,
    ExcessivePermissionServer,
    OversizedResponseServer,
    PoisonedDescriptionServer,
    PoisonedSchemaServer,
    ResponseInjectionServer,
    SecretFlowServer,
)

#: Read-only view of the allowlist: fixture name -> class.
REGISTRY: Mapping[str, type[LabFixture]] = MappingProxyType({cls.name: cls for cls in _FIXTURE_CLASSES})


@dataclass(frozen=True, slots=True)
class FixtureInfo:
    """Public description of an allowlisted fixture."""

    name: str
    summary: str
    tool_count: int
    supports_state_advance: bool


def fixture_names() -> list[str]:
    """Sorted names of all allowlisted fixtures."""
    return sorted(REGISTRY)


def is_allowed_fixture(name: str) -> bool:
    """Whether ``name`` is on the allowlist."""
    return name in REGISTRY


def create_fixture(name: str) -> LabFixture:
    """Instantiate a fresh fixture. Raises :class:`UnknownFixtureError` for anything off-list."""
    cls = REGISTRY.get(name)
    if cls is None:
        raise UnknownFixtureError(f"unknown fixture {name!r}; allowed fixtures: {', '.join(fixture_names())}")
    return cls()


def fixture_info() -> list[FixtureInfo]:
    """Describe every allowlisted fixture."""
    infos = []
    for name in fixture_names():
        fixture = create_fixture(name)
        infos.append(
            FixtureInfo(
                name=name,
                summary=fixture.summary,
                tool_count=len(fixture.tool_definitions()),
                supports_state_advance=fixture.supports_state_advance,
            )
        )
    return infos
