"""Health endpoint and API-key enforcement."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardbench.api.dependencies import AuthDep, get_session


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert "local security lab" in body["notice"].lower()


def test_health_needs_no_api_key_even_outside_dev_mode(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(app_factory(dev_mode=False)) as c:
        assert c.get("/health").status_code == 200


def test_health_reports_degraded_when_database_fails(app_factory: Callable[..., FastAPI]) -> None:
    class BrokenSession:
        def execute(self, *_a: Any, **_k: Any) -> None:
            raise RuntimeError("database down")

        def rollback(self) -> None: ...
        def close(self) -> None: ...

    app = app_factory()
    app.dependency_overrides[get_session] = lambda: iter([BrokenSession()])
    with TestClient(app) as c:
        response = c.get("/health")
    assert response.status_code == 200
    assert response.json() == {**response.json(), "status": "degraded", "database": "unavailable"}
    assert "database down" not in response.text  # no internals leaked


def _protected_app(app_factory: Callable[..., FastAPI], **overrides: Any) -> FastAPI:
    app = app_factory(**overrides)

    @app.get("/protected", dependencies=[AuthDep])
    def protected() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_dev_mode_skips_api_key(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(_protected_app(app_factory, dev_mode=True)) as c:
        assert c.get("/protected").status_code == 200


def test_non_dev_mode_fails_closed_without_configured_key(app_factory: Callable[..., FastAPI]) -> None:
    with TestClient(_protected_app(app_factory, dev_mode=False)) as c:
        response = c.get("/protected")
    assert response.status_code == 503
    assert "GUARDBENCH_API_KEY" in response.json()["detail"]


def test_non_dev_mode_requires_matching_key(app_factory: Callable[..., FastAPI]) -> None:
    app = _protected_app(app_factory, dev_mode=False, api_key="correct-local-lab-key")
    with TestClient(app) as c:
        assert c.get("/protected").status_code == 401
        assert c.get("/protected", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/protected", headers={"X-API-Key": "correct-local-lab-key"}).status_code == 200
