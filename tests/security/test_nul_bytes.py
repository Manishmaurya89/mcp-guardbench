"""NUL characters are refused at the API boundary (PostgreSQL text cannot hold them)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi.testclient import TestClient

from guardbench.api.middleware import RequestGuardMiddleware

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    ("method", "url", "kwargs"),
    [
        ("GET", "/test-cases?category=%00", {}),
        ("GET", "/test-cases?category=a%00b", {}),
        ("GET", "/findings?severity=high%00", {}),
        ("GET", "/test-cases/TP%00001", {}),
        ("GET", "/projects?limit=1&offset=%00", {}),
        (
            "POST",
            "/projects",
            {"content": '{"name": "a\\u0000b"}', "headers": {"content-type": "application/json"}},
        ),
        (
            "POST",
            "/projects",
            {"content": '{"name": "a\\U0000b"}', "headers": {"content-type": "application/json"}},
        ),
        (
            "POST",
            "/projects",
            {"content": b'{"name": "a\x00b"}', "headers": {"content-type": "application/json"}},
        ),
        ("POST", "/test-cases/validate", {"json": {"yaml": "id: TP-001\nname: \x00"}}),
    ],
)
def test_nul_characters_are_rejected_with_400_everywhere(
    client: TestClient, method: str, url: str, kwargs: dict[str, Any]
) -> None:
    response = client.request(method, url, **kwargs)
    assert response.status_code == 400, (url, response.text)
    assert response.json() == {"detail": "request contains a NUL character"}


def test_nothing_is_stored_when_a_body_is_rejected(client: TestClient) -> None:
    client.post("/projects", content='{"name": "ghost\\u0000"}', headers={"content-type": "application/json"})
    assert client.get("/projects").json()["total"] == 0


@pytest.mark.parametrize(
    ("method", "url", "kwargs"),
    [
        ("GET", "/test-cases?category=tool_poisoning", {}),
        ("GET", "/test-cases/TP-001", {}),
        ("POST", "/projects", {"json": {"name": "fine"}}),
        (
            "POST",
            "/projects",
            {"json": {"name": "fine-name", "description": "text with u0000 and 100%00 in it"}},
        ),
    ],
)
def test_legitimate_requests_are_unaffected(
    client: TestClient, method: str, url: str, kwargs: dict[str, Any]
) -> None:
    assert client.request(method, url, **kwargs).status_code in {200, 201}


def test_an_escape_split_across_two_body_chunks_is_still_caught() -> None:
    """The body is reassembled before it is checked, so `\\u00` + `00` cannot slip through."""
    seen: list[bytes] = []
    responses: list[dict[str, Any]] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            seen.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    chunks = [
        {"type": "http.request", "body": b'{"name": "a\\u00', "more_body": True},
        {"type": "http.request", "body": b'00b"}', "more_body": False},
    ]

    async def receive() -> Any:
        return chunks.pop(0)

    async def send(message: Any) -> None:
        responses.append(message)

    scope = {"type": "http", "path": "/x", "raw_path": b"/x", "query_string": b"", "headers": []}
    asyncio.run(RequestGuardMiddleware(app)(scope, receive, send))
    assert responses[0]["status"] == 400, "the split escape should have been detected"


def test_non_http_scopes_pass_straight_through() -> None:
    calls: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        calls.append(scope["type"])

    asyncio.run(RequestGuardMiddleware(app)({"type": "lifespan"}, None, None))  # type: ignore[arg-type]
    assert calls == ["lifespan"]


def test_oversized_streamed_bodies_without_a_content_length_get_413() -> None:
    """The size limit also holds for chunked uploads that never declare a length."""
    responses: list[dict[str, Any]] = []
    reached_app: list[bool] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        reached_app.append(True)

    chunks = [{"type": "http.request", "body": b"a" * (512 * 1024), "more_body": True} for _ in range(3)]
    chunks.append({"type": "http.request", "body": b"", "more_body": False})

    async def receive() -> Any:
        return chunks.pop(0)

    async def send(message: Any) -> None:
        responses.append(message)

    scope = {"type": "http", "path": "/x", "raw_path": b"/x", "query_string": b"", "headers": []}
    asyncio.run(RequestGuardMiddleware(app)(scope, receive, send))
    assert responses[0]["status"] == 413 and not reached_app


def test_a_body_within_the_limit_is_replayed_intact_to_the_application() -> None:
    received: list[bytes] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        message = await receive()
        received.append(message["body"])
        assert message["more_body"] is False

    chunks = [
        {"type": "http.request", "body": b'{"name":', "more_body": True},
        {"type": "http.request", "body": b' "ok"}', "more_body": False},
    ]

    async def receive() -> Any:
        return chunks.pop(0)

    scope = {"type": "http", "path": "/x", "raw_path": b"/x", "query_string": b"", "headers": []}
    asyncio.run(RequestGuardMiddleware(app)(scope, receive, lambda m: None))  # type: ignore[arg-type, return-value]
    assert received == [b'{"name": "ok"}']
