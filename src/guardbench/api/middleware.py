"""Small ASGI middleware: request screening and security headers."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

MAX_BODY_BYTES = 1024 * 1024  # 1 MiB: far above any legitimate request to this API

_ESCAPED_NUL = re.compile(rb"\\u0000", re.IGNORECASE)  # a JSON escape for NUL (backslash, u, 0000)
_PERCENT_NUL = re.compile(rb"%00")


def _contains_nul(data: bytes, *, percent_encoded: bool) -> bool:
    """A raw NUL byte, a JSON ``\\u0000`` escape, and (in URLs) a percent-encoded ``%00``."""
    if b"\x00" in data or _ESCAPED_NUL.search(data):
        return True
    return percent_encoded and bool(_PERCENT_NUL.search(data))


class RequestGuardMiddleware:
    """Screen every HTTP request before the application sees it.

    * **Size:** bodies larger than ``max_bytes`` get 413, whether the size is declared or streamed.
    * **NUL characters:** any NUL in the path, query string, or body gets 400. PostgreSQL text
      cannot hold NUL, so such a value would otherwise reach the database and surface as an
      unhandled 500 (SQLite accepts it, which hides the problem in local tests). No legitimate
      client sends one.

    The body is read once (it is bounded), checked, and replayed to the application. Rejecting here,
    rather than raising inside ``receive()``, matters: the framework turns exceptions raised while
    it parses a body into a generic 400/422 and our specific answer would never reach the client.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        target = (
            bytes(scope.get("raw_path") or scope.get("path", "").encode())
            + b"?"
            + bytes(scope.get("query_string", b""))
        )
        if _contains_nul(target, percent_encoded=True):
            await self._reject(send, 400, "request contains a NUL character")
            return
        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send, 413, "request body too large")
            return

        chunks: list[bytes] = []
        total = 0
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":  # the client went away
                return
            chunk = bytes(message.get("body", b""))
            total += len(chunk)
            if total > self.max_bytes:
                await self._reject(send, 413, "request body too large")
                return
            chunks.append(chunk)
            more = bool(message.get("more_body", False))
        body = b"".join(chunks)
        if _contains_nul(body, percent_encoded=False):
            await self._reject(send, 400, "request contains a NUL character")
            return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # later calls are for disconnect notifications

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Send, status: int, detail: str) -> None:
        body = ('{"detail":"' + detail + '"}').encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """Add conservative security headers to every HTTP response (existing values are kept)."""

    HEADERS = {
        b"x-content-type-options": b"nosniff",
        b"cache-control": b"no-store",
        b"referrer-policy": b"no-referrer",
        b"x-frame-options": b"DENY",
    }

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def add_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers.extend((k, v) for k, v in self.HEADERS.items() if k not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, add_headers)
