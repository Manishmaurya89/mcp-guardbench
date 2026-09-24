"""Structural output redaction for the API.

Every JSON response from a router that uses :class:`RedactingRoute` is redacted before it is
sent: synthetic marker values become safe identifiers and credential-shaped strings are
scrubbed. Enforcing this at the route class, instead of trusting each handler to remember,
means a newly added endpoint cannot forget it.

The wrapper **fails closed**: if a JSON response cannot be read and redacted, the client gets
a 500, never the unredacted body.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from guardbench.logging_config import get_logger
from guardbench.runtime.redaction import Redactor

log = get_logger("api.redaction")
_JSON = "application/json"
_REPLACED_HEADERS = {"content-length", "content-type"}


class RedactingRoute(APIRoute):
    """An ``APIRoute`` whose JSON responses always pass through the app's :class:`Redactor`."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        """Wrap the normal handler so JSON bodies are redacted on the way out."""
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            response = await original(request)
            if not response.headers.get("content-type", "").startswith(_JSON):
                return response  # reports (markdown/csv/html) are redacted when they are built
            body = getattr(response, "body", None)
            if not isinstance(body, bytes | bytearray | memoryview):
                log.error("unredactable_json_response", extra={"path": request.url.path})
                return JSONResponse(
                    status_code=500, content={"detail": "response could not be safely redacted"}
                )
            try:
                redactor: Redactor = request.app.state.redactor
                redacted = redactor.redact(json.loads(bytes(body)))
            except Exception:
                log.exception("redaction_failed", extra={"path": request.url.path})
                return JSONResponse(
                    status_code=500, content={"detail": "response could not be safely redacted"}
                )
            headers = {k: v for k, v in response.headers.items() if k.lower() not in _REPLACED_HEADERS}
            return JSONResponse(content=redacted, status_code=response.status_code, headers=headers)

        return handler
