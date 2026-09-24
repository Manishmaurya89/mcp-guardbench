"""Structured JSON logging with mandatory redaction.

Every record passes through :class:`RedactingFilter`, so synthetic markers and
credential-shaped strings never reach a log line, even by accident. Records carry the
ambient OpenTelemetry-style ``trace_id`` / ``span_id`` when a trace is active.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from guardbench.runtime.redaction import Redactor
from guardbench.runtime.trace_context import current_trace

SERVICE_NAME = "guardbench"
_STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime", "taskName"}


class RedactingFilter(logging.Filter):
    """Redacts the message, its arguments, and any ``extra`` fields in place."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        super().__init__()
        self._redactor = redactor or Redactor()

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact ``record`` and always let it through."""
        record.msg = self._redactor.redact_text(str(record.getMessage()))
        record.args = None
        for key in list(vars(record)):
            if key not in _STANDARD_ATTRS:
                setattr(record, key, self._redactor.redact(getattr(record, key)))
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line with OpenTelemetry-compatible field names."""

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` as a single JSON line."""
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "severity": record.levelname,
            "service.name": SERVICE_NAME,
            "logger": record.name,
            "body": record.getMessage(),
        }
        trace = current_trace()
        if trace is not None:
            payload["trace_id"] = trace.trace_id
            payload["span_id"] = trace.span_id
            if trace.run_id:
                payload["run_id"] = trace.run_id
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = Redactor().redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, sort_keys=False)


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    """Install one redacting stream handler on the root logger (idempotent)."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_guardbench", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler._guardbench = True  # type: ignore[attr-defined]
    handler.addFilter(RedactingFilter())
    handler.setFormatter(
        JsonFormatter()
        if json_output
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(f"guardbench.{name}")
