"""Redaction of synthetic markers and real-credential shapes.

Two levels, both deterministic and free of I/O:

* :meth:`Redactor.scrub_credentials` removes anything shaped like a real credential.
  Applied to *every* stored payload, because the lab must only ever hold synthetic values.
* :meth:`Redactor.redact` additionally replaces synthetic marker values with a stable,
  log-safe identifier such as ``[REDACTED:synthetic_secret_1]``. Applied to everything
  that leaves the evidence store: logs, API responses, reports, the dashboard.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from guardbench.domain.markers import CREDENTIAL_PATTERNS, SYNTHETIC_MARKERS, SyntheticMarker

# Numeric code points on purpose: literal invisible characters in source are a review hazard.
# ZWSP, ZWNJ, ZWJ, word joiner, BOM/ZWNBSP, soft hyphen.
_ZERO_WIDTH = dict.fromkeys((0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD), None)
DEPTH_MARKER = "[TRUNCATED:max_depth]"


def _normalize(text: str) -> str:
    """Fold compatibility forms and drop zero-width characters so trivial obfuscation still matches."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


class Redactor:
    """Replaces sensitive content with stable identifiers. Instances are immutable in practice."""

    def __init__(
        self, markers: Sequence[SyntheticMarker] = SYNTHETIC_MARKERS, *, max_depth: int = 16
    ) -> None:
        self._markers = tuple(sorted(markers, key=lambda m: len(m.value), reverse=True))
        self._by_upper = {m.value.upper(): m for m in self._markers}
        alternation = "|".join(re.escape(m.value) for m in self._markers)
        self._marker_re = re.compile(alternation, re.IGNORECASE) if alternation else None
        self._max_depth = max_depth

    # -- text ---------------------------------------------------------------

    def scrub_credentials_text(self, text: str) -> str:
        """Replace real-credential shapes in ``text``."""
        for name, pattern in CREDENTIAL_PATTERNS.items():
            text = pattern.sub(f"[REDACTED:credential:{name}]", text)
        return text

    def redact_text(self, text: str) -> str:
        """Scrub credentials, then replace synthetic marker values with their safe identifiers."""
        text = self.scrub_credentials_text(text)
        if self._marker_re is None:
            return text
        if not self._marker_re.search(text):
            normalized = _normalize(text)
            if not self._marker_re.search(normalized):
                return text
            text = normalized
        return self._marker_re.sub(lambda m: self._by_upper[m.group(0).upper()].redaction_token, text)

    def find_markers_in_text(self, text: str) -> list[SyntheticMarker]:
        """Distinct markers present in ``text`` (case- and obfuscation-tolerant), in registry order."""
        if self._marker_re is None:
            return []
        hits = {m.group(0).upper() for m in self._marker_re.finditer(_normalize(text))}
        return [m for m in self._markers if m.value.upper() in hits]

    # -- structured values --------------------------------------------------

    def redact(self, value: Any) -> Any:
        """Deep-copy ``value`` with credentials scrubbed and marker values replaced."""
        return self._walk(value, self.redact_text, 0)

    def scrub_credentials(self, value: Any) -> Any:
        """Deep-copy ``value`` with only real-credential shapes scrubbed (markers preserved)."""
        return self._walk(value, self.scrub_credentials_text, 0)

    def find_markers(self, value: Any) -> list[SyntheticMarker]:
        """Distinct markers found anywhere inside ``value`` (keys included)."""
        found: dict[str, SyntheticMarker] = {}
        self._collect(value, found, 0)
        return [m for m in self._markers if m.value in found]

    # -- internals ----------------------------------------------------------

    def _walk(self, value: Any, text_fn: Any, depth: int) -> Any:
        if depth > self._max_depth:
            return DEPTH_MARKER
        if isinstance(value, str):
            return text_fn(value)
        if isinstance(value, dict):
            return {
                (text_fn(k) if isinstance(k, str) else str(k)): self._walk(v, text_fn, depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._walk(v, text_fn, depth + 1) for v in value]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, bytes | bytearray):
            return f"<{len(value)} bytes>"
        if isinstance(value, Enum):
            return self._walk(value.value, text_fn, depth + 1)
        if isinstance(value, datetime | date):
            return value.isoformat()
        if isinstance(value, UUID):
            return str(value)
        return text_fn(str(value))

    def _collect(self, value: Any, found: dict[str, SyntheticMarker], depth: int) -> None:
        if depth > self._max_depth:
            return
        if isinstance(value, str):
            for marker in self.find_markers_in_text(value):
                found[marker.value] = marker
        elif isinstance(value, dict):
            for key, item in value.items():
                self._collect(key, found, depth + 1)
                self._collect(item, found, depth + 1)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                self._collect(item, found, depth + 1)
        elif isinstance(value, Enum):
            self._collect(value.value, found, depth + 1)
