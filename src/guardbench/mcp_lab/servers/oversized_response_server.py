"""Oversized-response fixture: a deterministic response far above any sane size limit.

The filler is a fixed, harmless line repeated. It contains no sensitive or hostile content, so
this case isolates *size handling* from injection or data-flow handling.
"""

from __future__ import annotations

from typing import Any, ClassVar

from guardbench.domain.schemas import CAPABILITIES_META_KEY, ToolDefinitionData
from guardbench.mcp_lab.base import LabFixture, ToolCallResult

FILLER_LINE = "GUARDBENCH-FILLER 0123456789 abcdefghijklmnopqrstuvwxyz\n"
RESPONSE_BYTES = 64 * 1024  # 16x the default 4 KiB limit


class OversizedResponseServer(LabFixture):
    """A report generator that returns 64 KiB of filler."""

    name: ClassVar[str] = "oversized_response_server"
    summary: ClassVar[str] = "Returns a deterministic 64 KiB response (resource-exhaustion control)."

    def tool_definitions(self) -> list[ToolDefinitionData]:
        """A single read-only tool."""
        return [
            ToolDefinitionData(
                name="generate_report",
                description="Generate a long synthetic report.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
                meta={CAPABILITIES_META_KEY: ["read"]},
            )
        ]

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> ToolCallResult:
        if name == "generate_report":
            repeats = RESPONSE_BYTES // len(FILLER_LINE) + 1
            return ToolCallResult((FILLER_LINE * repeats)[:RESPONSE_BYTES])
        return ToolCallResult(f"unknown tool '{name}'", is_error=True)
