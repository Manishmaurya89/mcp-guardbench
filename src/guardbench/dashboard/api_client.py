"""Read-only API client and view-model helpers for the dashboard.

The dashboard never touches the database. It calls the REST API (the "dashboard to API" trust
boundary), which redacts every response. This module contains no Streamlit code so it can be
unit-tested without a browser.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

DEFAULT_TIMEOUT = 15.0
SCOPE_BANNER = "This is a local security lab. Results are experimental. No external server has been scanned."
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class DashboardApiError(RuntimeError):
    """The API could not be reached or returned an error. The message is safe to show."""


class ApiClient:
    """A minimal, read-only client. It only issues GET requests."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        headers = {"X-API-Key": api_key} if api_key else {}
        self._http = client or httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._http.close()

    def get(self, path: str, **params: Any) -> Any:
        """GET ``path`` and return the decoded JSON. Errors become :class:`DashboardApiError`."""
        clean = {k: v for k, v in params.items() if v is not None}
        try:
            response = self._http.get(path, params=clean)
        except httpx.HTTPError as exc:
            raise DashboardApiError(
                f"cannot reach the API ({type(exc).__name__}). Is `guardbench serve` running?"
            ) from exc
        if response.status_code == 401:
            raise DashboardApiError(
                "the API rejected the credentials; set GUARDBENCH_API_KEY for the dashboard"
            )
        if response.status_code == 503:
            raise DashboardApiError("the API is not configured (no API key set on the server)")
        if response.status_code == 404:
            raise DashboardApiError(_detail(response) or "not found")
        if response.status_code >= 400:
            raise DashboardApiError(f"the API returned HTTP {response.status_code}")
        return response.json()

    def get_or_none(self, path: str, **params: Any) -> Any | None:
        """Like :meth:`get`, but a 404 yields ``None`` (for optional resources such as drift)."""
        try:
            return self.get(path, **params)
        except DashboardApiError as exc:
            if "cannot reach" in str(exc) or "rejected" in str(exc):
                raise
            return None

    def all_pages(
        self, path: str, *, page_size: int = 200, max_items: int = 5000, **params: Any
    ) -> list[Any]:
        """Follow pagination and return every item (bounded by ``max_items``)."""
        items: list[Any] = []
        offset = 0
        while len(items) < max_items:
            page = self.get(path, limit=page_size, offset=offset, **params)
            batch = page["items"]
            items.extend(batch)
            offset += len(batch)
            if not batch or offset >= page["total"]:
                break
        return items[:max_items]


def _detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    detail = body.get("detail") if isinstance(body, dict) else None
    return detail if isinstance(detail, str) else ""


# --------------------------------------------------------------------------- view models


def format_rate(value: float | None) -> str:
    """Percent, or ``undefined`` (never 0%) when the metric has no denominator."""
    return "undefined" if value is None else f"{value * 100:.1f}%"


def severity_label(severity: str) -> str:
    """Upper-case severity for tables (plain text: tool-supplied text is never rendered as markup)."""
    return severity.upper()


def sort_by_severity(rows: list[dict[str, Any]], key: str = "severity") -> list[dict[str, Any]]:
    """Most severe first; unknown severities sort last."""
    rank = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    return sorted(rows, key=lambda r: rank.get(str(r.get(key)), len(SEVERITY_ORDER)))


def headline_rows(metrics: list[dict[str, Any]]) -> list[dict[str, str]]:
    """One row per adapter with the four headline rates, from ``/runs/{id}/metrics``."""
    wanted = {
        "detection_rate": "Detection",
        "prevention_rate": "Prevention",
        "false_positive_rate": "False positives",
        "evidence_completeness_rate": "Evidence completeness",
    }
    by_adapter: dict[str, dict[str, str]] = {}
    for m in metrics:
        dims = m.get("dimensions_json", {})
        if m["metric_name"] in wanted and "category" not in dims:
            by_adapter.setdefault(dims.get("adapter", "?"), {"Adapter": dims.get("adapter", "?")})[
                wanted[m["metric_name"]]
            ] = format_rate(m["metric_value"])
    return list(by_adapter.values())


def category_rows(metrics: list[dict[str, Any]], adapter: str) -> list[dict[str, str]]:
    """Per-category coverage, detection, and prevention for one adapter."""
    table: dict[str, dict[str, str]] = {}
    labels = {
        "category_coverage": "Coverage",
        "category_detection_rate": "Detection",
        "category_prevention_rate": "Prevention",
    }
    for m in metrics:
        dims = m.get("dimensions_json", {})
        if m["metric_name"] in labels and dims.get("adapter") == adapter:
            row = table.setdefault(dims["category"], {"Category": dims["category"]})
            row[labels[m["metric_name"]]] = format_rate(m["metric_value"])
    return sorted(table.values(), key=lambda r: r["Category"])


def group_events_by_trace(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Events grouped by trace id, each group in sequence order."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in sorted(events, key=lambda e: e["sequence"]):
        grouped.setdefault(event["trace_id"], []).append(event)
    return grouped


def trace_options(run: dict[str, Any]) -> list[tuple[str, str]]:
    """(label, trace_id) pairs for the trace selector, from the run summary."""
    traces = run.get("summary_json", {}).get("traces", [])
    return [(f"{t['adapter']} / {t['test_case_id']} ({t['status']})", t["trace_id"]) for t in traces]


def timeline_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten events into table rows. Payloads are already redacted by the API."""
    rows = []
    for e in events:
        payload = e.get("redacted_payload_json", {})
        rows.append(
            {
                "#": e["sequence"],
                "time": e["timestamp"][11:23] if isinstance(e.get("timestamp"), str) else "",
                "event": e["event_type"],
                "source": e["source"],
                "tool": e.get("tool_name") or "",
                "decision": e.get("decision") or "",
                "rule": payload.get("matched_rule", ""),
                "tags": ", ".join(e.get("risk_tags", [])),
            }
        )
    return rows


def data_flow_paths(findings: list[dict[str, Any]], trace_id: str | None = None) -> list[dict[str, Any]]:
    """Synthetic data-flow paths (marker ids only) from findings, optionally for one trace."""
    paths = []
    for f in findings:
        evidence = f.get("evidence_json", {}).get("evidence", {})
        if "propagation_path" in evidence and (trace_id is None or evidence.get("trace_id") == trace_id):
            paths.append(
                {
                    "marker": evidence.get("marker_id"),
                    "decision": evidence.get("decision"),
                    "path": evidence["propagation_path"],
                }
            )
    return paths


def load_or_message(loader: Callable[[], Any]) -> tuple[Any | None, str | None]:
    """Run ``loader``; return ``(data, None)`` or ``(None, safe_error_message)``."""
    try:
        return loader(), None
    except DashboardApiError as exc:
        return None, str(exc)
