"""The dashboard's API client and view-model helpers (no Streamlit involved)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from guardbench.dashboard.api_client import (
    SCOPE_BANNER,
    ApiClient,
    DashboardApiError,
    category_rows,
    data_flow_paths,
    format_rate,
    group_events_by_trace,
    headline_rows,
    load_or_message,
    severity_label,
    sort_by_severity,
    timeline_rows,
    trace_options,
)


def client_for(handler: Any, api_key: str | None = None) -> ApiClient:
    return ApiClient("http://api.test", api_key, transport=httpx.MockTransport(handler))


def respond(status: int, body: Any = None) -> Any:
    return lambda request: httpx.Response(status, json=body if body is not None else {})


# ---------------------------------------------------------------- the client


def test_only_get_requests_are_ever_sent_and_the_api_key_header_is_attached() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    client = client_for(handler, api_key="lab-key")
    assert client.get("/dashboard-summary") == {"ok": True}
    assert [r.method for r in seen] == ["GET"]
    assert seen[0].headers["x-api-key"] == "lab-key"
    assert not hasattr(client, "post") and not hasattr(client, "put") and not hasattr(client, "delete")


def test_no_api_key_header_is_sent_when_none_is_configured() -> None:
    seen: list[httpx.Request] = []
    client_for(lambda r: seen.append(r) or httpx.Response(200, json={})).get("/x")  # type: ignore[func-returns-value]
    assert "x-api-key" not in seen[0].headers


def test_none_parameters_are_dropped_from_the_query() -> None:
    seen: list[httpx.Request] = []
    client_for(lambda r: seen.append(r) or httpx.Response(200, json={})).get("/x", a=1, b=None)  # type: ignore[func-returns-value]
    assert dict(seen[0].url.params) == {"a": "1"}


@pytest.mark.parametrize(
    ("status", "fragment"),
    [
        (401, "rejected the credentials"),
        (503, "not configured"),
        (404, "not found"),
        (500, "HTTP 500"),
        (422, "HTTP 422"),
    ],
)
def test_http_errors_become_safe_messages(status: int, fragment: str) -> None:
    with pytest.raises(DashboardApiError, match=fragment):
        client_for(respond(status)).get("/x")


def test_a_404_detail_from_the_api_is_shown() -> None:
    with pytest.raises(DashboardApiError, match="no approved baseline"):
        client_for(respond(404, {"detail": "no approved baseline"})).get("/x")


def test_connection_failures_explain_how_to_start_the_api() -> None:
    def boom(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(DashboardApiError, match=r"cannot reach the API.*guardbench serve"):
        client_for(boom).get("/x")


def test_error_messages_never_contain_the_api_key() -> None:
    def boom(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(DashboardApiError) as excinfo:
        client_for(boom, api_key="super-secret-key").get("/x")
    assert "super-secret-key" not in str(excinfo.value)


def test_get_or_none_hides_404_but_not_connection_or_auth_problems() -> None:
    assert client_for(respond(404)).get_or_none("/x") is None
    with pytest.raises(DashboardApiError):
        client_for(respond(401)).get_or_none("/x")


def test_all_pages_follows_pagination_and_is_bounded() -> None:
    rows = [{"n": i} for i in range(23)]

    def handler(request: httpx.Request) -> httpx.Response:
        limit, offset = int(request.url.params["limit"]), int(request.url.params["offset"])
        return httpx.Response(
            200,
            json={
                "items": rows[offset : offset + limit],
                "total": len(rows),
                "limit": limit,
                "offset": offset,
            },
        )

    assert client_for(handler).all_pages("/x", page_size=10) == rows
    assert len(client_for(handler).all_pages("/x", page_size=10, max_items=15)) == 15


def test_all_pages_stops_on_an_empty_page_even_if_total_lies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [], "total": 10**9, "limit": 10, "offset": 0})

    assert client_for(handler).all_pages("/x") == []


def test_load_or_message_returns_data_or_a_safe_message() -> None:
    assert load_or_message(lambda: 5) == (5, None)

    def failing() -> None:
        raise DashboardApiError("nope")

    assert load_or_message(failing) == (None, "nope")


# ---------------------------------------------------------------- view models


def test_rates_are_undefined_not_zero() -> None:
    assert format_rate(None) == "undefined"
    assert format_rate(0.0) == "0.0%"
    assert format_rate(0.5714) == "57.1%"
    assert format_rate(1.0) == "100.0%"


def test_severity_sorting_and_labels() -> None:
    rows = [{"severity": s} for s in ("low", "critical", "weird", "high", "info", "medium")]
    assert [r["severity"] for r in sort_by_severity(rows)] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "weird",
    ]
    assert severity_label("high") == "HIGH"


def metric(name: str, value: float | None, **dims: Any) -> dict[str, Any]:
    return {"metric_name": name, "metric_value": value, "dimensions_json": dims}


def test_headline_rows_group_by_adapter_and_skip_category_metrics() -> None:
    metrics = [
        metric("detection_rate", 1.0, adapter="a"),
        metric("prevention_rate", None, adapter="a"),
        metric("detection_rate", 0.5, adapter="b"),
        metric("detection_rate", 0.9, adapter="a", category="tool_poisoning"),
        metric("cases_completed", 4, adapter="a"),
    ]
    rows = {r["Adapter"]: r for r in headline_rows(metrics)}
    assert rows["a"] == {"Adapter": "a", "Detection": "100.0%", "Prevention": "undefined"}
    assert rows["b"] == {"Adapter": "b", "Detection": "50.0%"}


def test_category_rows_are_per_adapter_and_sorted() -> None:
    metrics = [
        metric("category_coverage", 1.0, adapter="a", category="z_cat"),
        metric("category_detection_rate", 0.5, adapter="a", category="a_cat"),
        metric("category_prevention_rate", None, adapter="a", category="a_cat"),
        metric("category_coverage", 0.2, adapter="other", category="a_cat"),
    ]
    rows = category_rows(metrics, "a")
    assert [r["Category"] for r in rows] == ["a_cat", "z_cat"]
    assert rows[0] == {"Category": "a_cat", "Detection": "50.0%", "Prevention": "undefined"}


def event(seq: int, trace: str = "t1", **kw: Any) -> dict[str, Any]:
    base = {
        "sequence": seq,
        "trace_id": trace,
        "timestamp": "2026-01-01T12:34:56.789012+00:00",
        "event_type": "tool_response",
        "source": "scenario-runner",
        "tool_name": None,
        "decision": None,
        "risk_tags": [],
        "redacted_payload_json": {},
    }
    return {**base, **kw}


def test_events_are_grouped_by_trace_and_ordered() -> None:
    grouped = group_events_by_trace([event(3, "a"), event(1, "b"), event(2, "a")])
    assert [e["sequence"] for e in grouped["a"]] == [2, 3] and next(iter(grouped["b"]))["sequence"] == 1


def test_timeline_rows_extract_the_policy_rule_and_tags() -> None:
    rows = timeline_rows(
        [
            event(
                1,
                event_type="policy_decision",
                decision="deny",
                tool_name="t",
                risk_tags=["POL-007"],
                redacted_payload_json={"matched_rule": "POL-007"},
            )
        ]
    )
    assert rows == [
        {
            "#": 1,
            "time": "12:34:56.789",
            "event": "policy_decision",
            "source": "scenario-runner",
            "tool": "t",
            "decision": "deny",
            "rule": "POL-007",
            "tags": "POL-007",
        }
    ]


def test_trace_options_come_from_the_run_summary() -> None:
    run = {
        "summary_json": {
            "traces": [
                {"adapter": "a", "test_case_id": "TP-001", "status": "completed", "trace_id": "x" * 32}
            ]
        }
    }
    assert trace_options(run) == [("a / TP-001 (completed)", "x" * 32)]
    assert trace_options({"summary_json": {}}) == []


def test_data_flow_paths_use_marker_ids_and_can_be_filtered_by_trace() -> None:
    flow = {
        "evidence_json": {
            "evidence": {
                "marker_id": "synthetic_secret_1",
                "decision": "blocked",
                "trace_id": "t1",
                "propagation_path": ["a:b", "c:d"],
            }
        }
    }
    other = {
        "evidence_json": {
            "evidence": {
                "marker_id": "synthetic_secret_1",
                "decision": "allowed",
                "trace_id": "t2",
                "propagation_path": ["x:y"],
            }
        }
    }
    unrelated = {"evidence_json": {"evidence": {}}}
    assert data_flow_paths([flow, other, unrelated]) == [
        {"marker": "synthetic_secret_1", "decision": "blocked", "path": ["a:b", "c:d"]},
        {"marker": "synthetic_secret_1", "decision": "allowed", "path": ["x:y"]},
    ]
    assert [p["decision"] for p in data_flow_paths([flow, other], trace_id="t2")] == ["allowed"]


def test_the_scope_banner_carries_the_required_labels() -> None:
    lowered = SCOPE_BANNER.lower()
    assert (
        "local security lab" in lowered
        and "experimental" in lowered
        and "no external server has been scanned" in lowered
    )
    assert json.dumps(SCOPE_BANNER)  # plain text
