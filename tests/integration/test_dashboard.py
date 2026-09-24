"""The Streamlit dashboard, driven headlessly with ``AppTest`` against a real, seeded API."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from streamlit.testing.v1 import AppTest

import guardbench.dashboard as dashboard_package
from guardbench.dashboard.api_client import ApiClient
from guardbench.db.session import session_scope
from guardbench.domain.markers import MARKER_VALUES
from guardbench.services.demo import seed_demo

APP = Path(dashboard_package.__file__).resolve().parent / "app.py"
ADAPTERS = ["no-defense-baseline", "reference-static", "reference-runtime"]
PAGES = ["Overview", "Benchmark Runs", "Findings", "Tool Inventory", "Drift", "Trace Explorer"]


@pytest.fixture
def seeded(client: TestClient, session_factory: sessionmaker[Session]) -> TestClient:
    """The API with demo servers seeded and one full benchmark run executed."""
    with session_scope(session_factory) as session:
        seed_demo(session)
    project = client.get("/projects").json()["items"][0]["id"]
    run = client.post("/runs", json={"project_id": project, "adapters": ADAPTERS}).json()["id"]
    assert client.post(f"/runs/{run}/execute").status_code == 200
    return client


def open_dashboard(test_client: TestClient) -> AppTest:
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.session_state["api_client"] = ApiClient("http://testserver", client=test_client)
    return at.run()


def go(at: AppTest, page: str) -> AppTest:
    at.sidebar.radio[0].set_value(page)
    return at.run()


def page_text(at: AppTest) -> str:
    """Every string the page currently renders."""
    parts: list[str] = []
    for kind in (
        "title",
        "header",
        "subheader",
        "markdown",
        "caption",
        "text",
        "code",
        "warning",
        "info",
        "error",
        "success",
    ):
        parts.extend(str(e.value) for e in getattr(at, kind))
    for metric in at.metric:
        parts.extend([str(metric.label), str(metric.value)])
    for js in at.json:
        parts.append(str(js.value))
    for frame in at.dataframe:
        parts.append(frame.value.to_csv(index=False))
    for select in at.selectbox:
        parts.extend([str(select.label), *[str(o) for o in select.options]])
    for expander in at.expander:
        parts.append(str(expander.label))
    return "\n".join(parts)


def assert_healthy(at: AppTest) -> None:
    assert not at.exception, [e.value for e in at.exception]


# ---------------------------------------------------------------- the frame


def test_every_page_carries_the_required_labels(seeded: TestClient) -> None:
    at = open_dashboard(seeded)
    assert_healthy(at)
    assert at.title[0].value == "MCP-GuardBench"
    for page in PAGES:
        text = page_text(go(at, page)).lower()
        assert "local security lab" in text and "experimental" in text, page
        assert "no external server has been scanned" in text, page
        assert "never granted automatically" in text, page


def test_the_sidebar_offers_exactly_the_six_required_pages(seeded: TestClient) -> None:
    at = open_dashboard(seeded)
    assert list(at.sidebar.radio[0].options) == PAGES


def test_the_dashboard_is_read_only_by_construction() -> None:
    source = "\n".join(p.read_text(encoding="utf-8") for p in APP.parent.glob("*.py"))
    assert "unsafe_allow_html" not in source, "tool text is attacker-controlled; HTML must stay disabled"
    for verb in (".post(", ".put(", ".delete(", ".patch("):
        assert verb not in source, verb
    assert not re.search(r"st\.(button|form|text_input|file_uploader)\(", source), (
        "no controls that could mutate state"
    )


# ---------------------------------------------------------------- pages with data


def test_overview_shows_totals_and_the_headline_rates(seeded: TestClient) -> None:
    at = open_dashboard(seeded)
    assert_healthy(at)
    metrics = {m.label: m.value for m in at.metric}
    assert (
        metrics["Benchmark runs"] == "1"
        and metrics["Test cases"] == "9"
        and metrics["Servers registered"] == "8"
    )
    assert metrics["Detection rate"] == "100.0%" and metrics["Prevention rate"] == "100.0%"
    assert int(metrics["Open findings"]) > 0 and int(metrics["High-severity findings"]) > 0
    table = at.dataframe[0].value.set_index("Adapter")
    assert table.loc["no-defense-baseline", "Prevention"] == "0.0%"
    assert (
        table.loc["reference-static", "Prevention"] == "0.0%"
        and table.loc["reference-static", "Detection"] == "57.1%"
    )
    assert table.loc["reference-runtime", "Detection"] == "100.0%"


def test_overview_on_an_empty_database_says_undefined_not_zero(client: TestClient) -> None:
    at = open_dashboard(client)
    assert_healthy(at)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Detection rate"] == "undefined" and metrics["Prevention rate"] == "undefined"
    assert metrics["Benchmark runs"] == "0"
    assert any("No completed run" in i.value for i in at.info)


def test_every_page_renders_with_data_and_without_errors(seeded: TestClient) -> None:
    at = open_dashboard(seeded)
    for page in PAGES:
        go(at, page)
        assert_healthy(at)
        assert not at.error, (page, [e.value for e in at.error])


def test_benchmark_runs_page_lists_runs_and_shows_metrics_and_results(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Benchmark Runs")
    text = page_text(at)
    assert "completed" in text and "reference-runtime" in text
    assert "Per-category breakdown" in text and "Skipped" in text
    results = next(f.value for f in at.dataframe if "Expectation met" in f.value.columns)
    assert len(results) == 27
    attack = ~results["Case"].str.startswith("BN")
    runtime = results[(results["Adapter"] == "reference-runtime") & attack]
    assert len(runtime) == 7 and runtime["Prevented"].all() and runtime["Expectation met"].all()
    controls = results[(results["Adapter"] == "reference-runtime") & ~attack]
    assert not controls["Prevented"].any() and controls["Expectation met"].all(), (
        "nothing to prevent in a control"
    )
    baseline = results[(results["Adapter"] == "no-defense-baseline") & attack]
    assert not baseline["Prevented"].any() and not baseline["Detected"].any()


def test_benchmark_runs_page_can_filter_by_status(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Benchmark Runs")
    at.selectbox[0].set_value("failed").run()
    assert_healthy(at)
    assert any("No runs match" in i.value for i in at.info)


def test_findings_page_filters_by_severity_and_shows_evidence_and_remediation(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Findings")
    assert_healthy(at)
    everything = at.dataframe[0].value
    assert set(everything["Severity"]) >= {"CRITICAL", "HIGH", "MEDIUM"}
    order = list(everything["Severity"])
    assert order == sorted(order, key=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index), (
        "most severe first"
    )

    at.multiselect[0].set_value(["critical"]).run()
    assert set(at.dataframe[0].value["Severity"]) == {"CRITICAL"}
    detail = page_text(at)
    assert "Remediation" in detail and "Matched evidence" in detail and "Evidence references" in detail
    assert "Location:" in detail

    at.multiselect[0].set_value([]).run()
    at.multiselect[1].set_value(["sensitive_data_flow"]).run()
    assert set(at.dataframe[0].value["Category"]) == {"sensitive_data_flow"}


def test_tool_inventory_shows_servers_tools_hashes_and_approval_state(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Tool Inventory")
    assert_healthy(at)
    servers = at.dataframe[0].value.set_index("Server")
    assert len(servers) == 8
    assert (
        servers.loc["drift_server", "Trust"] == "quarantined"
        and servers.loc["drift_server", "Lab phase"] == 1
    )
    assert servers.loc["clean_server", "Trust"] == "trusted"

    at.selectbox[0].set_value("drift_server").run()
    tools = at.dataframe[1].value.set_index("Tool")
    assert tools.loc["lookup_record", "Drifted"] and not tools.loc["list_record_ids", "Drifted"]
    assert tools.loc["lookup_record", "Definition hash"].endswith("...")
    assert {"Approval", "Last observed", "Capabilities"} <= set(tools.columns)


def test_drift_page_shows_hashes_changed_fields_severity_and_action(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Drift")
    assert_healthy(at)
    labels = [e.label for e in at.expander]
    assert any("drift_server: DRIFTED" in label for label in labels)
    assert any("clean_server: unchanged" in label for label in labels)
    values = [
        m.value for m in at.metric
    ]  # one trio per server: do not key by label, later servers would overwrite
    assert "HIGH" in values and "block_until_reviewed" in values
    assert "INFO" in values and "none" in values, "the unchanged servers are shown as such"
    hashes = [c.value for c in at.code if re.fullmatch(r"[0-9a-f]{64}", str(c.value))]
    assert len(hashes) >= 2 and hashes[0] != hashes[1], (
        "old and new hashes are both shown and differ for the drifted server"
    )
    changed = next(f.value for f in at.dataframe if {"Tool", "Field", "Old", "New"} <= set(f.value.columns))
    assert "lookup_record" in set(changed["Tool"])
    text = page_text(at)
    assert "Why this severity" in text and "capabilities escalated" in text


def test_trace_explorer_shows_the_timeline_decisions_and_the_data_flow_path(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Trace Explorer")
    assert_healthy(at)
    trace_select = at.selectbox[1]
    assert "reference-runtime / DF-001 (completed)" in trace_select.options
    at.selectbox[1].set_value("reference-runtime / DF-001 (completed)").run()
    assert_healthy(at)

    timeline = at.dataframe[0].value
    assert timeline["#"].is_monotonic_increasing
    assert {"tools_listed", "tool_call_requested", "policy_decision", "data_flow"} <= set(timeline["event"])
    decisions = next(f.value for f in at.dataframe if "Decision" in f.value.columns)
    assert ("deny", "POL-007") in set(zip(decisions["Decision"], decisions["Rule"], strict=True))

    text = page_text(at)
    assert "synthetic_secret_1" in text and "blocked" in text
    path = next(str(c.value) for c in at.code if "fixture_source:" in str(c.value))
    assert path.count("->") == 3 and "outbound_request:send_notification" in path


def test_trace_explorer_for_the_baseline_shows_no_policy_decisions(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Trace Explorer")
    at.selectbox[1].set_value("no-defense-baseline / TP-001 (completed)").run()
    assert_healthy(at)
    assert any("enforces no policy" in i.value for i in at.info)


# ---------------------------------------------------------------- safety


def test_no_synthetic_marker_value_is_ever_rendered_on_any_page(seeded: TestClient) -> None:
    at = open_dashboard(seeded)
    for page in PAGES:
        go(at, page)
        text = page_text(at).lower()
        assert not any(m.lower() in text for m in MARKER_VALUES), f"marker rendered on {page}"
    # exercise the pages that show evidence in depth
    go(at, "Findings")
    for option in list(at.selectbox[0].options)[:40]:
        at.selectbox[0].set_value(option).run()
        assert not any(m.lower() in page_text(at).lower() for m in MARKER_VALUES), option
    go(at, "Trace Explorer")
    for label in list(at.selectbox[1].options):
        at.selectbox[1].set_value(label).run()
        assert not any(m.lower() in page_text(at).lower() for m in MARKER_VALUES), label


def test_redaction_identifiers_are_visible_instead_of_values(seeded: TestClient) -> None:
    at = go(open_dashboard(seeded), "Findings")
    at.multiselect[1].set_value(["tool_poisoning"]).run()
    seen = "\n".join(
        page_text(at.selectbox[0].set_value(o).run()) for o in list(at.selectbox[0].options)[:60]
    )
    assert "[REDACTED:synthetic_secret_1]" in seen


def test_when_the_api_is_unreachable_the_page_shows_a_friendly_error_not_a_stack_trace(
    client: TestClient,
) -> None:
    import httpx

    def boom(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    at = AppTest.from_file(str(APP), default_timeout=60)
    at.session_state["api_client"] = ApiClient("http://api.test", transport=httpx.MockTransport(boom))
    at.run()
    assert not at.exception
    assert any("cannot reach the API" in e.value for e in at.error)
    assert at.title[0].value == "MCP-GuardBench", "the frame still renders"


def test_when_the_api_rejects_the_key_the_dashboard_says_so(client: TestClient) -> None:
    import httpx

    at = AppTest.from_file(str(APP), default_timeout=60)
    at.session_state["api_client"] = ApiClient(
        "http://api.test", transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"detail": "no"}))
    )
    at.run()
    assert not at.exception and any("rejected the credentials" in e.value for e in at.error)


def test_hostile_tool_text_in_findings_is_rendered_as_plain_text(seeded: TestClient) -> None:
    """The poisoned fixture's <IMPORTANT> block must appear only inside code/text elements."""
    at = go(open_dashboard(seeded), "Findings")
    at.multiselect[1].set_value(["tool_poisoning"]).run()
    for option in list(at.selectbox[0].options)[:60]:
        at.selectbox[0].set_value(option).run()
        assert_healthy(at)
        for element in at.markdown:
            assert "<IMPORTANT>" not in str(element.value), "hostile markup reached a markdown element"
