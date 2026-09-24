"""MCP-GuardBench dashboard (Streamlit). Read-only: it only issues GET requests to the API.

Run with ``guardbench dashboard`` (or ``streamlit run``). Configuration comes from the
environment: ``GUARDBENCH_API_URL`` and, if the API requires one, ``GUARDBENCH_API_KEY``.

Everything shown comes from the API, which redacts synthetic markers. Text supplied by tool
servers is attacker-controlled, so it is shown in tables and code blocks only; this file never
enables HTML in Markdown.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

import streamlit as st

from guardbench.dashboard.api_client import (
    SCOPE_BANNER,
    ApiClient,
    DashboardApiError,
    category_rows,
    data_flow_paths,
    format_rate,
    headline_rows,
    load_or_message,
    severity_label,
    sort_by_severity,
    timeline_rows,
    trace_options,
)

FOOTER = (
    "Approvals are never granted automatically. Simulated approvals exist only for tests and are always "
    "labelled as simulated. Hashes detect change; they do not prove a server is trustworthy."
)


def get_client() -> ApiClient:
    """The API client. Tests inject a ready client through ``st.session_state['api_client']``."""
    injected = st.session_state.get("api_client")
    if injected is not None:
        return injected  # type: ignore[no-any-return]
    return ApiClient(
        os.environ.get("GUARDBENCH_API_URL", "http://127.0.0.1:8000"),
        os.environ.get("GUARDBENCH_API_KEY") or None,
    )


def _finding_label(finding: dict[str, Any]) -> str:
    """The text a finding is listed under in the detail selector."""
    rule = finding["evidence_json"].get("rule_id", "")
    return f"{severity_label(finding['severity'])} {rule}: {finding['title'][:70]} [{finding['id'][:8]}]"


def _uniform_columns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Give every column one type. A column mixing numbers and text (for example ``0.5`` and
    ``"undefined"``) is converted to text so the table always serializes cleanly."""
    mixed = {
        key
        for key in {k for row in rows for k in row}
        if len({type(row[key]) for row in rows if row.get(key) is not None}) > 1
    }
    return [{k: ("" if v is None else str(v)) if k in mixed else v for k, v in row.items()} for row in rows]


def show_table(rows: list[dict[str, Any]], empty: str = "Nothing to show yet.") -> None:
    """A read-only table. ``st.dataframe`` renders cell text literally, never as markup."""
    if rows:
        st.dataframe(_uniform_columns(rows), hide_index=True, width="stretch")
    else:
        st.info(empty)


def fetch(loader: Callable[[], Any]) -> Any | None:
    """Run an API call; show a friendly error and return ``None`` if it fails."""
    data, error = load_or_message(loader)
    if error:
        st.error(error)
    return data


# --------------------------------------------------------------------------- pages


def page_overview(client: ApiClient) -> None:
    """Totals and the headline rates of the latest run."""
    st.header("Overview")
    summary = fetch(lambda: client.get("/dashboard-summary"))
    if summary is None:
        return
    top = st.columns(4)
    top[0].metric("Benchmark runs", summary["total_runs"])
    top[1].metric("Test cases", summary["total_test_cases"])
    top[2].metric("Servers registered", summary["total_servers"])
    top[3].metric("Latest run", str(summary["latest_run_id"])[:8] if summary["latest_run_id"] else "none")
    rates = st.columns(4)
    rates[0].metric("Detection rate", format_rate(summary["detection_rate"]))
    rates[1].metric("Prevention rate", format_rate(summary["prevention_rate"]))
    rates[2].metric("Open findings", summary["open_findings"])
    rates[3].metric("High-severity findings", summary["high_severity_findings"])
    st.caption(
        "Rates come from the reference runtime adapter in the most recent completed run. "
        "'undefined' means a zero denominator, not 0%."
    )
    headlines = summary.get("latest_run_headlines", {})
    if headlines:
        st.subheader("Latest run: every adapter under identical conditions")
        show_table(
            [
                {
                    "Adapter": name,
                    "Detection": format_rate(h.get("detection_rate")),
                    "Prevention": format_rate(h.get("prevention_rate")),
                    "False positives": format_rate(h.get("false_positive_rate")),
                    "Evidence completeness": format_rate(h.get("evidence_completeness_rate")),
                }
                for name, h in headlines.items()
            ]
        )
        st.caption(
            "An alert is not prevention: prevention means the unsafe simulated action was actually blocked."
        )
    else:
        st.info("No completed run yet. Run `make demo` (or `guardbench benchmark run`).")


def page_runs(client: ApiClient) -> None:
    """List runs with filters, then show one run's metrics and results."""
    st.header("Benchmark runs")
    status = st.selectbox("Status", ["(any)", "completed", "running", "pending", "failed", "cancelled"])
    runs = fetch(lambda: client.all_pages("/runs", status=None if status == "(any)" else status))
    if not runs:
        st.info("No runs match. Run `make demo` to create one.")
        return
    show_table(
        [
            {
                "Run": r["id"][:8],
                "Status": r["status"],
                "Started": r["started_at"] or "",
                "Adapters": ", ".join(r["configuration_json"].get("adapters", [])),
                "Cases": r["summary_json"].get("cases", ""),
                "Completed": r["summary_json"].get("completed", ""),
                "Skipped": r["summary_json"].get("skipped", ""),
            }
            for r in runs
        ]
    )
    labels = {f"{r['id'][:8]} ({r['status']}, {(r['started_at'] or '')[:19]})": r for r in runs}
    run = labels[st.selectbox("Run detail", list(labels))]
    st.subheader(f"Run {run['id'][:8]}")
    with st.expander("Configuration"):
        st.json(run["configuration_json"])

    metrics = fetch(lambda: client.get(f"/runs/{run['id']}/metrics"))
    if not metrics:
        return
    st.subheader("Metrics")
    show_table(headline_rows(metrics))
    adapters = sorted(
        {m["dimensions_json"].get("adapter") for m in metrics if m["dimensions_json"].get("adapter")}
    )
    adapter = st.selectbox("Per-category breakdown for", adapters)
    show_table(category_rows(metrics, adapter))
    with st.expander("All metrics (numerator / denominator, undefined reasons)"):
        show_table(
            [
                {
                    "Adapter": m["dimensions_json"].get("adapter", ""),
                    "Category": m["dimensions_json"].get("category", ""),
                    "Metric": m["metric_name"],
                    "Value": "undefined" if m["metric_value"] is None else round(m["metric_value"], 4),
                    "Num": m["dimensions_json"].get("numerator"),
                    "Den": m["dimensions_json"].get("denominator"),
                    "Note": m["dimensions_json"].get("undefined_reason") or "",
                }
                for m in metrics
            ]
        )

    report = (
        fetch(lambda: client.get(f"/runs/{run['id']}/report", format="json"))
        if run["status"]
        in {
            "completed",
            "cancelled",
        }
        else None
    )
    if report:
        st.subheader("Results")
        show_table(
            [
                {
                    "Adapter": r["adapter"],
                    "Case": r["test_case_id"],
                    "Status": r["status"],
                    "Detected": r["detected"],
                    "Prevented": r["blocked"],
                    "Approval": r["required_approval"],
                    "Expectation met": r["expectation_met"],
                    "Unsafe outcomes": ", ".join(r["unsafe_outcomes"]),
                }
                for r in report["results"]
            ]
        )
        cols = st.columns(2)
        cols[0].write(f"**Failed (expectation not met):** {len(report['failed_tests'])}")
        cols[1].write(f"**Skipped:** {len(report['skipped_tests'])}")
        if report["skipped_tests"]:
            with st.expander("Skipped tests and why"):
                show_table(report["skipped_tests"])


def page_findings(client: ApiClient) -> None:
    """Filterable findings with evidence and remediation."""
    st.header("Findings")
    severities = st.multiselect("Severity", ["critical", "high", "medium", "low", "info"], default=[])
    categories_all = [
        "tool_poisoning", "response_injection", "tool_definition_drift", "sensitive_data_flow",
        "excessive_permission", "oversized_response", "schema_risk", "purpose_mismatch",
        "cross_tool_reference", "shadowing", "policy_violation",
    ]  # fmt: skip
    categories = st.multiselect("Category", categories_all, default=[])
    findings = fetch(lambda: client.all_pages("/findings"))
    if not findings:
        st.info("No findings yet.")
        return
    shown = [
        f
        for f in findings
        if (not severities or f["severity"] in severities) and (not categories or f["category"] in categories)
    ]
    shown = sort_by_severity(shown)
    st.caption(f"Showing {len(shown)} of {len(findings)} findings, most severe first.")
    show_table(
        [
            {
                "Severity": severity_label(f["severity"]),
                "Rule": f["evidence_json"].get("rule_id", ""),
                "Category": f["category"],
                "Tool": f["evidence_json"].get("tool_name") or "",
                "Location": f["evidence_json"].get("location") or "",
                "Detected by": f["evidence_json"].get("detected_by") or "",
                "Title": f["title"],
            }
            for f in shown
        ]
    )
    if not shown:
        return
    options = {_finding_label(f): f for f in shown[:300]}
    finding = options[st.selectbox("Finding detail", list(options))]
    ev = finding["evidence_json"]
    st.subheader(finding["title"])
    st.write(
        f"**Severity:** {finding['severity']}   **Confidence:** {finding['confidence']:.2f}   "
        f"**Status:** {finding['status']}   **Deterministic:** {ev.get('deterministic')}"
    )
    st.write("**Description**")
    st.text(finding["description"])
    st.write(f"**Location:** `{ev.get('location')}`")
    st.write("**Matched evidence**")
    st.code(ev.get("matched_evidence") or "(none)", language="text")
    st.write("**Remediation**")
    st.text(finding["remediation"])
    refs = ev.get("evidence_event_ids") or []
    st.write(f"**Evidence references:** {len(refs)} event(s)")
    if refs:
        st.code("\n".join(refs), language="text")
    with st.expander("Raw evidence (redacted)"):
        st.json(ev)


def page_inventory(client: ApiClient) -> None:
    """Registered servers and their tools, hashes, and approval state."""
    st.header("Tool inventory")
    servers = fetch(lambda: client.all_pages("/servers"))
    if not servers:
        st.info("No servers registered. Run `make seed`.")
        return
    show_table(
        [
            {
                "Server": s["name"],
                "Fixture": s["endpoint"].removeprefix("fixture://"),
                "Version": s["version"] or "",
                "Trust": s["trust_status"],
                "Lab phase": s["lab_phase"],
                "Registered": s["created_at"][:19],
            }
            for s in servers
        ]
    )
    server = {s["name"]: s for s in servers}[st.selectbox("Server", [s["name"] for s in servers])]
    tools = fetch(lambda: client.get(f"/servers/{server['id']}/tools"))
    if tools is None:
        return
    show_table(
        [
            {
                "Tool": t["name"],
                "Capabilities": ", ".join(t["capabilities"]),
                "Definition hash": t["definition_hash"][:16] + "...",
                "Approval": t["approval_status"],
                "Drifted": t["drifted"],
                "Last observed": t["observed_at"][:19],
            }
            for t in tools
        ],
        empty="This server has not been scanned yet.",
    )
    with st.expander("Full hashes"):
        show_table(
            [
                {
                    "Tool": t["name"],
                    "Definition hash": t["definition_hash"],
                    "Approved hash": t["approved_hash"] or "",
                }
                for t in tools
            ]
        )
    snapshots = fetch(lambda: client.get(f"/servers/{server['id']}/snapshots"))
    if snapshots:
        with st.expander(f"Snapshots ({len(snapshots)})"):
            show_table(
                [
                    {
                        "Snapshot hash": s["snapshot_hash"],
                        "Tools": s["tool_count"],
                        "Approved baseline": s["is_approved_baseline"],
                        "Taken": s["created_at"][:19],
                    }
                    for s in snapshots
                ]
            )
    st.caption(FOOTER)


def page_drift(client: ApiClient) -> None:
    """Old and new hashes, changed fields, severity, and the recommended action, per server."""
    st.header("Drift")
    servers = fetch(lambda: client.all_pages("/servers"))
    if not servers:
        st.info("No servers registered. Run `make seed`.")
        return
    found = 0
    for server in servers:
        report = client.get_or_none(f"/servers/{server['id']}/drift")
        if report is None:
            continue
        found += 1
        state = "DRIFTED" if report["drifted"] else "unchanged"
        with st.expander(f"{server['name']}: {state}", expanded=report["drifted"]):
            cols = st.columns(3)
            cols[0].metric("Severity", severity_label(report["severity"]))
            cols[1].metric("Recommended action", report["recommended_action"])
            cols[2].metric("Requires review", "yes" if report["requires_review"] else "no")
            st.write("**Old (approved) hash**")
            st.code(report["old_hash"], language="text")
            st.write("**New (current) hash**")
            st.code(report["new_hash"], language="text")
            if report["added_tools"] or report["removed_tools"]:
                st.write(f"Added: {report['added_tools'] or '-'}   Removed: {report['removed_tools'] or '-'}")
            groups = {
                "Descriptions": report["changed_descriptions"],
                "Input schemas": report["changed_input_schemas"],
                "Output schemas": report["changed_output_schemas"],
                "Annotations": report["changed_annotations"],
                "Capabilities": report["changed_capabilities"],
                "Server identity": report["changed_identity"],
            }
            for title, changes in groups.items():
                if changes:
                    st.write(f"**{title}**")
                    show_table(
                        [
                            {
                                "Tool": c["tool_name"],
                                "Field": c["field"],
                                "Old": json.dumps(c["old_value"], sort_keys=True)[:200],
                                "New": json.dumps(c["new_value"], sort_keys=True)[:200],
                            }
                            for c in changes
                        ]
                    )
            if report["reasons"]:
                st.write("**Why this severity**")
                for reason in report["reasons"]:
                    st.text("- " + reason)
    if not found:
        st.info(
            "No server has an approved baseline yet, so drift is undefined. "
            "Approve a snapshot first (`make seed` does)."
        )


def page_traces(client: ApiClient) -> None:
    """A run's event timeline: tool calls, decisions, policy rules, and synthetic data-flow paths."""
    st.header("Trace explorer")
    runs = fetch(lambda: client.get("/runs", status="completed", limit=50))
    if not runs or not runs["items"]:
        st.info("No completed runs yet. Run `make demo`.")
        return
    run_map = {f"{r['id'][:8]} ({(r['started_at'] or '')[:19]})": r for r in runs["items"]}
    run = run_map[st.selectbox("Run", list(run_map))]
    options = trace_options(run)
    if not options:
        st.info("This run has no traces.")
        return
    label_to_trace = dict(options)
    trace_id = label_to_trace[st.selectbox("Trace (adapter / test case)", list(label_to_trace))]
    events = fetch(lambda: client.all_pages(f"/runs/{run['id']}/events", trace_id=trace_id))
    if not events:
        return
    st.subheader("Timeline")
    show_table(timeline_rows(events))

    calls = [
        e
        for e in events
        if e["event_type"]
        in {"tool_call_requested", "tool_call_executed", "tool_call_blocked", "tool_response"}
    ]
    decisions = [e for e in events if e["event_type"] == "policy_decision"]
    left, right = st.columns(2)
    with left:
        st.subheader("Tool calls")
        show_table(timeline_rows(calls), empty="No tool calls in this trace.")
    with right:
        st.subheader("Policy decisions and rules")
        show_table(
            [
                {
                    "#": e["sequence"],
                    "Tool": e.get("tool_name") or "",
                    "Decision": e.get("decision") or "",
                    "Rule": e["redacted_payload_json"].get("matched_rule", ""),
                    "Reason": e["redacted_payload_json"].get("reason", ""),
                }
                for e in decisions
            ],
            empty="No policy decisions in this trace (this adapter enforces no policy).",
        )

    st.subheader("Synthetic data-flow path")
    findings = (
        fetch(lambda: client.all_pages(f"/runs/{run['id']}/findings", category="sensitive_data_flow")) or []
    )
    paths = data_flow_paths(findings, trace_id)
    if paths:
        for p in paths:
            st.write(f"**Marker `{p['marker']}`** was **{p['decision']}**")
            st.code("  ->  ".join(p["path"]), language="text")
        st.caption("Only safe marker identifiers are shown, never the synthetic values themselves.")
    else:
        st.info("No synthetic marker flow was recorded for this trace.")

    with st.expander("Event detail (redacted payloads)"):
        for e in events:
            st.write(f"**#{e['sequence']} {e['event_type']}** ({e['source']})")
            st.json(e["redacted_payload_json"])


PAGES: dict[str, Callable[[ApiClient], None]] = {
    "Overview": page_overview,
    "Benchmark Runs": page_runs,
    "Findings": page_findings,
    "Tool Inventory": page_inventory,
    "Drift": page_drift,
    "Trace Explorer": page_traces,
}


def main() -> None:
    """Render the dashboard."""
    st.set_page_config(page_title="MCP-GuardBench", page_icon=":shield:", layout="wide")
    st.title("MCP-GuardBench")
    st.caption(
        "An evidence-based benchmark and runtime evaluation framework for secure MCP tool-using agents."
    )
    st.warning(SCOPE_BANNER)
    page = st.sidebar.radio("Page", list(PAGES))
    st.sidebar.caption("Read-only view. Data comes from the local API and is redacted.")
    client = get_client()
    try:
        PAGES[page](client)
    except DashboardApiError as exc:
        st.error(str(exc))
    st.divider()
    st.caption(FOOTER)


main()
