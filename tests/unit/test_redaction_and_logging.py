"""Redaction of synthetic markers and credential shapes, and its enforcement in logging."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

import pytest

from guardbench.domain.markers import SIMULATED_EXTERNAL_DESTINATION, TEST_PRIVATE_RECORD, TEST_SECRET
from guardbench.logging_config import JsonFormatter, RedactingFilter, configure_logging
from guardbench.runtime.redaction import DEPTH_MARKER, Redactor
from guardbench.runtime.trace_context import DeterministicIdSource, TraceContext, current_trace, use_trace

R = Redactor()
SECRET_TOKEN = "[REDACTED:synthetic_secret_1]"


def test_marker_values_are_replaced_by_their_safe_identifiers() -> None:
    text = f"a {TEST_SECRET} b {TEST_PRIVATE_RECORD} c {SIMULATED_EXTERNAL_DESTINATION}"
    assert R.redact_text(text) == (
        "a [REDACTED:synthetic_secret_1] b [REDACTED:synthetic_private_record_1] "
        "c [REDACTED:synthetic_destination_1]"
    )


def test_redaction_is_case_insensitive() -> None:
    assert R.redact_text("x test_secret_123 y") == f"x {SECRET_TOKEN} y"
    assert R.redact_text("x Test_Secret_123 y") == f"x {SECRET_TOKEN} y"


def test_zero_width_obfuscation_does_not_defeat_redaction() -> None:
    zwsp = chr(0x200B)
    obfuscated = "TEST_SEC" + zwsp + "RET_123"
    assert TEST_SECRET not in obfuscated
    assert SECRET_TOKEN in R.redact_text(f"leak: {obfuscated}")
    assert R.find_markers_in_text(obfuscated)[0].marker_id == "synthetic_secret_1"


def test_fullwidth_lookalikes_are_caught() -> None:
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalpha() else c for c in TEST_SECRET)
    assert fullwidth != TEST_SECRET
    assert SECRET_TOKEN in R.redact_text(fullwidth)


def test_structured_values_are_redacted_recursively_including_keys() -> None:
    value = {"body": TEST_SECRET, "nested": [{"x": (TEST_SECRET,)}], TEST_SECRET: 1, "n": 5, "ok": None}
    out = R.redact(value)
    assert TEST_SECRET not in json.dumps(out)
    assert out["body"] == SECRET_TOKEN
    assert out[SECRET_TOKEN] == 1
    assert out["n"] == 5 and out["ok"] is None


def test_redaction_does_not_mutate_its_input() -> None:
    original = {"a": [TEST_SECRET]}
    R.redact(original)
    assert original == {"a": [TEST_SECRET]}


def test_redaction_is_idempotent() -> None:
    once = R.redact({"a": f"{TEST_SECRET} AKIAABCDEFGHIJKLMNOP"})
    assert R.redact(once) == once


class Color(StrEnum):
    RED = "red"


def test_non_json_values_are_normalized_safely() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    uid = uuid4()
    out = R.redact({"b": b"\x00\x01", "e": Color.RED, "d": now, "u": uid, "o": object.__name__})
    assert out["b"] == "<2 bytes>"
    assert out["e"] == "red"
    assert out["d"] == now.isoformat()
    assert out["u"] == str(uid)


def test_arbitrary_objects_are_stringified_then_redacted() -> None:
    class Leaky:
        def __str__(self) -> str:
            return f"secret is {TEST_SECRET}"

    assert TEST_SECRET not in json.dumps(R.redact({"x": Leaky()}))


def test_excessive_nesting_is_cut_off() -> None:
    deep: dict[str, object] = {}
    node = deep
    for _ in range(40):
        child: dict[str, object] = {}
        node["k"] = child
        node = child
    assert DEPTH_MARKER in json.dumps(R.redact(deep))


@pytest.mark.parametrize(
    ("value", "shape"),
    [
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_block"),
        ("AKIAABCDEFGHIJKLMNOP", "aws_access_key_id"),
        ("ghp_" + "a" * 36, "github_token"),
        ("sk-" + "a" * 30, "api_key_sk"),
        ("xoxb-1234567890-abcdefghij", "slack_token"),
        ("Bearer " + "a" * 30, "bearer_token"),
        ("eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4", "jwt"),
        ("password=hunter2hunter2", "password_assignment"),
    ],
)
def test_real_credential_shapes_are_scrubbed_in_both_raw_and_redacted_forms(value: str, shape: str) -> None:
    scrubbed = R.scrub_credentials({"v": f"prefix {value} suffix"})["v"]
    assert value not in scrubbed
    assert f"[REDACTED:credential:{shape}]" in scrubbed
    assert value not in R.redact_text(value)


def test_scrub_credentials_keeps_synthetic_markers_for_flow_analysis() -> None:
    kept = R.scrub_credentials({"body": TEST_SECRET})
    assert kept == {"body": TEST_SECRET}
    assert R.redact(kept) == {"body": SECRET_TOKEN}


def test_find_markers_searches_keys_and_values_in_a_deterministic_order() -> None:
    found = R.find_markers({"a": [TEST_SECRET], TEST_PRIVATE_RECORD: 1})
    # registry order: longest marker value first
    assert [m.marker_id for m in found] == ["synthetic_private_record_1", "synthetic_secret_1"]
    assert R.find_markers({"nothing": "here"}) == []


def test_partial_marker_lookalikes_are_not_flagged() -> None:
    assert R.find_markers({"a": "TEST_SECRET_12"}) == []
    assert R.redact_text("TEST_SECRET_12") == "TEST_SECRET_12"


# ---------------------------------------------------------------- logging


def _record(msg: str, *args: object, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("guardbench.test", logging.INFO, __file__, 1, msg, args or None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_log_filter_redacts_message_arguments_and_extra_fields() -> None:
    record = _record("value is %s", TEST_SECRET, payload={"body": TEST_SECRET}, note=f"x {TEST_SECRET}")
    RedactingFilter().filter(record)
    rendered = JsonFormatter().format(record)
    assert TEST_SECRET not in rendered
    assert SECRET_TOKEN in rendered
    assert json.loads(rendered)["payload"] == {"body": SECRET_TOKEN}


def test_json_formatter_emits_otel_style_fields() -> None:
    record = _record("hello")
    RedactingFilter().filter(record)
    data = json.loads(JsonFormatter().format(record))
    assert data["service.name"] == "guardbench"
    assert data["severity"] == "INFO"
    assert data["body"] == "hello"
    assert "trace_id" not in data


def test_log_lines_carry_the_ambient_trace_when_active() -> None:
    ctx = TraceContext.new_root(DeterministicIdSource("t"), run_id="run-1")
    with use_trace(ctx):
        assert current_trace() == ctx
        data = json.loads(JsonFormatter().format(_record("inside")))
    assert current_trace() is None
    assert data["trace_id"] == ctx.trace_id and data["span_id"] == ctx.span_id and data["run_id"] == "run-1"


def test_exception_text_is_redacted_too() -> None:
    try:
        raise RuntimeError(f"failed with {TEST_SECRET}")
    except RuntimeError:
        import sys

        record = logging.LogRecord("g", logging.ERROR, __file__, 1, "boom", None, sys.exc_info())
    assert TEST_SECRET not in JsonFormatter().format(record)


def test_configured_root_logger_never_emits_marker_values(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("DEBUG", json_output=True)
    caplog.set_level(logging.DEBUG)
    try:
        logging.getLogger("guardbench.check").info("secret=%s", TEST_SECRET, extra={"data": TEST_SECRET})
        handler = next(h for h in logging.getLogger().handlers if getattr(h, "_guardbench", False))
        record = _record("value %s", TEST_SECRET, data={"k": TEST_SECRET})
        assert all(f.filter(record) for f in handler.filters)
        assert TEST_SECRET not in handler.format(record)
    finally:
        for h in list(logging.getLogger().handlers):
            if getattr(h, "_guardbench", False):
                logging.getLogger().removeHandler(h)


def test_configure_logging_is_idempotent() -> None:
    try:
        configure_logging("INFO")
        configure_logging("INFO")
        ours = [h for h in logging.getLogger().handlers if getattr(h, "_guardbench", False)]
        assert len(ours) == 1
    finally:
        for h in list(logging.getLogger().handlers):
            if getattr(h, "_guardbench", False):
                logging.getLogger().removeHandler(h)


# ---------------------------------------------------------------- trace ids


def test_deterministic_ids_reproduce_from_a_seed_and_have_otel_shapes() -> None:
    a, b = DeterministicIdSource("seed"), DeterministicIdSource("seed")
    assert a.new_trace_id() == b.new_trace_id()
    assert len(a.new_span_id()) == 16
    assert DeterministicIdSource("other").new_trace_id() != DeterministicIdSource("seed").new_trace_id()


def test_child_spans_share_the_trace_and_link_to_the_parent() -> None:
    ids = DeterministicIdSource("s")
    root = TraceContext.new_root(ids)
    child = root.child(ids)
    assert child.trace_id == root.trace_id
    assert child.parent_span_id == root.span_id
    assert child.span_id != root.span_id
