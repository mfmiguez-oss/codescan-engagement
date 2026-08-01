"""Properties of the SIEM export.

The trail is already safe to ship; the risk this file guards is that the
*exporter* stops being. A SIEM has broad read access and long retention, so
anything that leaks into an exported event leaks into the worst possible place.
``test_no_exported_field_carries_content_the_audit_withheld`` is the one that
matters: it fails if a future event kind starts carrying prompt text and the
allow-list is not updated to refuse it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engagement.audit import AuditEvent, AuditLog, FileSink, read_events
from engagement.siem import (
    ALLOWED_DETAILS,
    export,
    render,
    summarize,
    to_cef,
    to_ecs,
)

_SENSITIVE = ("prompt", "content", "answer", "source", "snippet", "secret", "text")


def _model_call() -> AuditEvent:
    return AuditEvent(
        kind="model_call",
        detail={
            "phase": "scenarios",
            "deployment": "gpt-5-mini",
            "prompt_sha256": "a" * 64,
            "input_tokens": 100,
            "output_tokens": 20,
            "redactions": 2,
            "calls_so_far": 3,
        },
    )


def _trail(tmp_path: Path) -> Path:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(FileSink(path))
    log.record("run_started", target="acme", run_id="run-001")
    log.dispatch("scenarios", "gpt-5-mini", "b" * 64, 100, 20, 1, 1)
    log.record(
        "run_finished",
        phase="complete",
        calls=1,
        completed=1,
        parked=0,
        unfunded=0,
        redactions=1,
        reviewed_fraction=1.0,
        complete=True,
    )
    return path


# -- the export never widens the disclosure surface --------------------------


def test_a_detail_key_outside_the_allowlist_is_dropped_and_reported() -> None:
    event = AuditEvent(
        kind="model_call",
        detail={"phase": "router", "prompt_text": "the whole prompt"},
    )
    document = to_ecs(event)

    labels = document["labels"]
    assert isinstance(labels, dict)
    assert "prompt_text" not in labels
    assert document["engagement"] == {"dropped_fields": ["prompt_text"]}


def test_an_unclassified_event_ships_its_identity_and_none_of_its_payload() -> None:
    """Failing closed: a new event kind must not ship its detail by default."""
    event = AuditEvent(kind="brand_new_stage", detail={"anything": "at all"})
    document = to_ecs(event)

    assert document["labels"] == {}
    assert document["engagement"] == {"dropped_fields": ["anything"]}
    assert isinstance(document["event"], dict)
    assert document["event"]["action"] == "brand_new_stage"


def test_no_exported_field_carries_content_the_audit_withheld() -> None:
    for kind, allowed in ALLOWED_DETAILS.items():
        for key in allowed:
            assert not any(word in key.lower() for word in _SENSITIVE) or key.endswith(
                "_sha256"
            ), f"{kind}.{key} looks like it could carry content, not a measurement"


def test_the_export_is_a_pure_function_of_the_trail(tmp_path: Path) -> None:
    path = _trail(tmp_path)
    events = read_events(path)
    out, count = export(path, tmp_path / "out.json", "ecs", "acme/run-001")

    assert count == len(events)
    exported = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    sources = {event.timestamp for event in events}
    assert {document["@timestamp"] for document in exported} == sources


# -- the formats are what the collectors expect ------------------------------


def test_ecs_documents_carry_a_timestamp_category_and_observer() -> None:
    document = to_ecs(_model_call(), run="acme/run-001")

    assert document["@timestamp"]
    event = document["event"]
    assert isinstance(event, dict)
    assert event["category"] == ["process"]
    assert event["dataset"] == "engagement.audit"
    assert document["observer"] == {
        "vendor": "codescan",
        "product": "engagement",
        "version": "0.1.0",
    }
    assert document["trace"] == {"id": "acme/run-001"}


def test_a_cef_line_has_the_seven_header_fields() -> None:
    line = to_cef(_model_call())
    header, _, _ = line.partition("|rt=")

    assert line.startswith("CEF:0|codescan|engagement|")
    assert len(header.split("|")) == 7


def test_cef_severity_is_rescaled_rather_than_reused() -> None:
    incomplete = AuditEvent(kind="run_finished", detail={"complete": False})
    severity = int(to_cef(incomplete).split("|")[6])

    assert 0 <= severity <= 10, "an ECS 0-100 severity saturated the CEF field"


def test_an_incomplete_run_is_exported_at_a_higher_severity_than_a_clean_one() -> None:
    clean = AuditEvent(kind="run_finished", detail={"complete": True})
    partial = AuditEvent(kind="run_finished", detail={"complete": False})

    clean_event, partial_event = to_ecs(clean)["event"], to_ecs(partial)["event"]
    assert isinstance(clean_event, dict) and isinstance(partial_event, dict)
    assert partial_event["severity"] > clean_event["severity"], (
        "a half-reviewed backlog is the event an operator most needs to see"
    )


def test_cef_metacharacters_in_a_value_are_escaped() -> None:
    event = AuditEvent(kind="run_started", detail={"target": "a=b|c", "run_id": "r"})
    line = to_cef(event)

    assert "a\\=b" in line


def test_jsonl_passes_the_trail_through_unchanged(tmp_path: Path) -> None:
    events = read_events(_trail(tmp_path))
    rendered = render(events, "jsonl")

    assert [json.loads(line)["kind"] for line in rendered.splitlines()] == [
        event.kind for event in events
    ]


def test_an_unknown_format_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown SIEM format"):
        render([], "splunk-hec")


# -- the file the shipper writes ---------------------------------------------


def test_every_event_in_the_trail_reaches_the_export(tmp_path: Path) -> None:
    path = _trail(tmp_path)
    out, count = export(path, tmp_path / "siem.json", "ecs")

    assert count == 3
    assert len(out.read_text(encoding="utf-8").strip().splitlines()) == 3


def test_an_empty_trail_exports_an_empty_file_rather_than_failing(tmp_path: Path) -> None:
    empty = tmp_path / "audit.jsonl"
    empty.write_text("", encoding="utf-8")
    out, count = export(empty, tmp_path / "siem.json", "cef")

    assert count == 0
    assert out.read_text(encoding="utf-8") == ""


def test_the_summary_counts_every_kind(tmp_path: Path) -> None:
    tally = summarize(read_events(_trail(tmp_path)))

    assert tally == {"run_started": 1, "model_call": 1, "run_finished": 1}
