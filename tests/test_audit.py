"""The audit trail: complete, append-only, and safe to ship."""

from __future__ import annotations

from pathlib import Path

import pytest

from engagement.audit import AuditLog, FileSink, MemorySink, read_events
from engagement.budget import Ledger
from engagement.contracts import Priority, RunRef
from engagement.driver import Driver, Policy
from engagement.providers import FakeProvider
from fakes import FakeWorkspace, scenarios

REF = RunRef(target="acme", run_id="run-001")


def _run(sink: MemorySink, **workspace_kwargs: object) -> object:
    workspace = FakeWorkspace(
        scenarios=scenarios(("S001", Priority.normal)),
        candidates_per_scenario=1,
        **workspace_kwargs,  # type: ignore[arg-type]
    )
    return Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}"),
        ledger=Ledger(),
        policy=Policy(model="m"),
        audit=AuditLog(sink),
    ).run(REF)


def test_every_model_call_is_recorded() -> None:
    """Counting calls in memory is not an audit trail: the ledger knows there
    were two, and cannot say what either of them was."""
    sink = MemorySink()
    _run(sink)

    calls = [e for e in sink.events if e.kind == "model_call"]
    assert len(calls) == 2  # one expert, one triage
    for event in calls:
        assert event.detail["deployment"] == "m"
        assert len(str(event.detail["prompt_sha256"])) == 64
        assert event.detail["phase"] in {"scenarios", "triage"}


def test_the_run_is_bracketed_by_start_and_finish() -> None:
    sink = MemorySink()
    _run(sink)

    kinds = [e.kind for e in sink.events]
    assert kinds[0] == "run_started"
    assert kinds[-1] == "run_finished"

    finished = sink.events[-1].detail
    assert finished["complete"] is True
    assert finished["reviewed_fraction"] == 1.0


def test_the_outcome_records_what_was_not_done() -> None:
    """The audit trail carries the denominator, not just the successes."""
    sink = MemorySink()
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.status_for["S001"] = "needs_context"
    Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}"),
        ledger=Ledger(),
        policy=Policy(model="m", expand_context=False),
        audit=AuditLog(sink),
    ).run(REF)

    finished = sink.events[-1].detail
    assert finished["parked"] == 1
    assert finished["complete"] is False


def test_no_prompt_text_or_model_output_is_recorded() -> None:
    """The trail must be safe to ship to a log platform that the source under
    review is not."""
    sink = MemorySink()
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.prompt_extra = '\nsecret_marker = "AKIAIOSFODNN7EXAMPLE"\n'
    Driver(
        workspace=workspace,
        provider=FakeProvider(default='{"marker": "model-said-this"}'),
        ledger=Ledger(),
        policy=Policy(model="m"),
        audit=AuditLog(sink),
    ).run(REF)

    serialized = "\n".join(e.model_dump_json() for e in sink.events)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "secret_marker" not in serialized
    assert "model-said-this" not in serialized
    assert "review the material below" not in serialized


def test_redactions_are_counted_in_the_trail() -> None:
    sink = MemorySink()
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.prompt_extra = '\nkey = "AKIAIOSFODNN7EXAMPLE"\n'
    Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}"),
        ledger=Ledger(),
        policy=Policy(model="m"),
        audit=AuditLog(sink),
    ).run(REF)

    calls = [e for e in sink.events if e.kind == "model_call"]
    assert any(int(str(e.detail["redactions"])) >= 1 for e in calls)


def test_the_file_sink_appends_rather_than_replaces(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(FileSink(path))
    log.record("first", n=1)
    log.record("second", n=2)

    events = read_events(path)
    assert [e.kind for e in events] == ["first", "second"]


def test_a_write_failure_is_an_error_not_a_warning(tmp_path: Path) -> None:
    """A run that cannot record what it is doing should stop doing it."""
    blocked = tmp_path / "audit.jsonl"
    blocked.mkdir()  # a directory where the log expects a file
    with pytest.raises(OSError):
        AuditLog(FileSink(blocked)).record("anything")


def test_a_corrupt_audit_line_is_an_error_not_a_skip(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"kind": "ok", "detail": {}}\nnot json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="unreadable audit event"):
        read_events(path)


def test_an_unaudited_run_is_an_explicit_choice() -> None:
    """The default sink records nothing, but it is named rather than implied."""
    from engagement.audit import NullSink

    log = AuditLog()
    assert isinstance(log._sink, NullSink)


# -- wiring -----------------------------------------------------------------


def test_the_trail_lives_beside_the_run_it_describes(tmp_path: Path) -> None:
    """Archiving a run folder should archive the evidence of what produced it."""
    from engagement.audit import default_audit_path

    path = default_audit_path(tmp_path, "acme", "run-001")
    assert path == tmp_path / "runs" / "acme" / "run-001" / "audit.jsonl"


def test_the_cli_wires_an_audit_sink() -> None:
    """The control existed for a while and the entry point never used it, so
    every real run had no trail while the unit tests passed. Asserted at the
    source, because that is where the omission was."""
    source = (
        Path(__file__).resolve().parent.parent
        / "src" / "engagement" / "cli.py"
    ).read_text(encoding="utf-8")
    assert "AuditLog(FileSink(" in source, "the CLI must construct a file-backed audit"
    assert "default_audit_path(" in source
