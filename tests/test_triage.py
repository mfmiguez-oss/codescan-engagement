"""The handoff from an engagement to the triage backbone."""

from __future__ import annotations

from pathlib import Path

import pytest

from engagement.contracts import (
    Disposition,
    Phase,
    Priority,
    RunRef,
    RunReport,
    WorkOutcome,
)
from engagement.triage import TriageError, TriageSummary, ingest_run
from fakes import FakeWorkspace, scenarios

REF = RunRef(target="acme", run_id="run-001")


class FakePipeline:
    def __init__(self, summary: TriageSummary | None = None) -> None:
        self.summary = summary or TriageSummary(findings=3, kev_findings=1, top_score=85.0)
        self.calls: list[tuple[Path, str]] = []

    def ingest(
        self, sarif: Path, repo: str, out_dir: Path, feeds: Path | None = None
    ) -> TriageSummary:
        self.calls.append((sarif, repo))
        return self.summary


def _report(**kwargs: object) -> RunReport:
    base: dict[str, object] = {
        "ref": REF,
        "phase": Phase.export,
        "sarif_path": "findings.sarif",
        "scenarios": [WorkOutcome(item_id="S001", disposition=Disposition.completed)],
    }
    base.update(kwargs)
    return RunReport.model_validate(base)


def test_a_complete_run_hands_its_findings_to_the_backbone() -> None:
    pipeline = FakePipeline()
    summary = ingest_run(_report(), repo="acme/app", out_dir=Path("out"), pipeline=pipeline)

    assert pipeline.calls == [(Path("findings.sarif"), "acme/app")]
    assert summary.findings == 3
    assert summary.warnings == []


def test_a_partial_run_produces_a_queue_that_says_it_is_partial() -> None:
    """A ranked list from a half-reviewed backlog ranks what was reviewed, and
    must not be readable as what exists."""
    report = _report(
        scenarios=[
            WorkOutcome(item_id="S001", disposition=Disposition.completed),
            WorkOutcome(item_id="S002", disposition=Disposition.parked),
            WorkOutcome(item_id="S003", disposition=Disposition.unfunded),
        ]
    )
    summary = ingest_run(report, repo="acme/app", out_dir=Path("out"), pipeline=FakePipeline())

    coverage = [w for w in summary.warnings if "coverage:" in w]
    assert coverage, summary.warnings
    assert "33%" in coverage[0]
    assert "1 parked" in coverage[0] and "1 unfunded" in coverage[0]


def test_a_run_with_no_export_is_refused_rather_than_scored_empty() -> None:
    with pytest.raises(TriageError, match="no SARIF"):
        ingest_run(_report(sarif_path=None), repo="acme/app", out_dir=Path("out"))


def test_the_engagement_gate_does_not_require_the_triage_backbone() -> None:
    """The port exists so this package installs and tests without it."""
    from engagement import triage

    assert hasattr(triage, "TriagekitPipeline")


def test_a_driver_run_feeds_the_backbone_end_to_end() -> None:
    from engagement.budget import Ledger
    from engagement.driver import Driver, Policy
    from engagement.providers import FakeProvider

    workspace = FakeWorkspace(
        scenarios=scenarios(("S001", Priority.normal)), candidates_per_scenario=1
    )
    report = Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}"),
        ledger=Ledger(),
        policy=Policy(model="m"),
    ).run(REF)

    pipeline = FakePipeline()
    summary = ingest_run(report, repo="acme/app", out_dir=Path("out"), pipeline=pipeline)

    assert report.is_complete()
    assert summary.findings == 3
    assert pipeline.calls[0][1] == "acme/app"
