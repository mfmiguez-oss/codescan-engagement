"""The analyst view: read-only, self-contained, honest about coverage."""

from __future__ import annotations

from pathlib import Path

from engagement.contracts import (
    Disposition,
    ParkedScenario,
    Phase,
    RunRef,
    RunReport,
    WorkOutcome,
)
from engagement.report import render, write
from engagement.triage import TriageSummary

REF = RunRef(target="acme", run_id="run-001")


def _partial() -> RunReport:
    return RunReport(
        ref=REF,
        phase=Phase.export,
        scenarios=[
            WorkOutcome(item_id="S001", disposition=Disposition.completed),
            WorkOutcome(item_id="S002", disposition=Disposition.parked, detail="still unresolved"),
            WorkOutcome(item_id="S003", disposition=Disposition.unfunded, detail="budget"),
        ],
        parked=[
            ParkedScenario(
                scenario_id="S002",
                expert="injection",
                missing_context=["cannot resolve app/auth.py"],
                expanded=True,
                unresolved_paths=["app/auth.py"],
            )
        ],
        warnings=["coverage: 1 scenario(s) parked"],
    )


def test_a_hostile_title_is_escaped_in_the_report() -> None:
    """The page renders text recovered from a repository under review, and is
    mailed to people who did not run the scan. Every value it prints is
    attacker-influenced by construction."""
    report = _partial()
    report.parked = [
        ParkedScenario(
            scenario_id="<script>alert(1)</script>",
            expert="<img src=x onerror=alert(1)>",
            missing_context=["</td><td onmouseover=alert(1)>"],
            reason="<svg onload=alert(1)>",
        )
    ]

    html = render(report)

    assert "<script>alert(1)</script>" not in html
    assert "onerror=alert(1)>" not in html
    assert "onload=alert(1)>" not in html
    assert "&lt;script&gt;" in html, "the value was dropped rather than escaped"


def test_coverage_is_the_first_thing_the_page_says() -> None:
    """A queue is only meaningful against the denominator that produced it."""
    html = render(_partial())
    assert "reviewed 33% of its backlog" in html
    assert "not known to be\nbe clean" not in html  # no mangled copy
    assert html.index("33%") < html.index("Parked scenarios")


def test_a_complete_run_says_so_without_a_caveat() -> None:
    report = RunReport(
        ref=REF,
        phase=Phase.export,
        scenarios=[WorkOutcome(item_id="S001", disposition=Disposition.completed)],
    )
    html = render(report)
    assert "Every scenario reached a conclusion" in html
    # match the applied class, not the word: the warning variant is always
    # present in the stylesheet whether or not the banner uses it
    assert "class='banner'" in html
    assert "class='banner partial'" not in html


def test_parked_scenarios_show_the_gap_and_what_was_refused() -> None:
    html = render(_partial())
    assert "cannot resolve app/auth.py" in html
    assert "not supplied" in html


def test_the_page_is_self_contained() -> None:
    """No CDN, no fonts, no scripts: it opens from a private blob container."""
    html = render(_partial())
    for external in ("http://", "https://", "<script"):
        assert external not in html


def test_the_page_states_it_cannot_change_state() -> None:
    """A page that let an anonymous reader close a finding would undo the
    invariant the estate is built on."""
    html = render(_partial())
    assert "Read-only" in html
    assert "authenticated control plane" in html


def test_missing_exploit_intelligence_is_declared_not_implied() -> None:
    html = render(_partial(), TriageSummary(findings=4, enriched=False))
    assert "not known exploitation" in html


def test_the_page_writes_to_disk(tmp_path: Path) -> None:
    out = write(_partial(), tmp_path / "report.html")
    assert out.exists() and out.read_text(encoding="utf-8").startswith("<!doctype html>")
