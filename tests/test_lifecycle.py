"""Properties of the lifecycle pass: deprecation, end of support, end of life.

The load-bearing test in this file is
``test_a_component_the_feed_does_not_cover_is_unknown_not_supported``. Every
other property here is arithmetic; that one is the difference between a report
that says "we checked and it is fine" and one that says "we did not check", and
those two statements produce an identical-looking clean queue if the code ever
stops distinguishing them.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from engagement.contracts import ScoredFinding
from engagement.lifecycle import (
    STATE_ADJUSTMENT,
    Assessment,
    Cycle,
    LifecycleError,
    LifecycleState,
    PackageLifecycle,
    assess,
    load_feed,
)

TODAY = date(2026, 8, 1)


def _finding(
    id: str = "f1",
    component: str = "django",
    ecosystem: str = "pypi",
    version: str = "3.2.1",
    score: float = 40.0,
) -> ScoredFinding:
    return ScoredFinding(
        id=id,
        repo="acme/app",
        title="a finding",
        risk_score=score,
        component=component,
        ecosystem=ecosystem,
        version=version,
    )


def _feed(**overrides: object) -> dict[str, PackageLifecycle]:
    package = PackageLifecycle(
        ecosystem="pypi",
        name="django",
        cycles=[
            Cycle(cycle="3.2", eos=date(2024, 4, 1), eol=date(2024, 4, 1)),
            Cycle(cycle="4.2", eos=date(2025, 12, 1), eol=date(2027, 4, 1)),
            Cycle(cycle="5.0", eos=date(2028, 1, 1), eol=date(2029, 1, 1)),
        ],
        source="endoflife.date",
        **overrides,  # type: ignore[arg-type]
    )
    return {package.key: package}


def _write_feed(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "lifecycle.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# -- the three states are distinguished --------------------------------------


def test_a_version_past_its_eol_date_is_end_of_life() -> None:
    report = assess([_finding(version="3.2.1")], _feed(), as_of=TODAY)

    assert report.assessments[0].state is LifecycleState.eol


def test_a_version_past_support_but_not_eol_is_end_of_support_not_end_of_life() -> None:
    report = assess([_finding(version="4.2.3")], _feed(), as_of=TODAY)

    state = report.assessments[0].state
    assert state is LifecycleState.eos, (
        "end of support was reported as end of life; the difference is whether a "
        "fix can still be bought"
    )


def test_a_current_version_is_supported() -> None:
    report = assess([_finding(version="5.0.2")], _feed(), as_of=TODAY)

    assert report.assessments[0].state is LifecycleState.supported


def test_a_maintainer_deprecation_applies_with_no_dates_at_all() -> None:
    package = PackageLifecycle(
        ecosystem="npm", name="request", deprecated=True, replacement="got"
    )
    report = assess(
        [_finding(component="request", ecosystem="npm", version="2.88.2")],
        {package.key: package},
        as_of=TODAY,
    )

    assert report.assessments[0].state is LifecycleState.deprecated
    assert "got" in report.assessments[0].detail


def test_end_of_life_outranks_a_deprecation_flag() -> None:
    report = assess([_finding(version="3.2.1")], _feed(deprecated=True), as_of=TODAY)

    assert report.assessments[0].state is LifecycleState.eol, (
        "the worse of two applicable states must win"
    )


# -- unknown is not supported ------------------------------------------------


def test_a_component_the_feed_does_not_cover_is_unknown_not_supported() -> None:
    report = assess(
        [_finding(component="leftpad", ecosystem="npm")], _feed(), as_of=TODAY
    )

    assert report.assessments[0].state is LifecycleState.unknown
    assert report.unknown_components == ["npm:leftpad"]
    assert any("unknown is not" in warning for warning in report.warnings)


def test_a_covered_package_on_an_uncovered_version_is_unknown() -> None:
    report = assess([_finding(version="9.9.9")], _feed(), as_of=TODAY)

    assert report.assessments[0].state is LifecycleState.unknown


def test_no_feed_reports_that_nothing_was_checked() -> None:
    report = assess([_finding()], None, as_of=TODAY)

    assert not report.feed_loaded
    assert report.assessments == []
    assert any("no feed supplied" in warning for warning in report.warnings)
    assert any("would otherwise read as clean" in w for w in report.warnings)


def test_a_queue_with_no_components_says_so_rather_than_reporting_none() -> None:
    code_only = ScoredFinding(id="f1", repo="acme/app", title="sqli", path="app.py")
    report = assess([code_only], _feed(), as_of=TODAY)

    assert any("no components were identified" in w for w in report.warnings)


# -- an EOL package is a finding in its own right ----------------------------


def test_an_end_of_life_component_becomes_a_finding_with_no_cve_behind_it() -> None:
    report = assess([_finding(version="3.2.1")], _feed(), repo="acme/app", as_of=TODAY)

    assert len(report.findings) == 1
    minted = report.findings[0]
    assert "End of life" in minted.title
    assert minted.repo == "acme/app"
    assert "no further updates" in minted.evidence


def test_a_supported_component_mints_no_finding() -> None:
    report = assess([_finding(version="5.0.2")], _feed(), as_of=TODAY)

    assert report.findings == []


def test_a_lifecycle_finding_id_is_stable_across_runs() -> None:
    first = assess([_finding(version="3.2.1")], _feed(), as_of=TODAY)
    second = assess([_finding(version="3.2.1")], _feed(), as_of=date(2026, 9, 1))

    assert first.findings[0].id == second.findings[0].id, (
        "an analyst decision about this package would not survive a rescan"
    )


def test_a_component_only_in_the_inventory_is_still_checked() -> None:
    """The blind spot only closes if a package with no finding can be seen."""
    report = assess(
        [], _feed(), repo="acme/app", as_of=TODAY, inventory=[("pypi", "django", "3.2.1")]
    )

    assert len(report.findings) == 1
    assert report.assessments[0].state is LifecycleState.eol


# -- the adjustment is explainable -------------------------------------------


def test_an_end_of_life_component_raises_the_score_of_findings_against_it() -> None:
    finding = _finding(version="3.2.1", score=40.0)
    assess([finding], _feed(), as_of=TODAY)

    assert finding.lifecycle == "eol"
    assert finding.risk_score == 40.0 + STATE_ADJUSTMENT[LifecycleState.eol]


def test_the_adjustment_can_always_be_undone() -> None:
    finding = _finding(version="3.2.1", score=40.0)
    assess([finding], _feed(), as_of=TODAY)

    assert finding.base_score == 40.0, "the backbone's own score was not recoverable"


def test_an_unknown_component_adjusts_nothing() -> None:
    finding = _finding(component="leftpad", ecosystem="npm", score=40.0)
    assess([finding], _feed(), as_of=TODAY)

    assert finding.risk_score == 40.0
    assert finding.lifecycle == "unknown"


def test_the_adjustment_cannot_push_a_score_past_the_ceiling() -> None:
    finding = _finding(version="3.2.1", score=99.0)
    assess([finding], _feed(), as_of=TODAY)

    assert finding.risk_score == 100.0


# -- the feed is read strictly -----------------------------------------------


def test_a_feed_loads_from_disk(tmp_path: Path) -> None:
    path = _write_feed(
        tmp_path,
        {
            "source": "endoflife.date",
            "packages": [
                {
                    "ecosystem": "pypi",
                    "name": "django",
                    "cycles": [{"cycle": "3.2", "eol": "2024-04-01"}],
                }
            ],
        },
    )
    feed = load_feed(path)

    assert feed["pypi:django"].cycles[0].eol == date(2024, 4, 1)
    assert feed["pypi:django"].source == "endoflife.date"


def test_a_malformed_date_is_an_error_not_a_skipped_row(tmp_path: Path) -> None:
    path = _write_feed(
        tmp_path,
        {"packages": [{"name": "django", "cycles": [{"cycle": "3.2", "eol": "soon"}]}]},
    )
    with pytest.raises(LifecycleError, match="not an ISO date"):
        load_feed(path)


def test_a_nameless_package_is_an_error(tmp_path: Path) -> None:
    path = _write_feed(tmp_path, {"packages": [{"ecosystem": "pypi"}]})
    with pytest.raises(LifecycleError, match="no name"):
        load_feed(path)


def test_an_unreadable_feed_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(LifecycleError, match="unreadable"):
        load_feed(tmp_path / "absent.json")


def test_a_version_range_operator_does_not_defeat_matching() -> None:
    package = PackageLifecycle(name="django", cycles=[Cycle(cycle="3.2", eol=TODAY)])

    assert package.cycle_for("^3.2.1") is not None
    assert package.cycle_for("v3.2.1-beta.1") is not None


def test_the_narrower_release_line_wins_when_both_are_published() -> None:
    package = PackageLifecycle(
        name="node",
        cycles=[Cycle(cycle="18", eol=date(2030, 1, 1)), Cycle(cycle="18.2", eol=TODAY)],
    )
    cycle = package.cycle_for("18.2.4")

    assert cycle is not None and cycle.cycle == "18.2"


def test_the_detail_line_explains_what_the_state_costs_the_reader() -> None:
    assessment = Assessment(
        component="django",
        state=LifecycleState.eol,
        cycle="3.2",
        eol_date=date(2024, 4, 1),
    )

    assert "no further updates" in assessment.detail
    assert "2024-04-01" in assessment.detail
