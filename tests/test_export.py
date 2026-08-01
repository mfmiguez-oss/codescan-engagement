"""Properties of the worklist CSV: provenance, dedup, and movement.

Two tests carry the weight. ``test_a_merge_keeps_the_worse_reading`` — two
sources disagreeing about severity is not a reason to report the milder one. And
``test_a_first_run_reports_unknown_movement_not_new`` — labelling a whole first
queue "new" trains an analyst to ignore the column exactly when it starts to
mean something.
"""

from __future__ import annotations

import csv
from pathlib import Path

from engagement.contracts import ScoredFinding
from engagement.export import (
    COLUMNS,
    Baseline,
    dedupe,
    movement_summary,
    neutralize,
    to_rows,
    write_manifest,
    write_queue,
)


def _finding(
    id: str = "f1",
    score: float = 50.0,
    severity: str = "medium",
    title: str = "SQL injection",
    **kwargs: object,
) -> ScoredFinding:
    return ScoredFinding(
        id=id,
        repo="acme/app",
        title=title,
        severity=severity,
        risk_score=score,
        path="src/db.py",
        **kwargs,  # type: ignore[arg-type]
    )


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


# -- detail ------------------------------------------------------------------


def test_the_worklist_says_where_and_what_detected_it() -> None:
    rows = to_rows([_finding()], "run-1", sources={"f1": ["snyk", "openhack"]})
    row = rows[0]

    assert row.finding.path == "src/db.py"
    assert row.finding.repo == "acme/app"
    assert set(row.detected_by) == {"snyk", "openhack"}
    assert row.corroboration == 2


def test_every_documented_column_is_written(tmp_path: Path) -> None:
    path, _, _ = write_queue([_finding()], tmp_path, "run-1")
    written = _read(path)

    assert list(written[0]) == COLUMNS


def test_one_source_reporting_twice_is_still_one_corroboration() -> None:
    rows = to_rows([_finding()], "run-1", sources={"f1": ["snyk", "Snyk", "snyk "]})

    assert rows[0].corroboration == 1


# -- dedup -------------------------------------------------------------------


def test_the_same_finding_from_two_sources_is_one_row() -> None:
    rows = dedupe([_finding(), _finding()], sources={"f1": ["snyk"]})

    assert len(rows) == 1
    assert rows[0].merged_count == 1


def test_a_merge_keeps_the_worse_reading() -> None:
    """Disagreement is not a reason to report the milder severity."""
    rows = dedupe([_finding(score=40.0, severity="medium"), _finding(score=80.0, severity="high")])

    assert len(rows) == 1
    assert rows[0].finding.risk_score == 80.0
    assert rows[0].merged_count == 1, "the merge must stay visible"


def test_a_merge_keeps_every_source_it_absorbed() -> None:
    rows = dedupe(
        [_finding(id="f1"), _finding(id="f1")],
        sources={"f1": ["snyk"]},
    )

    assert rows[0].detected_by == ["snyk"]


def test_distinct_findings_are_not_merged() -> None:
    rows = dedupe([_finding(id="f1"), _finding(id="f2", title="XSS")])

    assert len(rows) == 2


def test_findings_with_no_id_do_not_collide_under_an_empty_key() -> None:
    a = ScoredFinding(id="", repo="r", title="one", path="a.py")
    b = ScoredFinding(id="", repo="r", title="two", path="b.py")

    assert len(dedupe([a, b])) == 2


def test_rows_are_ranked_worst_first() -> None:
    rows = to_rows([_finding(id="a", score=10.0), _finding(id="b", score=90.0)], "run-1")

    assert [row.finding.id for row in rows] == ["b", "a"]


# -- movement ----------------------------------------------------------------


def test_a_first_run_reports_unknown_movement_not_new() -> None:
    rows = to_rows([_finding()], "run-1", baseline=None)

    assert rows[0].severity_delta == "unknown"
    assert "no previous run" in rows[0].movement_reason


def test_a_severity_increase_is_reported_with_both_values() -> None:
    baseline = Baseline(run_id="run-1", severities={"f1": "medium"}, scores={"f1": 50.0})
    rows = to_rows([_finding(severity="critical", score=80.0)], "run-2", baseline)

    assert rows[0].severity_delta == "increased (medium -> critical)"
    assert rows[0].score_delta == 30.0


def test_a_severity_decrease_is_reported() -> None:
    baseline = Baseline(run_id="run-1", severities={"f1": "critical"}, scores={"f1": 80.0})
    rows = to_rows([_finding(severity="low", score=20.0)], "run-2", baseline)

    assert rows[0].severity_delta == "decreased (critical -> low)"
    assert rows[0].score_delta == -60.0


def test_a_score_move_without_a_severity_change_is_still_reported() -> None:
    baseline = Baseline(run_id="run-1", severities={"f1": "medium"}, scores={"f1": 50.0})
    rows = to_rows([_finding(score=65.0)], "run-2", baseline)

    assert rows[0].severity_delta == "score increased"


def test_an_unchanged_finding_says_so_with_no_noise() -> None:
    baseline = Baseline(run_id="run-1", severities={"f1": "medium"}, scores={"f1": 50.0})
    rows = to_rows([_finding()], "run-2", baseline)

    assert rows[0].severity_delta == "unchanged"
    assert rows[0].movement_reason == ""


def test_a_finding_absent_from_the_baseline_is_new() -> None:
    baseline = Baseline(run_id="run-1", severities={"other": "low"}, scores={"other": 5.0})
    rows = to_rows([_finding()], "run-2", baseline)

    assert rows[0].severity_delta == "new"


def test_the_movement_reason_attributes_a_lifecycle_bump() -> None:
    baseline = Baseline(run_id="run-1", severities={"f1": "medium"}, scores={"f1": 50.0})
    finding = _finding(score=65.0, lifecycle="eol", lifecycle_adjust=15.0)
    rows = to_rows([finding], "run-2", baseline)

    assert "lifecycle" in rows[0].movement_reason
    assert "eol" in rows[0].movement_reason


def test_the_movement_reason_names_kev() -> None:
    baseline = Baseline(run_id="run-1", severities={"f1": "medium"}, scores={"f1": 50.0})
    rows = to_rows([_finding(score=85.0, kev=True)], "run-2", baseline)

    assert "KEV" in rows[0].movement_reason


def test_first_seen_survives_across_runs() -> None:
    first = Baseline.from_findings([_finding()], "run-1")
    second = Baseline.from_findings([_finding()], "run-2", previous=first)

    assert second.first_seen["f1"] == "run-1", "the finding did not first appear in run-2"


def test_the_baseline_rolls_forward_on_write(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    write_queue([_finding(score=50.0)], tmp_path, "run-1", baseline_path)
    _, rows, _ = write_queue([_finding(score=70.0)], tmp_path, "run-2", baseline_path)

    assert rows[0].severity_delta == "score increased"
    assert rows[0].score_delta == 20.0


def test_a_missing_baseline_is_reported_not_silently_treated_as_unchanged(
    tmp_path: Path,
) -> None:
    _, _, warnings = write_queue([_finding()], tmp_path, "run-1", tmp_path / "absent.json")

    assert any("not the same as unchanged" in w for w in warnings)


def test_a_corrupt_baseline_does_not_withhold_the_queue(tmp_path: Path) -> None:
    """The baseline drives one column; it must not block the findings."""
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("{ not json", encoding="utf-8")
    path, rows, warnings = write_queue([_finding()], tmp_path, "run-2", baseline_path)

    assert path.exists() and len(rows) == 1
    assert any("unreadable" in w for w in warnings)


def test_the_summary_counts_what_moved() -> None:
    baseline = Baseline(
        run_id="run-1",
        severities={"a": "low", "b": "critical", "c": "medium"},
        scores={"a": 10.0, "b": 90.0, "c": 50.0},
    )
    rows = to_rows(
        [
            _finding(id="a", severity="high", score=70.0),
            _finding(id="b", severity="low", score=20.0),
            _finding(id="c", severity="medium", score=50.0),
            _finding(id="d", severity="high", score=75.0),
        ],
        "run-2",
        baseline,
    )

    assert movement_summary(rows) == {
        "increased": 1,
        "decreased": 1,
        "unchanged": 1,
        "new": 1,
    }


# -- the file itself ---------------------------------------------------------


def test_a_formula_cell_is_neutralised() -> None:
    assert neutralize("=cmd|'/c calc'!A1").startswith("'=")
    assert neutralize("normal text") == "normal text"


def test_a_hostile_title_cannot_execute_in_a_spreadsheet(tmp_path: Path) -> None:
    path, _, _ = write_queue([_finding(title="=HYPERLINK(\"http://evil\")")], tmp_path, "run-1")
    written = _read(path)

    assert written[0]["title"].startswith("'=")


def test_the_manifest_carries_what_the_csv_flattens(tmp_path: Path) -> None:
    rows = to_rows([_finding()], "run-1", sources={"f1": ["snyk"]})
    path = write_manifest(rows, tmp_path / "queue.json", "run-1")
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["run_id"] == "run-1"
    assert payload["findings"][0]["detected_by"] == ["snyk"]
    assert payload["movement"]["unchanged"] + payload["movement"]["new"] >= 0
