"""Properties of the two dimensions that used to be structurally zero.

`exposure` and `chaining` carry 35% of the score's weight between them and were
never populated, so every blended score was pulled down and the KEV floor did
the ranking of every exploited finding rather than the blend. Two findings that
differ entirely — one on an unauthenticated SAML endpoint, one behind three
internal hops — scored identically.

Both are now filled from evidence the pipeline already produced. The tests that
matter are the ones proving the adjustment stays *reversible*: an adjustment you
cannot undo is an assertion, not an explanation.
"""

from __future__ import annotations

import json
from pathlib import Path

from engagement.contracts import Chain, ScoredFinding
from engagement.signals import (
    BOUNDARY_EXPOSURE,
    MAX_CHAIN_ADJUST,
    NO_BOUNDARY_EXPOSURE,
    apply_chaining,
    apply_exposure,
    load_boundaries,
)


def _finding(id: str = "f1", path: str = "src/app.py", score: float = 50.0) -> ScoredFinding:
    return ScoredFinding(id=id, repo="acme/app", title="a finding", path=path, risk_score=score)


def _recon(tmp_path: Path, *rows: dict[str, object]) -> Path:
    path = tmp_path / "recon-items.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    return path


# -- exposure ----------------------------------------------------------------


def test_a_finding_on_a_request_boundary_is_more_exposed_than_one_that_is_not(
    tmp_path: Path,
) -> None:
    recon = _recon(
        tmp_path,
        {"type": "request-boundary", "path": "src/routes.py", "boundary_type": "webhook"},
    )
    exposed, buried = _finding("a", "src/routes.py"), _finding("b", "src/internal.py")
    apply_exposure([exposed, buried], load_boundaries(recon))

    assert exposed.exposure > buried.exposure
    assert exposed.risk_score > buried.risk_score
    assert exposed.exposure_boundary == "webhook"


def test_an_unauthenticated_boundary_outranks_one_needing_a_session() -> None:
    assert BOUNDARY_EXPOSURE["saml_acs"] > BOUNDARY_EXPOSURE["logout"]
    assert BOUNDARY_EXPOSURE["webhook"] > BOUNDARY_EXPOSURE["auth_check"]


def test_the_exposure_adjustment_is_reversible(tmp_path: Path) -> None:
    recon = _recon(
        tmp_path, {"type": "request-boundary", "path": "src/app.py", "boundary_type": "saml_acs"}
    )
    finding = _finding(score=50.0)
    apply_exposure([finding], load_boundaries(recon))

    assert finding.risk_score > 50.0
    assert finding.base_score == 50.0, "the backbone's own score was not recoverable"


def test_a_path_with_no_boundary_is_not_penalised(tmp_path: Path) -> None:
    """Recon only sees boundaries it recognised; absence is weak evidence."""
    recon = _recon(
        tmp_path, {"type": "request-boundary", "path": "src/routes.py", "boundary_type": "webhook"}
    )
    buried = _finding("b", "src/internal.py", score=50.0)
    apply_exposure([buried], load_boundaries(recon))

    assert buried.risk_score == 50.0
    assert buried.exposure == NO_BOUNDARY_EXPOSURE


def test_the_most_exposed_boundary_in_a_file_decides(tmp_path: Path) -> None:
    """Reachability is a floor, not an average."""
    recon = _recon(
        tmp_path,
        {"type": "request-boundary", "path": "src/app.py", "boundary_type": "logout"},
        {"type": "request-boundary", "path": "src/app.py", "boundary_type": "saml_acs"},
    )
    mapping = load_boundaries(recon)

    assert mapping.score_for("src/app.py") == (BOUNDARY_EXPOSURE["saml_acs"], "saml_acs")


def test_path_separators_do_not_defeat_the_match(tmp_path: Path) -> None:
    recon = _recon(
        tmp_path, {"type": "request-boundary", "path": "src/app.py", "boundary_type": "webhook"}
    )
    mapping = load_boundaries(recon)

    assert mapping.score_for("./src/App.py")[0] == BOUNDARY_EXPOSURE["webhook"]
    assert mapping.score_for("src\\app.py")[0] == BOUNDARY_EXPOSURE["webhook"]


def test_missing_recon_is_reported_not_silently_flat(tmp_path: Path) -> None:
    mapping = load_boundaries(tmp_path / "absent.jsonl")
    report = apply_exposure([_finding()], mapping)

    assert not mapping.loaded
    assert any("did not contribute to ranking" in w for w in report.warnings)


def test_non_boundary_recon_items_are_ignored(tmp_path: Path) -> None:
    recon = _recon(
        tmp_path,
        {"type": "routing-unit", "path": "src/app.py"},
        {"type": "request-boundary", "path": "src/routes.py", "boundary_type": "upload"},
    )
    mapping = load_boundaries(recon)

    assert mapping.boundaries == 1
    assert mapping.score_for("src/app.py")[0] == NO_BOUNDARY_EXPOSURE


# -- chaining ----------------------------------------------------------------


def test_a_finding_in_a_chain_outranks_the_same_finding_alone() -> None:
    chained, alone = _finding("a", score=50.0), _finding("b", score=50.0)
    apply_chaining([chained, alone], [Chain(id="CH-1", title="t", finding_ids=["a", "c"])])

    assert chained.risk_score > alone.risk_score
    assert chained.chain_count == 1


def test_a_hub_in_several_chains_outranks_a_link_in_one() -> None:
    """A hub is where a responder should start."""
    hub, link = _finding("a", score=50.0), _finding("b", score=50.0)
    apply_chaining(
        [hub, link],
        [
            Chain(id="CH-1", title="t", finding_ids=["a", "b"]),
            Chain(id="CH-2", title="t", finding_ids=["a", "x"]),
            Chain(id="CH-3", title="t", finding_ids=["a", "y"]),
        ],
    )

    assert hub.chain_count == 3
    assert link.chain_count == 1
    assert hub.risk_score > link.risk_score


def test_the_chaining_adjustment_is_capped() -> None:
    """Many overlapping chains must not inflate one finding past its evidence."""
    hub = _finding("a", score=50.0)
    apply_chaining(
        [hub], [Chain(id=f"CH-{n}", title="t", finding_ids=["a", "b"]) for n in range(20)]
    )

    assert hub.chaining_adjust == MAX_CHAIN_ADJUST


def test_the_chaining_adjustment_is_reversible() -> None:
    finding = _finding("a", score=50.0)
    apply_chaining([finding], [Chain(id="CH-1", title="t", finding_ids=["a", "b"])])

    assert finding.base_score == 50.0


def test_a_finding_counted_twice_in_one_chain_counts_once() -> None:
    finding = _finding("a", score=50.0)
    apply_chaining([finding], [Chain(id="CH-1", title="t", finding_ids=["a", "a", "b"])])

    assert finding.chain_count == 1


def test_no_chains_changes_nothing() -> None:
    finding = _finding("a", score=50.0)
    apply_chaining([finding], [])

    assert finding.risk_score == 50.0 and finding.chaining_adjust == 0.0


def test_both_adjustments_together_stay_reversible(tmp_path: Path) -> None:
    """The property that makes the whole score explainable."""
    recon = _recon(
        tmp_path, {"type": "request-boundary", "path": "src/app.py", "boundary_type": "saml_acs"}
    )
    finding = _finding("a", score=40.0)
    finding.lifecycle_adjust = 15.0
    finding.risk_score += 15.0

    report = apply_exposure([finding], load_boundaries(recon))
    apply_chaining([finding], [Chain(id="CH-1", title="t", finding_ids=["a", "b"])], report)

    assert finding.risk_score > 55.0
    assert finding.base_score == 40.0, "not every adjustment was recoverable"
    assert report.exposure_applied == 1 and report.chaining_applied == 1


def test_a_score_cannot_exceed_the_ceiling(tmp_path: Path) -> None:
    recon = _recon(
        tmp_path, {"type": "request-boundary", "path": "src/app.py", "boundary_type": "saml_acs"}
    )
    finding = _finding("a", score=98.0)
    apply_exposure([finding], load_boundaries(recon))
    apply_chaining([finding], [Chain(id="CH-1", title="t", finding_ids=["a", "b"])])

    assert finding.risk_score == 100.0
