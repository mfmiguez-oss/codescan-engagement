"""Properties of the advisory layer: chains and PoC drafts.

Every test here is named after a property rather than a function, and the ones
that matter most are the refusals — a chain that references an invented finding,
a PoC drafted for something nobody asked about, a bound applied without being
reported. Those are the failures that would let a model quietly extend a queue
it is only allowed to annotate.
"""

from __future__ import annotations

import json
from pathlib import Path

from engagement.analysis import (
    CRITICAL_SCORE,
    MAX_POC_FINDINGS,
    POC_BATCH,
    AnalysisSummary,
    ChainEngine,
    PocEngine,
    analyse,
    draft_requested,
    is_critical,
    to_markdown,
)
from engagement.audit import AuditLog, MemorySink
from engagement.budget import Budget, Ledger
from engagement.contracts import ScoredFinding
from engagement.dispatch import Dispatcher
from engagement.providers import FakeProvider
from engagement.signals import CHAIN_POINTS, SignalReport


def _finding(
    id: str,
    score: float = 50.0,
    repo: str = "acme/app",
    severity: str = "medium",
) -> ScoredFinding:
    return ScoredFinding(
        id=id,
        repo=repo,
        title=f"finding {id}",
        severity=severity,
        risk_score=score,
        path=f"src/{id}.py",
    )


def _critical(id: str, score: float = 90.0, repo: str = "acme/app") -> ScoredFinding:
    """A finding the automatic rule will draft for.

    Spelled out in the PoC tests rather than made the default, because "which
    findings get drafted for" is the rule under test and a helper that quietly
    satisfied it would let the rule regress without a single test noticing.
    """
    return _finding(id, score=score, repo=repo, severity="critical")


def _dispatcher(answers: list[str], max_calls: int = 50) -> Dispatcher:
    return Dispatcher(
        FakeProvider(answers=answers),
        Ledger(budget=Budget(max_calls=max_calls)),
        AuditLog(MemorySink()),
    )


def _chain_answer(*groups: list[str]) -> str:
    return json.dumps(
        {
            "chains": [
                {
                    "title": f"chain {index}",
                    "finding_ids": ids,
                    "narrative": "a then b",
                    "impact": "rce",
                    "likelihood": 0.5,
                    "score": 80,
                }
                for index, ids in enumerate(groups)
            ]
        }
    )


def _poc_answer(*ids: str) -> str:
    return json.dumps(
        {
            "pocs": [
                {
                    "id": id,
                    "available": True,
                    "summary": f"demonstrate {id}",
                    "preconditions": ["the endpoint is reachable"],
                    "steps": ["1. send the request", "2. observe the response"],
                    "expected_evidence": "a 500 with a stack trace",
                }
                for id in ids
            ]
        }
    )


# -- chains ------------------------------------------------------------------


def test_a_chain_may_only_reference_findings_from_its_own_request() -> None:
    findings = [_finding("a"), _finding("b")]
    summary = AnalysisSummary()
    engine = ChainEngine(_dispatcher([_chain_answer(["a", "b", "ghost"])]), "m")

    chains = engine.find(findings, summary)

    assert len(chains) == 1
    assert chains[0].finding_ids == ["a", "b"], "an id nobody asked about survived"


def test_a_chain_narrowed_below_two_findings_is_dropped_as_fabricated() -> None:
    findings = [_finding("a"), _finding("b")]
    summary = AnalysisSummary()
    # only one of the two referenced ids was in the request
    engine = ChainEngine(_dispatcher([_chain_answer(["a", "ghost"])]), "m")

    assert engine.find(findings, summary) == []


def test_chain_ids_are_minted_locally_not_taken_from_the_model() -> None:
    findings = [_finding("a"), _finding("b")]
    answer = json.dumps(
        {"chains": [{"title": "t", "finding_ids": ["a", "b"], "id": "MODEL-OWNED"}]}
    )
    chains = ChainEngine(_dispatcher([answer]), "m").find(findings, AnalysisSummary())

    assert chains[0].id != "MODEL-OWNED"


def test_a_chain_fingerprint_is_stable_over_its_finding_set() -> None:
    findings = [_finding("a"), _finding("b")]
    first = ChainEngine(_dispatcher([_chain_answer(["a", "b"])]), "m").find(
        findings, AnalysisSummary()
    )
    second = ChainEngine(_dispatcher([_chain_answer(["b", "a"])]), "m").find(
        findings, AnalysisSummary()
    )

    assert first[0].fingerprint == second[0].fingerprint, (
        "an analyst decision would not survive a rescan that reordered the ids"
    )


def test_chains_are_scoped_per_service() -> None:
    findings = [
        _finding("a", repo="acme/app"),
        _finding("b", repo="acme/app"),
        _finding("c", repo="acme/api"),
        _finding("d", repo="acme/api"),
    ]
    dispatcher = _dispatcher([_chain_answer(["a", "b"]), _chain_answer(["c", "d"])])
    ChainEngine(dispatcher, "m").find(findings, AnalysisSummary())

    assert dispatcher.ledger.calls == 2, "one call per service, not one for the estate"


def test_a_service_whose_chain_call_fails_is_reported_as_unexamined() -> None:
    findings = [_finding("a"), _finding("b")]
    summary = AnalysisSummary()
    ChainEngine(_dispatcher(["not json at all"]), "m").find(findings, summary)

    assert sorted(summary.chains_unanalysed) == ["a", "b"]
    assert any("never examined" in warning for warning in summary.warnings)


def test_a_service_unreachable_on_budget_is_reported_not_skipped() -> None:
    findings = [_finding("a"), _finding("b")]
    summary = AnalysisSummary()
    spent = Ledger(budget=Budget(max_calls=1))
    spent.record()
    dispatcher = Dispatcher(FakeProvider(), spent, AuditLog(MemorySink()))

    assert ChainEngine(dispatcher, "m").find(findings, summary) == []
    assert sorted(summary.chains_unanalysed) == ["a", "b"]
    assert any("budget exhausted" in warning for warning in summary.warnings)


def test_the_prompt_states_both_scales_because_they_are_not_guessable() -> None:
    """A live run scored chains 8 and 9 on an unstated 0-100 scale, which reads
    as trivial beside a finding scored 63, and returned an unusable likelihood."""
    from engagement.analysis import _CHAIN_SYSTEM

    assert "0 to 100" in _CHAIN_SYSTEM
    assert "0.0 to 1.0" in _CHAIN_SYSTEM


def test_a_quoted_number_is_read_rather_than_scored_zero() -> None:
    """Rejecting "0.85" scored it 0.0 — "no chance" instead of "unparseable"."""
    findings = [_finding("a"), _finding("b")]
    answer = json.dumps(
        {
            "chains": [
                {
                    "title": "t",
                    "finding_ids": ["a", "b"],
                    "likelihood": "0.85",
                    "score": "72",
                }
            ]
        }
    )
    chain = ChainEngine(_dispatcher([answer]), "m").find(findings, AnalysisSummary())[0]

    assert chain.likelihood == 0.85
    assert chain.score == 72.0


def test_a_genuinely_non_numeric_scalar_is_still_zero() -> None:
    findings = [_finding("a"), _finding("b")]
    answer = json.dumps(
        {"chains": [{"title": "t", "finding_ids": ["a", "b"], "likelihood": "high"}]}
    )
    chain = ChainEngine(_dispatcher([answer]), "m").find(findings, AnalysisSummary())[0]

    assert chain.likelihood == 0.0, "an invented severity is worse than an absent one"


def test_a_scalar_out_of_range_is_clamped() -> None:
    findings = [_finding("a"), _finding("b")]
    answer = json.dumps(
        {
            "chains": [
                {
                    "title": "t",
                    "finding_ids": ["a", "b"],
                    "likelihood": 40,
                    "score": 9999,
                }
            ]
        }
    )
    chain = ChainEngine(_dispatcher([answer]), "m").find(findings, AnalysisSummary())[0]

    assert chain.likelihood == 1.0
    assert chain.score == 100.0


# -- PoC drafting ------------------------------------------------------------


def test_a_poc_is_drafted_only_against_a_finding_in_its_request() -> None:
    findings = [_critical("a")]
    pocs = PocEngine(_dispatcher([_poc_answer("a", "ghost")]), "m").draft(
        findings, AnalysisSummary()
    )

    assert [poc.finding_id for poc in pocs] == ["a"]


def test_poc_drafting_batches_so_one_response_cannot_truncate_them_all() -> None:
    findings = [_critical(f"f{n}") for n in range(POC_BATCH * 2)]
    ids = [finding.id for finding in findings]
    dispatcher = _dispatcher(
        [_poc_answer(*ids[:POC_BATCH]), _poc_answer(*ids[POC_BATCH:])]
    )
    pocs = PocEngine(dispatcher, "m").draft(findings, AnalysisSummary())

    assert dispatcher.ledger.calls == 2
    assert len(pocs) == POC_BATCH * 2


def test_a_failed_batch_costs_only_its_own_drafts() -> None:
    findings = [_critical(f"f{n}") for n in range(POC_BATCH * 2)]
    ids = [finding.id for finding in findings]
    summary = AnalysisSummary()
    dispatcher = _dispatcher(["}} not json", _poc_answer(*ids[POC_BATCH:])])
    pocs = PocEngine(dispatcher, "m").draft(findings, summary)

    assert len(pocs) == POC_BATCH, "a bad batch took the good one with it"
    assert len(summary.pocs_undrafted) == POC_BATCH


def test_findings_past_the_poc_cap_are_reported_not_silently_skipped() -> None:
    findings = [_critical(f"f{n}", score=float(n)) for n in range(MAX_POC_FINDINGS + 5)]
    summary = AnalysisSummary()
    PocEngine(_dispatcher(["{}"] * 10), "m").draft(findings, summary)

    assert len(summary.pocs_undrafted) >= 5
    assert any("were not drafted for" in warning for warning in summary.warnings)


def test_poc_drafting_takes_the_highest_risk_findings_first() -> None:
    findings = [_critical(f"f{n}", score=float(n)) for n in range(MAX_POC_FINDINGS + 5)]
    summary = AnalysisSummary()
    dispatcher = _dispatcher(["{}"] * 10)
    PocEngine(dispatcher, "m").draft(findings, summary)

    # the five lowest-scoring findings are the ones left out
    assert set(summary.pocs_undrafted) >= {"f0", "f1", "f2", "f3", "f4"}


def test_a_finding_the_model_ignored_is_recorded_as_undrafted() -> None:
    findings = [_critical("a"), _critical("b")]
    summary = AnalysisSummary()
    PocEngine(_dispatcher([_poc_answer("a")]), "m").draft(findings, summary)

    assert summary.pocs_undrafted == ["b"]


def test_model_prose_cannot_carry_markup_into_the_pack() -> None:
    findings = [_critical("a")]
    answer = json.dumps(
        {
            "pocs": [
                {
                    "id": "a",
                    "available": True,
                    "summary": "<script>alert(1)</script>",
                    "steps": ["<img src=x onerror=alert(1)>"],
                }
            ]
        }
    )
    poc = PocEngine(_dispatcher([answer]), "m").draft(findings, AnalysisSummary())[0]

    assert "<" not in poc.summary and ">" not in poc.summary
    assert all("<" not in step and ">" not in step for step in poc.steps)


def test_a_step_that_numbers_itself_is_not_numbered_twice() -> None:
    findings = [_critical("a")]
    poc = PocEngine(_dispatcher([_poc_answer("a")]), "m").draft(
        findings, AnalysisSummary()
    )[0]

    assert poc.steps[0].startswith("send"), f"leading enumeration survived: {poc.steps[0]}"


# -- who gets drafted for ----------------------------------------------------


def test_only_critical_findings_are_drafted_for_automatically() -> None:
    findings = [_critical("crit"), _finding("mid", score=50.0)]
    summary = AnalysisSummary()
    dispatcher = _dispatcher([_poc_answer("crit", "mid")])
    pocs = PocEngine(dispatcher, "m").draft(findings, summary)

    assert [poc.finding_id for poc in pocs] == ["crit"]
    assert "mid" in summary.pocs_undrafted


def test_a_high_finding_pushed_over_the_line_by_enrichment_is_drafted_for() -> None:
    """The reason the rule reads the final score and not the declared severity.

    A high finding that KEV, lifecycle, exposure and chaining together lifted
    into the critical band is exactly the finding those adjustments exist to
    surface, and drafting it is the point of running them.
    """
    lifted = _finding("lifted", score=CRITICAL_SCORE, severity="high")
    summary = AnalysisSummary()
    pocs = PocEngine(_dispatcher([_poc_answer("lifted")]), "m").draft(
        [lifted], summary
    )

    assert [poc.finding_id for poc in pocs] == ["lifted"]


def test_a_scanners_own_critical_is_drafted_for_without_any_intelligence() -> None:
    """The other half: knowing nothing extra is not grounds to demote."""
    declared = _finding("declared", score=10.0, severity="critical")

    assert is_critical(declared)


def test_a_non_critical_finding_costs_no_call_at_all() -> None:
    dispatcher = _dispatcher([_poc_answer("mid")])
    PocEngine(dispatcher, "m").draft([_finding("mid")], AnalysisSummary())

    assert dispatcher.ledger.calls == 0, "the queue was drafted for after all"


def test_findings_below_critical_are_named_and_pointed_at_the_request_path() -> None:
    summary = AnalysisSummary()
    PocEngine(_dispatcher(["{}"]), "m").draft([_finding("mid")], summary)

    assert summary.pocs_undrafted == ["mid"]
    warning = " ".join(summary.warnings)
    assert "requested" in warning, "the analyst was not told drafts can be asked for"
    assert "not implausible" in warning, "absence read as a judgement"


def test_chain_membership_reaches_the_score_before_poc_selection_reads_it() -> None:
    """The ordering bug this rule would otherwise have: a finding that only
    becomes critical *because* it is a link in a chain must still be drafted."""
    below = CRITICAL_SCORE - 5.0
    findings = [_finding("a", score=below), _finding("b", score=below)]
    dispatcher = _dispatcher([_chain_answer(["a", "b"]), _poc_answer("a", "b")])

    summary = analyse(findings, dispatcher, "m")

    assert all(f.chaining_adjust > 0 for f in findings), "chaining never landed"
    assert {poc.finding_id for poc in summary.pocs} == {"a", "b"}


def test_chaining_is_applied_exactly_once() -> None:
    findings = [_finding("a", score=50.0), _finding("b", score=50.0)]
    signals = SignalReport()
    analyse(findings, _dispatcher([_chain_answer(["a", "b"]), "{}"]), "m", signals=signals)

    assert signals.chaining_applied == 2
    assert findings[0].chaining_adjust == CHAIN_POINTS, "double-counted"


# -- drafting on request -----------------------------------------------------


def test_a_requested_draft_ignores_criticality_entirely() -> None:
    findings = [_finding("mid", score=12.0), _finding("low", score=3.0)]
    summary = draft_requested(findings, _dispatcher([_poc_answer("mid")]), "m", ["mid"])

    assert [poc.finding_id for poc in summary.pocs] == ["mid"]


def test_a_requested_draft_still_cannot_invent_a_finding() -> None:
    summary = draft_requested(
        [_finding("mid")], _dispatcher([_poc_answer("ghost")]), "m", ["ghost"]
    )

    assert summary.pocs == []
    assert any("not in this run's queue" in w for w in summary.warnings)


def test_a_request_for_nothing_spends_nothing() -> None:
    dispatcher = _dispatcher([_poc_answer("mid")])
    summary = draft_requested([_finding("mid")], dispatcher, "m", [])

    assert dispatcher.ledger.calls == 0
    assert summary.warnings


def test_a_repeated_id_is_drafted_for_once() -> None:
    dispatcher = _dispatcher([_poc_answer("mid")])
    draft_requested([_finding("mid")], dispatcher, "m", ["mid", "mid", "mid"])

    assert dispatcher.ledger.calls == 1


def test_a_request_is_metered_and_bounded_like_any_other_spend() -> None:
    findings = [_finding(f"f{n}") for n in range(MAX_POC_FINDINGS + 3)]
    summary = draft_requested(
        findings, _dispatcher(["{}"] * 10), "m", [f.id for f in findings]
    )

    assert any("still a request to spend" in w for w in summary.warnings)


# -- the pack and the orchestrator -------------------------------------------


def test_the_pack_says_nothing_was_executed() -> None:
    findings = [_critical("a"), _critical("b")]
    summary = AnalysisSummary(
        chains=ChainEngine(_dispatcher([_chain_answer(["a", "b"])]), "m").find(
            findings, AnalysisSummary()
        ),
        pocs=PocEngine(_dispatcher([_poc_answer("a")]), "m").draft(
            findings, AnalysisSummary()
        ),
    )
    pack = to_markdown(summary, findings, "acme/app")

    assert "Drafts, not exploits" in pack
    assert "has been executed" in pack


def test_the_pack_names_what_it_does_not_cover() -> None:
    findings = [_critical("a")]
    summary = AnalysisSummary(
        pocs=PocEngine(_dispatcher([_poc_answer("a")]), "m").draft(
            findings, AnalysisSummary()
        ),
        pocs_undrafted=["b", "c"],
    )
    pack = to_markdown(summary, findings)

    assert "Not covered by this pack" in pack
    assert "not* a judgement" in pack or "not a judgement" in pack


def test_an_empty_analysis_writes_no_pack() -> None:
    assert to_markdown(AnalysisSummary(), []) == ""


def test_analysis_never_raises_when_every_call_fails(tmp_path: Path) -> None:
    findings = [_finding("a"), _finding("b")]
    summary = analyse(
        findings,
        dispatcher=_dispatcher(["garbage"] * 10),
        deployment="m",
        out_dir=tmp_path,
        repo="acme/app",
    )

    assert summary.chains == []
    assert summary.warnings, "a total failure was reported as a clean analysis"


def test_analysis_spends_from_the_run_ledger(tmp_path: Path) -> None:
    findings = [_critical("a"), _critical("b")]
    dispatcher = _dispatcher([_chain_answer(["a", "b"]), _poc_answer("a", "b")])
    analyse(findings, dispatcher, "m", out_dir=tmp_path)

    assert dispatcher.ledger.calls == 2, "the advisory stages metered somewhere else"


def test_analysis_writes_both_artifacts(tmp_path: Path) -> None:
    findings = [_critical("a"), _critical("b")]
    dispatcher = _dispatcher([_chain_answer(["a", "b"]), _poc_answer("a", "b")])
    summary = analyse(findings, dispatcher, "m", out_dir=tmp_path, repo="acme/app")

    assert (tmp_path / "chains.json").exists()
    assert (tmp_path / "pocs.md").exists()
    assert summary.chains_path and summary.pocs_path
    stored = json.loads((tmp_path / "chains.json").read_text(encoding="utf-8"))
    assert stored[0]["fingerprint"], "the stable identity was not persisted"
