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
    MAX_POC_FINDINGS,
    POC_BATCH,
    AnalysisSummary,
    ChainEngine,
    PocEngine,
    analyse,
    to_markdown,
)
from engagement.audit import AuditLog, MemorySink
from engagement.budget import Budget, Ledger
from engagement.contracts import ScoredFinding
from engagement.dispatch import Dispatcher
from engagement.providers import FakeProvider


def _finding(id: str, score: float = 50.0, repo: str = "acme/app") -> ScoredFinding:
    return ScoredFinding(
        id=id, repo=repo, title=f"finding {id}", risk_score=score, path=f"src/{id}.py"
    )


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
    findings = [_finding("a")]
    pocs = PocEngine(_dispatcher([_poc_answer("a", "ghost")]), "m").draft(
        findings, AnalysisSummary()
    )

    assert [poc.finding_id for poc in pocs] == ["a"]


def test_poc_drafting_batches_so_one_response_cannot_truncate_them_all() -> None:
    findings = [_finding(f"f{n}") for n in range(POC_BATCH * 2)]
    ids = [finding.id for finding in findings]
    dispatcher = _dispatcher(
        [_poc_answer(*ids[:POC_BATCH]), _poc_answer(*ids[POC_BATCH:])]
    )
    pocs = PocEngine(dispatcher, "m").draft(findings, AnalysisSummary())

    assert dispatcher.ledger.calls == 2
    assert len(pocs) == POC_BATCH * 2


def test_a_failed_batch_costs_only_its_own_drafts() -> None:
    findings = [_finding(f"f{n}") for n in range(POC_BATCH * 2)]
    ids = [finding.id for finding in findings]
    summary = AnalysisSummary()
    dispatcher = _dispatcher(["}} not json", _poc_answer(*ids[POC_BATCH:])])
    pocs = PocEngine(dispatcher, "m").draft(findings, summary)

    assert len(pocs) == POC_BATCH, "a bad batch took the good one with it"
    assert len(summary.pocs_undrafted) == POC_BATCH


def test_findings_past_the_poc_cap_are_reported_not_silently_skipped() -> None:
    findings = [_finding(f"f{n}", score=float(n)) for n in range(MAX_POC_FINDINGS + 5)]
    summary = AnalysisSummary()
    PocEngine(_dispatcher(["{}"] * 10), "m").draft(findings, summary)

    assert len(summary.pocs_undrafted) >= 5
    assert any("were not drafted for" in warning for warning in summary.warnings)


def test_poc_drafting_takes_the_highest_risk_findings_first() -> None:
    findings = [_finding(f"f{n}", score=float(n)) for n in range(MAX_POC_FINDINGS + 5)]
    summary = AnalysisSummary()
    dispatcher = _dispatcher(["{}"] * 10)
    PocEngine(dispatcher, "m").draft(findings, summary)

    # the five lowest-scoring findings are the ones left out
    assert set(summary.pocs_undrafted) >= {"f0", "f1", "f2", "f3", "f4"}


def test_a_finding_the_model_ignored_is_recorded_as_undrafted() -> None:
    findings = [_finding("a"), _finding("b")]
    summary = AnalysisSummary()
    PocEngine(_dispatcher([_poc_answer("a")]), "m").draft(findings, summary)

    assert summary.pocs_undrafted == ["b"]


def test_model_prose_cannot_carry_markup_into_the_pack() -> None:
    findings = [_finding("a")]
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
    findings = [_finding("a")]
    poc = PocEngine(_dispatcher([_poc_answer("a")]), "m").draft(
        findings, AnalysisSummary()
    )[0]

    assert poc.steps[0].startswith("send"), f"leading enumeration survived: {poc.steps[0]}"


# -- the pack and the orchestrator -------------------------------------------


def test_the_pack_says_nothing_was_executed() -> None:
    findings = [_finding("a"), _finding("b")]
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
    findings = [_finding("a")]
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
    findings = [_finding("a"), _finding("b")]
    dispatcher = _dispatcher([_chain_answer(["a", "b"]), _poc_answer("a", "b")])
    analyse(findings, dispatcher, "m", out_dir=tmp_path)

    assert dispatcher.ledger.calls == 2, "the advisory stages metered somewhere else"


def test_analysis_writes_both_artifacts(tmp_path: Path) -> None:
    findings = [_finding("a"), _finding("b")]
    dispatcher = _dispatcher([_chain_answer(["a", "b"]), _poc_answer("a", "b")])
    summary = analyse(findings, dispatcher, "m", out_dir=tmp_path, repo="acme/app")

    assert (tmp_path / "chains.json").exists()
    assert (tmp_path / "pocs.md").exists()
    assert summary.chains_path and summary.pocs_path
    stored = json.loads((tmp_path / "chains.json").read_text(encoding="utf-8"))
    assert stored[0]["fingerprint"], "the stable identity was not persisted"
