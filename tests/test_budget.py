"""The spend governor: bounded by default, refusing before dispatch."""

from __future__ import annotations

import contextlib

import pytest

from engagement.budget import Budget, BudgetExceeded, Ledger


def test_default_ceiling_is_bounded_not_unlimited() -> None:
    """An unattended run that can spend without limit is a defect."""
    budget = Budget()
    assert budget.max_calls < 10_000
    assert budget.max_total_tokens < 100_000_000


def test_call_ceiling_refuses_before_dispatch() -> None:
    ledger = Ledger(budget=Budget(max_calls=2))
    ledger.reserve()
    ledger.reserve()
    with pytest.raises(BudgetExceeded):
        ledger.check()


def test_token_ceiling_refuses_before_dispatch() -> None:
    ledger = Ledger(budget=Budget(max_calls=100, max_total_tokens=50))
    ledger.reserve()
    ledger.record_usage(input_tokens=40, output_tokens=20)
    with pytest.raises(BudgetExceeded):
        ledger.check()


def test_a_claimed_call_is_counted_before_the_answer_comes_back() -> None:
    """Concurrent dispatch is why claiming and counting are one step. Two
    callers that each pass a check at one slot remaining would both dispatch if
    the count only happened on the way back."""
    ledger = Ledger(budget=Budget(max_calls=1))
    ledger.reserve()
    assert ledger.calls == 1
    with pytest.raises(BudgetExceeded):
        ledger.reserve()


def test_a_reservation_whose_dispatch_failed_is_handed_back() -> None:
    """A call that produced nothing is not spend. Counting it would let a run of
    transient failures exhaust a budget that bought nothing."""
    ledger = Ledger(budget=Budget(max_calls=2))
    ledger.reserve()
    ledger.release()
    assert ledger.calls == 0
    assert ledger.remaining_calls() == 2


def test_the_ceiling_holds_when_callers_claim_concurrently() -> None:
    """The property the lock exists for: N threads racing one ceiling must not
    between them claim more than the ceiling allows."""
    from concurrent.futures import ThreadPoolExecutor

    ledger = Ledger(budget=Budget(max_calls=25))
    granted = 0

    def _claim() -> bool:
        try:
            ledger.reserve()
        except BudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        granted = sum(pool.map(lambda _: _claim(), range(200)))

    assert granted == 25
    assert ledger.calls == 25


def test_projection_answers_the_question_the_backlog_gate_asked() -> None:
    """Cost of the expensive phase, known before entering it — one call per
    scenario plus one per candidate."""
    assert Budget().projection(scenarios=40, candidates=12) == 52


def test_projection_never_reports_a_negative_cost() -> None:
    assert Budget().projection(scenarios=-5, candidates=-1) == 0


def test_remaining_calls_reports_headroom_not_overspend() -> None:
    ledger = Ledger(budget=Budget(max_calls=3))
    ledger.reserve()
    assert ledger.remaining_calls() == 2
    for _ in range(5):
        with contextlib.suppress(BudgetExceeded):
            ledger.reserve()
    assert ledger.remaining_calls() == 0  # never negative
