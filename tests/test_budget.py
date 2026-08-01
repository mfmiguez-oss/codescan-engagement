"""The spend governor: bounded by default, refusing before dispatch."""

from __future__ import annotations

import pytest

from engagement.budget import Budget, BudgetExceeded, Ledger


def test_default_ceiling_is_bounded_not_unlimited() -> None:
    """An unattended run that can spend without limit is a defect."""
    budget = Budget()
    assert budget.max_calls < 10_000
    assert budget.max_total_tokens < 100_000_000


def test_call_ceiling_refuses_before_dispatch() -> None:
    ledger = Ledger(budget=Budget(max_calls=2))
    ledger.record()
    ledger.record()
    with pytest.raises(BudgetExceeded):
        ledger.check()


def test_token_ceiling_refuses_before_dispatch() -> None:
    ledger = Ledger(budget=Budget(max_calls=100, max_total_tokens=50))
    ledger.record(input_tokens=40, output_tokens=20)
    with pytest.raises(BudgetExceeded):
        ledger.check()


def test_projection_answers_the_question_the_backlog_gate_asked() -> None:
    """Cost of the expensive phase, known before entering it — one call per
    scenario plus one per candidate."""
    assert Budget().projection(scenarios=40, candidates=12) == 52


def test_projection_never_reports_a_negative_cost() -> None:
    assert Budget().projection(scenarios=-5, candidates=-1) == 0


def test_remaining_calls_reports_headroom_not_overspend() -> None:
    ledger = Ledger(budget=Budget(max_calls=3))
    ledger.record()
    assert ledger.remaining_calls() == 2
    for _ in range(5):
        ledger.record()
    assert ledger.remaining_calls() == 0  # never negative
