"""Picking parked work back up in a later run."""

from __future__ import annotations

from engagement.budget import Budget, Ledger
from engagement.contracts import Disposition, ParkedScenario, Priority, RunRef
from engagement.driver import Driver, Policy
from engagement.providers import FakeProvider
from fakes import FakeWorkspace, scenarios

REF = RunRef(target="acme", run_id="run-001")


def _driver(workspace: FakeWorkspace, budget: Budget | None = None) -> Driver:
    return Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}"),
        ledger=Ledger(budget=budget or Budget()),
        policy=Policy(model="m"),
    )


def _with_parked(*ids: str) -> FakeWorkspace:
    workspace = FakeWorkspace(scenarios=scenarios(*[(i, Priority.normal) for i in ids]))
    workspace.previously_parked = [
        ParkedScenario(scenario_id=i, expert="injection") for i in ids
    ]
    return workspace


def test_a_parked_scenario_is_re_attempted_from_the_queue_it_left() -> None:
    """The workspace considers a parked scenario finished, so it never returns
    to the pending list — the durable queue is the only way back to it."""
    workspace = _with_parked("S001")
    report = _driver(workspace).resume_parked(REF)

    assert report.scenarios_completed == 1
    assert report.is_complete()


def test_a_resume_that_still_cannot_conclude_re_parks_it() -> None:
    workspace = _with_parked("S001")
    workspace.status_for["S001"] = "needs_context"
    workspace.missing_for["S001"] = ["still cannot resolve app/auth.py"]

    report = _driver(workspace).resume_parked(REF)

    assert report.scenarios_parked == 1
    assert workspace.parked_written  # the queue is rewritten, not lost


def test_each_re_attempt_is_an_independent_review() -> None:
    """A fresh agent id, so it is a new review rather than a continuation of
    the one that gave up."""
    workspace = _with_parked("S001", "S002")
    report = _driver(workspace).resume_parked(REF)

    assert report.scenarios_completed == 2
    assert len(workspace.agent_ids) == 2


def test_nothing_parked_means_nothing_to_resume() -> None:
    report = _driver(FakeWorkspace()).resume_parked(REF)

    assert report.scenarios == []
    assert any("no parked queue" in warning for warning in report.warnings)


def test_a_resume_respects_the_budget_and_names_what_it_skipped() -> None:
    workspace = _with_parked("S001", "S002", "S003")
    report = _driver(workspace, budget=Budget(max_calls=1)).resume_parked(REF)

    assert report.scenarios_completed == 1
    unfunded = [
        item for item in report.scenarios if item.disposition is Disposition.unfunded
    ]
    assert len(unfunded) == 2
    assert any("remain unreviewed" in warning for warning in report.warnings)
