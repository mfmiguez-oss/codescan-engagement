"""The properties that make an unattended run trustworthy.

Tests are named after the property, not the function.
"""

from __future__ import annotations

import json

import pytest

from engagement.budget import Budget, Ledger
from engagement.contracts import Disposition, Phase, Priority, RunRef, RunReport
from engagement.driver import Driver, Policy
from engagement.providers import FakeProvider
from fakes import FakeWorkspace, scenarios

REF = RunRef(target="acme", run_id="run-001")


def _provider(answer: str = "{}", count: int = 64) -> FakeProvider:
    return FakeProvider(answers=[answer] * count, default=answer)


def _driver(
    workspace: FakeWorkspace,
    provider: FakeProvider | None = None,
    budget: Budget | None = None,
    **policy: object,
) -> Driver:
    return Driver(
        workspace=workspace,
        provider=provider or _provider(),
        ledger=Ledger(budget=budget or Budget()),
        policy=Policy(model="m", **policy),  # type: ignore[arg-type]
    )


def test_full_backlog_runs_to_completion_without_a_human() -> None:
    workspace = FakeWorkspace(
        scenarios=scenarios(("S001", Priority.normal), ("S002", Priority.normal)),
        candidates_per_scenario=1,
    )
    report = _driver(workspace).run(REF)
    assert report.phase is Phase.export
    assert report.scenarios_completed == 2
    assert len(report.candidates) == 2
    assert report.is_complete()
    assert workspace.sarif_written


def test_budget_stops_dispatch_and_reports_the_rest_as_unfunded() -> None:
    """The replacement for the human backlog gate: what was not paid for is
    named, not omitted."""
    backlog = scenarios(*[(f"S{i:03d}", Priority.normal) for i in range(1, 6)])
    workspace = FakeWorkspace(scenarios=backlog)
    report = _driver(workspace, budget=Budget(max_calls=2)).run(REF)

    assert report.scenarios_completed == 2
    assert report.scenarios_unfunded == 3
    assert not report.is_complete()
    assert report.reviewed_fraction == pytest.approx(0.4)
    assert any("NOT known to be clean" in warning for warning in report.warnings)


def test_backlog_is_processed_in_priority_order_when_budget_is_short() -> None:
    """A truncated run must spend what it has on the work that matters most."""
    workspace = FakeWorkspace(
        scenarios=scenarios(
            ("S001", Priority.low),
            ("S002", Priority.critical),
            ("S003", Priority.normal),
        )
    )
    report = _driver(workspace, budget=Budget(max_calls=1)).run(REF)
    completed = [
        item.item_id for item in report.scenarios if item.disposition == Disposition.completed
    ]
    assert completed == ["S002"]


def test_a_scenario_without_a_conclusion_is_parked_never_counted_clean() -> None:
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.status_for["S001"] = "needs_context"
    report = _driver(workspace).run(REF)

    assert report.scenarios_parked == 1
    assert report.scenarios_completed == 0
    assert not report.is_complete()
    assert any("parked" in warning for warning in report.warnings)


def test_every_dispatch_carries_the_digest_of_the_prompt_actually_sent() -> None:
    """Provenance is observed by the driver, not claimed by the model: a model
    answer that omits or fakes the hash cannot be recorded."""
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    report = _driver(workspace).run(REF)
    assert report.scenarios_completed == 1  # the fake rejects a wrong digest


def test_each_item_gets_its_own_agent_id_so_one_context_cannot_serve_all() -> None:
    """Per-item isolation is what makes these independent reviews rather than
    one conversation wearing several hats."""
    workspace = FakeWorkspace(
        scenarios=scenarios(("S001", Priority.normal), ("S002", Priority.normal)),
        candidates_per_scenario=1,
    )
    report = _driver(workspace).run(REF)
    assert report.is_complete()
    # four dispatched items, four distinct ids, none reused
    assert len(workspace.agent_ids) == 4


def test_a_rejected_answer_is_retried_then_reported_as_failed() -> None:
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.reject.add("S001")
    report = _driver(workspace, max_retries=1).run(REF)

    assert report.scenarios[0].disposition is Disposition.failed
    assert not report.is_complete()


def test_recon_runs_itself_when_the_run_has_not_reached_the_backlog() -> None:
    workspace = FakeWorkspace(
        scenarios=scenarios(("S001", Priority.normal)), recon_done=False
    )
    report = _driver(workspace).run(REF)
    assert workspace.recon_calls == 1
    assert report.scenarios_completed == 1


def test_router_answer_is_recorded_before_the_backlog_is_drained() -> None:
    workspace = FakeWorkspace(
        scenarios=scenarios(("S001", Priority.normal)), backlog_done=False
    )
    provider = _provider(json.dumps({"scenarios": [], "coverage_decisions": []}))
    report = _driver(workspace, provider=provider).run(REF)
    assert workspace.backlog_done
    assert report.scenarios_completed == 1


def test_an_export_failure_never_discards_a_completed_run() -> None:
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))

    def boom(ref: RunRef, out: object = None) -> None:
        from engagement.workspace import WorkspaceError

        raise WorkspaceError("blob storage unavailable")

    workspace.emit_sarif = boom  # type: ignore[assignment, method-assign]
    report = _driver(workspace).run(REF)

    assert report.scenarios_completed == 1
    assert any("SARIF was not written" in warning for warning in report.warnings)


def test_a_fenced_router_answer_is_unwrapped_before_the_recorder_sees_it() -> None:
    """A live DSVW run failed here: the model fenced its JSON in ```json, the
    router path handed it straight to the workspace, and json.loads died at
    character 0. The scenario and triage paths never hit it because `_stamp`
    parses and re-serialises."""
    from engagement.budget import Ledger
    from engagement.driver import Driver, Policy
    from engagement.providers import FakeProvider

    fenced = '```json\n{"scenarios": []}\n```'
    workspace = FakeWorkspace(scenarios=[], backlog_done=False)
    driver = Driver(
        workspace=workspace,
        provider=FakeProvider(answers=[fenced]),
        ledger=Ledger(),
        policy=Policy(model="m"),
    )
    driver._do_router(RunRef(target="acme", run_id="run-001"), RunReport(
        ref=RunRef(target="acme", run_id="run-001"), phase=Phase.router
    ))

    assert workspace.backlog_json is not None
    assert not workspace.backlog_json.lstrip().startswith("`")
    json.loads(workspace.backlog_json)


def test_a_truncated_router_answer_names_the_likely_cause() -> None:
    from engagement.driver import _unfence
    from engagement.workspace import WorkspaceError

    with pytest.raises(WorkspaceError, match="may have been truncated"):
        _unfence('```json\n{"scenarios": [{"id": "S001"')
