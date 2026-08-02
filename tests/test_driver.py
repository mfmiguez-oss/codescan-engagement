"""The properties that make an unattended run trustworthy.

Tests are named after the property, not the function.
"""

from __future__ import annotations

import json

import pytest

from engagement.budget import Budget, Ledger
from engagement.contracts import (
    Disposition,
    Phase,
    Priority,
    RunRef,
    RunReport,
    ScenarioRef,
)
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
    from engagement.driver import TruncatedAnswer, _router_answer

    with pytest.raises(TruncatedAnswer, match="truncated by the output limit"):
        _router_answer('```json\n{"scenarios": [{"id": "S001"')


def test_a_truncated_answer_is_distinguishable_from_a_rejected_one() -> None:
    """The two need opposite responses, so the router has to tell them apart.

    A rejected backlog is worth re-asking; a truncated one is not, because the
    same prompt truncates the same way. Sharing one exception type is what made
    the live BenchmarkPython run pay for two calls to fail once.
    """
    from engagement.driver import TruncatedAnswer, _router_answer
    from engagement.workspace import WorkspaceError

    with pytest.raises(WorkspaceError) as rejected:
        _router_answer('["not", "an", "object"]')

    assert not isinstance(rejected.value, TruncatedAnswer)


TRUNCATED = '{"scenarios": [{"id": "S001"'


def _chunk_answer(
    units: list[str], ids: list[str] | None = None, **extra: object
) -> str:
    """A well-formed router answer routing exactly the units it was assigned."""
    scenario_ids = ids or [f"S{n:03d}" for n in range(1, len(units) + 1)]
    return json.dumps({
        "scenarios": [
            {"id": sid, "routing_unit_id": unit, "expert": "injection"}
            for sid, unit in zip(scenario_ids, units, strict=True)
        ],
        "coverage_decisions": [],
        **extra,
    })


def _routed(workspace: FakeWorkspace) -> dict:
    return json.loads(workspace.backlog_json or "{}")


def test_the_backlog_is_routed_in_chunks_so_no_one_answer_has_to_hold_it_all() -> None:
    """The router's answer grows with the target, so a whole backlog cannot be
    asked for at once. A live BenchmarkPython run proved it: 606 routing units,
    one call, truncated mid-string at the output ceiling."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002", "U003", "U004", "U005"]
    provider = FakeProvider(answers=[
        _chunk_answer(["U001", "U002"]),
        _chunk_answer(["U003", "U004"]),
        _chunk_answer(["U005"]),
    ])
    driver = _driver(workspace, provider, router_chunk_units=2)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    assert len(provider.requests) == 3
    routed = [s["routing_unit_id"] for s in _routed(workspace)["scenarios"]]
    assert routed == workspace.units


def test_merged_scenarios_get_one_id_space_so_chunks_cannot_collide() -> None:
    """Every chunk numbers its own scenarios from S001. Merging without
    renumbering hands the recorder several scenarios claiming one id."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002"]
    provider = FakeProvider(answers=[
        _chunk_answer(["U001"], ["S001"]),
        _chunk_answer(["U002"], ["S001"]),
    ])
    driver = _driver(workspace, provider, router_chunk_units=1)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    scenarios = _routed(workspace)["scenarios"]
    assert [s["id"] for s in scenarios] == ["S001", "S002"]
    assert [s["routing_unit_id"] for s in scenarios] == ["U001", "U002"]


def test_only_the_assignment_varies_between_router_calls() -> None:
    """Chunking multiplies the calls, so the invariant material has to be paid
    for once rather than once per chunk. It is identical across calls by
    construction — which is exactly what makes it cacheable."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002", "U003"]
    # Padded past the deployment's minimum cacheable prefix. Below it the
    # dispatcher correctly declines to mark a breakpoint and folds the material
    # into the system prompt instead, so a short fake would assert nothing about
    # caching. A real router prompt is hundreds of kilobytes.
    workspace.prompt_extra = "padding. " * 4000
    provider = FakeProvider(answers=[
        _chunk_answer(["U001"]), _chunk_answer(["U002"]), _chunk_answer(["U003"])
    ])
    driver = _driver(workspace, provider, router_chunk_units=1)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    prefixes = {request.cache_prefix for request in provider.requests}
    assert len(prefixes) == 1
    assert prefixes.pop().startswith("# router prompt")
    assert driver.dispatcher.caching.offered == 3
    users = [request.user for request in provider.requests]
    assert len(set(users)) == len(users)
    assert "U001" in users[0] and "U001" not in users[1]


def test_a_router_call_gets_more_output_room_than_a_single_verdict_phase() -> None:
    """The 4096-token default is sized for a phase that returns one verdict. A
    router chunk returns a document; left on the default it truncates."""
    workspace = FakeWorkspace()
    workspace.units = ["U001"]
    provider = FakeProvider(answers=[_chunk_answer(["U001"])])
    driver = _driver(workspace, provider)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    assert provider.requests[0].max_output_tokens == Policy().router_max_output_tokens


def test_a_chunk_that_overruns_is_halved_rather_than_failing_the_run() -> None:
    """Chunk size is a tuning knob, not a correctness one: too large costs one
    wasted call before the split, and the run still completes."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002", "U003", "U004"]
    provider = FakeProvider(answers=[
        TRUNCATED,
        _chunk_answer(["U001", "U002"]),
        _chunk_answer(["U003", "U004"]),
    ])
    driver = _driver(workspace, provider, router_chunk_units=4)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    assert len(provider.requests) == 3
    routed = [s["routing_unit_id"] for s in _routed(workspace)["scenarios"]]
    assert routed == workspace.units


def test_a_truncation_is_never_retried_on_an_unchanged_prompt() -> None:
    """The failure that cost the live run twice. An identical prompt truncates
    identically, so a retry buys nothing; when a chunk is already one unit there
    is no split left and the ceiling is genuinely too low. Fail, do not spend."""
    from engagement.driver import TruncatedAnswer

    workspace = FakeWorkspace()
    workspace.units = ["U001"]
    provider = FakeProvider(answers=[TRUNCATED], default=TRUNCATED)
    driver = _driver(workspace, provider)

    with pytest.raises(TruncatedAnswer):
        driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    assert len(provider.requests) == 1


def test_units_the_router_ignored_are_reported_not_silently_dropped() -> None:
    """Work that was not done is never reported as work that found nothing. The
    recorder owns admissibility, so this says what happened and lets it rule."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002"]
    answer = _chunk_answer(["U001"])
    provider = FakeProvider(answers=[answer], default=answer)
    report = RunReport(ref=REF, phase=Phase.router)
    driver = _driver(workspace, provider, router_chunk_units=2)

    driver._do_router(REF, report)

    assert any("U002" in warning for warning in report.warnings)


def test_router_output_beyond_the_two_known_arrays_survives_the_merge() -> None:
    """The router also emits coverage notes. A merge that understood only
    scenarios and coverage decisions would drop them on every chunked run."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002"]
    provider = FakeProvider(answers=[
        _chunk_answer(["U001"], coverage_notes=["skipped crypto: no evidence"]),
        _chunk_answer(["U002"], coverage_notes=["skipped ldap: no sink"]),
    ])
    driver = _driver(workspace, provider, router_chunk_units=1)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    assert len(_routed(workspace)["coverage_notes"]) == 2


def test_a_failed_router_does_not_discard_the_chunks_it_already_paid_for() -> None:
    """The costliest defect the live runs found. The router is dozens of calls;
    holding the answers in memory meant one timeout on call 40 threw away 39
    paid-for answers. A live run lost $2.81 that way. Each answer is now durable,
    so the unit of loss is one call."""
    from engagement.providers import ProviderTimeout

    class _TimesOutOnThirdCall(FakeProvider):
        def complete(self, request: object) -> object:
            if len(self.requests) == 2:
                raise ProviderTimeout("no response within 600s")
            return super().complete(request)  # type: ignore[arg-type]

    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002", "U003"]
    provider = _TimesOutOnThirdCall(answers=[
        _chunk_answer(["U001"]), _chunk_answer(["U002"]), _chunk_answer(["U003"])
    ])
    driver = _driver(workspace, provider, router_chunk_units=1)

    with pytest.raises(ProviderTimeout):
        driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    # The two answers bought before the failure survived it.
    assert len(workspace.router_chunks) == 2


def test_a_resumed_router_re_asks_only_the_chunks_it_never_answered() -> None:
    """Resume is what makes the durability worth having: a re-run after a
    transient failure costs the remaining calls, not all of them again."""
    workspace = FakeWorkspace()
    workspace.units = ["U001", "U002", "U003"]
    first = FakeProvider(answers=[
        _chunk_answer(["U001"]), _chunk_answer(["U002"]), _chunk_answer(["U003"])
    ])
    _driver(workspace, first, router_chunk_units=1)._do_router(
        REF, RunReport(ref=REF, phase=Phase.router)
    )
    assert len(first.requests) == 3

    # Same workspace, fresh driver and provider: nothing left to ask.
    second = FakeProvider(answers=[], default="{}")
    _driver(workspace, second, router_chunk_units=1)._do_router(
        REF, RunReport(ref=REF, phase=Phase.router)
    )

    assert second.requests == []
    routed = [s["routing_unit_id"] for s in _routed(workspace)["scenarios"]]
    assert routed == workspace.units


def test_a_resumed_chunk_is_matched_by_its_units_not_its_position() -> None:
    """Halving renumbers every chunk after the split, so a positional key would
    make a resumed run read back the answer to a different assignment."""
    from engagement.driver import _chunk_key

    assert _chunk_key(["U001", "U002"]) == _chunk_key(["U001", "U002"])
    assert _chunk_key(["U001", "U002"]) != _chunk_key(["U002", "U001"])
    assert _chunk_key(["U001"]) != _chunk_key(["U001", "U002"])


def test_a_target_with_no_routing_units_still_routes_in_one_call() -> None:
    """Nothing to split on means nothing to chunk, and the prompt is the whole
    task rather than shared material — so it is asked, not cached."""
    workspace = FakeWorkspace()
    provider = FakeProvider(answers=['{"scenarios": [], "coverage_decisions": []}'])
    driver = _driver(workspace, provider)

    driver._do_router(REF, RunReport(ref=REF, phase=Phase.router))

    assert len(provider.requests) == 1
    assert provider.requests[0].cache_prefix == ""


def _verified(count: int, experts: tuple[str, ...] = ("injection",)) -> FakeWorkspace:
    backlog = [
        ScenarioRef(scenario_id=f"S{n:03d}", expert=experts[n % len(experts)])
        for n in range(1, count + 1)
    ]
    return FakeWorkspace(scenarios=backlog)


def test_concurrent_scenarios_all_complete_and_none_is_lost() -> None:
    """The scenario phase is one call per scenario and hundreds of them, all
    independent, so wall clock is otherwise just their generation summed."""
    workspace = _verified(12)
    driver = _driver(workspace, _provider('{"status": "verified"}'), scenario_concurrency=4)

    report = driver.run(REF)

    completed = [s for s in report.scenarios if s.disposition == Disposition.completed]
    assert len(completed) == 12
    assert len({s.item_id for s in report.scenarios}) == 12


def test_concurrent_scenarios_never_touch_the_workspace_at_the_same_time() -> None:
    """The workspace is a CLI over one run directory. Two `openhack` processes
    against it would interleave their appends to the shared trace and state."""
    workspace = _verified(12)
    driver = _driver(workspace, _provider('{"status": "verified"}'), scenario_concurrency=6)

    driver.run(REF)

    assert workspace.max_concurrent_workspace_calls == 1


def test_the_call_ceiling_still_holds_when_scenarios_run_concurrently() -> None:
    """A ceiling enforced only under one thread is not a ceiling. Workers that
    lose the race for the last slots are recorded, not silently dropped."""
    workspace = _verified(20)
    driver = _driver(
        workspace,
        _provider('{"status": "verified"}'),
        budget=Budget(max_calls=5),
        scenario_concurrency=8,
    )

    report = driver.run(REF)

    assert driver.ledger.calls <= 5
    # Every scenario is accounted for either way: dispatched, or named unfunded.
    assert len(report.scenarios) == 20
    assert any("NOT known to be clean" in w for w in report.warnings)


def test_one_scenario_per_expert_goes_out_before_the_rest_fan_out() -> None:
    """The expert manifest is the cached prefix, and a cache entry only becomes
    readable once the response that wrote it has begun. Fanning out cold means
    every worker misses at once and each pays the write premium."""
    experts = ("injection", "crypto", "access")
    workspace = _verified(12, experts=experts)
    by_id = {item.scenario_id: item.expert for item in workspace.backlog}
    provider = _provider('{"status": "verified"}')
    driver = _driver(workspace, provider, scenario_concurrency=6)

    driver.run(REF)

    # The first three dispatches are the warming ones: sent in series, one per
    # distinct expert, before anything fans out.
    warmed = [
        expert
        for sid, expert in by_id.items()
        if any(sid in request.user for request in provider.requests[:3])
    ]
    assert sorted(warmed) == sorted(experts)


def test_a_single_worker_is_the_default_and_stays_serial() -> None:
    """Raising concurrency is a decision about the resource's per-minute quota,
    not a free speedup, so it is opt-in."""
    assert Policy().scenario_concurrency == 1


def test_a_declared_needs_context_reaches_expansion_even_if_the_recorder_refuses() -> None:
    """A live DSVW run failed every scenario here. The model correctly answered
    `needs_context` with nothing reviewed — it had been shown no source — and the
    result schema rejects that because it demands non-empty evidence. Retrying
    cannot help and failing discards the model's own statement of what it lacked,
    which is the only useful input to an expansion."""
    from engagement.driver import _declared_needs_context

    declared = _declared_needs_context(
        '{"status": "needs_context", "missing_context": ["need src/app.py"]}'
    )

    assert declared is not None
    assert declared.missing_context == ["need src/app.py"]


def test_a_genuinely_malformed_answer_still_fails_rather_than_expanding() -> None:
    """The narrowness is the point: only a *declared* needs_context is rescued."""
    from engagement.driver import _declared_needs_context

    assert _declared_needs_context("not json at all") is None
    assert _declared_needs_context('{"status": "verified"}') is None
    assert _declared_needs_context('["a", "list"]') is None


def test_a_refused_needs_context_scenario_parks_instead_of_failing() -> None:
    from engagement.budget import Ledger
    from engagement.contracts import Disposition
    from engagement.driver import Driver, Policy
    from engagement.providers import FakeProvider

    answer = '{"status": "needs_context", "missing_context": ["need dsvw.py"]}'
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.reject = {"S001"}  # the recorder refuses it, as the real one does
    driver = Driver(
        workspace=workspace,
        provider=FakeProvider(answers=[answer] * 6),
        ledger=Ledger(),
        policy=Policy(model="m", expand_context=False),
    )
    report = driver.run(RunRef(target="acme", run_id="run-001"))

    assert [item.disposition for item in report.scenarios] == [Disposition.parked]
    assert report.parked[0].missing_context == ["need dsvw.py"]
