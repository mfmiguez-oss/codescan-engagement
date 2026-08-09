"""Properties of model routing, cost projection, and sampling support.

The load-bearing test here is
``test_a_family_that_removed_sampling_is_never_sent_temperature``. Sending
``temperature`` to a model that removed it is a 400 — the whole call fails — so
a determinism setting that looks harmless is a hard outage on exactly the models
an operator routes the hardest work to.
"""

from __future__ import annotations

import pytest

from engagement.models import (
    CATALOGUE,
    PROFILES,
    Task,
    Tier,
    accepts_sampling,
    build_plan,
    render_plan,
    sampling_for,
    spec_for,
)
from engagement.providers import BedrockProvider, FoundryProvider, ModelRequest

_ALL = {task.value: "claude-haiku-4-5" for task in Task}


# -- sampling support is a per-family fact -----------------------------------


def test_a_family_that_removed_sampling_is_never_sent_temperature() -> None:
    """Opus 4.7+, Opus 5, Sonnet 5 and Fable 5 reject it with a 400."""
    for deployment in (
        "claude-opus-5",
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-sonnet-5",
        "claude-fable-5",
    ):
        assert not accepts_sampling(deployment), deployment
        assert sampling_for(deployment, 0.0, 42) == {}


def test_a_family_that_still_accepts_sampling_gets_it() -> None:
    assert sampling_for("claude-haiku-4-5", 0.0, None) == {"temperature": 0.0}


def test_a_seed_only_goes_to_a_surface_that_understands_one() -> None:
    assert sampling_for("gpt-5.6-luna", 0.0, 7) == {"temperature": 0.0, "seed": 7}
    # the Anthropic surface has no seed parameter at all
    assert "seed" not in sampling_for("claude-haiku-4-5", 0.0, 7)


def test_an_unknown_deployment_defaults_to_sending_sampling() -> None:
    """An unrecognised alias is more likely an older family than a new one."""
    assert accepts_sampling("some-internal-alias")


def test_a_prefix_match_catches_an_alias_not_in_the_catalogue() -> None:
    """Deployment aliases are named by whoever configured the resource."""
    assert not accepts_sampling("claude-opus-5-prod-eastus2")


# -- the wire request honours it ---------------------------------------------


def test_the_foundry_body_omits_temperature_for_a_removed_family() -> None:
    provider = FoundryProvider(resource="r", api_key="k")
    request = ModelRequest(deployment="claude-opus-5", system="s", user="u")

    assert "temperature" not in provider.build_request(request)["body"]


def test_a_platform_prefix_does_not_defeat_the_family_match() -> None:
    """Bedrock writes `anthropic.claude-opus-5`; cross-region adds `us.`.

    This was a live defect: the prefix meant the family check never fired and
    temperature went to a model that rejects it — a 400 on the whole call.
    """
    for deployment in (
        "anthropic.claude-opus-5",
        "us.anthropic.claude-opus-5",
        "eu.anthropic.claude-sonnet-5",
    ):
        assert not accepts_sampling(deployment), deployment


def test_the_foundry_body_carries_temperature_where_it_is_accepted() -> None:
    provider = FoundryProvider(resource="r", api_key="k")
    body = provider.build_request(
        ModelRequest(deployment="claude-haiku-4-5", system="s", user="u")
    )["body"]

    assert body["temperature"] == 0.0


def test_the_openai_surface_carries_temperature_and_seed() -> None:
    provider = FoundryProvider(resource="r", api_key="k")
    body = provider.build_request(
        ModelRequest(deployment="gpt-5.6-luna", system="s", user="u", seed=11)
    )["body"]

    assert body["temperature"] == 0.0
    assert body["seed"] == 11


def test_bedrock_applies_the_same_family_rule() -> None:
    provider = BedrockProvider(region="us-east-1", inference_geo="us")
    removed = provider.build_request(
        ModelRequest(deployment="anthropic.claude-opus-5", system="s", user="u")
    )
    kept = provider.build_request(
        ModelRequest(deployment="anthropic.claude-haiku-4-5", system="s", user="u")
    )

    assert "temperature" not in removed["inferenceConfig"]
    assert kept["inferenceConfig"]["temperature"] == 0.0


def test_the_default_temperature_is_zero() -> None:
    """A queue that changes between identical runs cannot be regression-tested."""
    assert ModelRequest(deployment="d", system="s", user="u").temperature == 0.0


# -- the allocation ----------------------------------------------------------


def test_every_billable_task_has_a_profile_with_a_stated_reason() -> None:
    for task in Task:
        profile = PROFILES[task]
        assert profile.rationale.strip(), task
        assert profile.volume.strip(), task


def test_judgement_heavy_low_volume_tasks_get_the_top_tier() -> None:
    """The allocation rule: spend on judgement, economise on volume."""
    assert PROFILES[Task.router].tier is Tier.frontier
    assert PROFILES[Task.scenarios].tier is Tier.frontier
    assert PROFILES[Task.poc].tier is Tier.economy


def test_the_plan_projects_one_call_per_scenario_and_candidate() -> None:
    plan = build_plan(_ALL, scenarios=12, candidates=5, services=2, findings=25)
    calls = {a.task: a.projected_calls for a in plan.allocations}

    assert calls[Task.router] == 1
    assert calls[Task.scenarios] == 12
    assert calls[Task.triage] == 5
    assert calls[Task.chains] == 2
    assert calls[Task.poc] == 3  # 25 findings, batches of 10


def test_the_poc_projection_respects_the_cap() -> None:
    plan = build_plan(_ALL, scenarios=1, findings=500)
    poc = next(a for a in plan.allocations if a.task is Task.poc)

    assert poc.projected_calls == 4  # cap of 40, in batches of 10


def test_the_projection_counts_drafts_for_criticals_not_the_whole_queue() -> None:
    """The rule changed what drafting costs, and a projection that did not follow
    would quote a bill for work the run no longer does."""
    whole_queue = build_plan(_ALL, findings=40)
    critical_only = build_plan(_ALL, findings=40, critical_findings=5)

    assert next(
        a.projected_calls for a in whole_queue.allocations if a.task is Task.poc
    ) == 4
    assert next(
        a.projected_calls for a in critical_only.allocations if a.task is Task.poc
    ) == 1


def test_an_unstated_critical_count_over_projects_rather_than_under() -> None:
    """Too high costs an operator a raised eyebrow; too low costs them a run
    that stops halfway through."""
    unstated = build_plan(_ALL, findings=40)
    every_finding_critical = build_plan(_ALL, findings=40, critical_findings=40)

    assert [a.projected_calls for a in unstated.allocations] == [
        a.projected_calls for a in every_finding_critical.allocations
    ]


def test_a_task_with_no_deployment_is_reported_not_defaulted() -> None:
    """An unattended run that guesses a deployment guesses a bill."""
    plan = build_plan({"router": "claude-haiku-4-5"}, scenarios=3)

    assert any("no deployment set for scenarios" in w for w in plan.warnings)
    assert [a.task for a in plan.allocations] == [Task.router]


def test_an_unpriced_deployment_is_reported_rather_than_guessed() -> None:
    plan = build_plan({task.value: "some-private-alias" for task in Task}, scenarios=2)

    assert plan.unpriced() == ["some-private-alias"]
    assert any("no published rate" in w for w in plan.warnings)
    assert all(a.projected_cost() is None for a in plan.allocations)


def test_a_deployment_below_its_task_tier_is_flagged() -> None:
    plan = build_plan({task.value: "claude-haiku-4-5" for task in Task}, scenarios=5)

    assert any("scenarios wants the frontier tier" in w for w in plan.warnings)


def test_cost_is_computed_from_the_published_rate() -> None:
    plan = build_plan({task.value: "claude-opus-5" for task in Task}, scenarios=1_000_000)
    allocation = next(a for a in plan.allocations if a.task is Task.scenarios)

    # a million scenario calls, so the per-call shape reads straight off as
    # millions of tokens: 6100 in at $5, 2100 out at $25, plus the cache tiers
    # at their published ratios to input — a tenth for a read, a quarter more
    # for a write
    assert allocation.projected_cost() == pytest.approx(
        6100 * 5.0 + 2100 * 25.0 + 1600 * 0.5 + 530 * 6.25
    )


def test_a_task_is_priced_on_its_own_token_shape_not_a_pipeline_average() -> None:
    """One flat average put the router 7x light. A router chunk re-reads the
    whole recon and answers with a document; a scenario answer does neither."""
    plan = build_plan(
        {task.value: "claude-opus-5" for task in Task}, scenarios=1, obligations=12
    )
    router = next(a for a in plan.allocations if a.task is Task.router)
    scenarios = next(a for a in plan.allocations if a.task is Task.scenarios)

    assert router.per_call_output > 4 * scenarios.per_call_output
    assert router.per_call_cache_read > 10 * scenarios.per_call_cache_read
    # both are one call here, so the costs compare directly
    assert router.projected_calls == scenarios.projected_calls == 1
    assert router.projected_cost() > scenarios.projected_cost()  # type: ignore[operator]


def test_the_router_is_projected_per_chunk_not_per_run() -> None:
    """It was one call, and stopped being one when the backlog started being
    chunked. A live pygoat run took 25 while the table said 1."""
    plan = build_plan(
        {task.value: "claude-opus-5" for task in Task},
        scenarios=200,
        obligations=166,
        router_chunk_obligations=12,
    )
    router = next(a for a in plan.allocations if a.task is Task.router)

    assert router.projected_calls == 14  # ceil(166 / 12)
    assert any("is a floor" in w for w in plan.warnings)


def test_an_unknown_obligation_count_says_so_rather_than_projecting_one() -> None:
    """Before recon the count is genuinely unknown, and the honest answer is not
    '1 call'. A silent 1 is what made a $18 run read as $3.90."""
    plan = build_plan({task.value: "claude-opus-5" for task in Task}, scenarios=200)
    router = next(a for a in plan.allocations if a.task is Task.router)

    assert router.projected_calls == 1
    assert any(
        "not known until recon" in w and "floors, not estimates" in w
        for w in plan.warnings
    )


#: pygoat run-001, 2026-08-09, every call on claude-sonnet-4-6. Frozen from
#: that run's audit.jsonl, which is a runtime artifact and gitignored, so the
#: totals are copied here rather than read — the alternative is a test that
#: silently stops checking anything the day the temp directory is cleared.
_PYGOAT = {
    "obligations": 166,
    "scenarios": 245,
    "router_calls": 25,
    "scenario_calls": 250,
    "billed_usd": 17.81,
}


def test_the_projection_lands_near_a_run_that_actually_happened() -> None:
    """The reconciliation. A projection nobody has ever checked against a bill
    is a number with a dollar sign in front of it.

    This one said $3.90 for a run that billed about $18 — optimistic by 4.5x,
    which is the worst direction to be wrong in. The residual gap is the router
    line, and it is a *floor* by construction: the formula divides obligations
    evenly, and the real chunker cut pygoat's 166 into 23 rather than 14 because
    a path too heavy for one chunk becomes disjoint slices that cannot be packed
    together. So the projection is asserted to sit inside a band that is tight
    on the optimistic side and open on the other.
    """
    plan = build_plan(
        {task.value: "claude-sonnet-4-6" for task in Task},
        scenarios=_PYGOAT["scenarios"],
        services=0,
        obligations=_PYGOAT["obligations"],
    )
    projected = sum(
        cost
        for a in plan.allocations
        if a.task in {Task.router, Task.scenarios} and (cost := a.projected_cost())
    )

    billed = _PYGOAT["billed_usd"]
    assert 0.8 * billed <= projected <= 1.3 * billed, (
        f"projected ${projected:.2f} against ${billed:.2f} actually billed"
    )


def test_the_rendered_plan_names_every_task_and_totals_the_spend() -> None:
    rendered = render_plan(build_plan(_ALL, scenarios=4, candidates=2, findings=10))

    for task in Task:
        assert task.value in rendered
    assert "projected" in rendered


def test_every_catalogue_entry_is_self_consistent() -> None:
    for deployment, spec in CATALOGUE.items():
        assert spec.id == deployment
        assert spec.output_per_mtok >= spec.input_per_mtok, deployment
        assert spec_for(deployment) is spec
