"""Properties of the deployment check.

Two distinctions carry this whole module, and both are easy to collapse by
accident:

- **Missing is not unknown.** A provider that says "I do not serve that" and one
  that cannot answer produce different verdicts. Collapsing them either blocks
  runs whose inference would have worked, or waves through a model nobody
  deployed.
- **Reporting is not choosing.** The check knows which models *are* available,
  which makes substituting one the obvious next line of code — and the thing
  that must never be written. A swap changes the bill and the findings while
  every count still looks healthy.
"""

from __future__ import annotations

import argparse

from engagement import cli
from engagement.preflight import PreflightReport, check, deployments_for
from engagement.providers import FakeProvider

SERVED = ["claude-opus-5", "claude-haiku-4-5", "gpt-5-mini"]


# -- missing is not unknown --------------------------------------------------


def test_a_configured_model_the_provider_does_not_serve_is_missing() -> None:
    report = check({"scenarios": "claude-opus-9"}, SERVED)

    assert report.checked
    assert report.missing == ["claude-opus-9"]
    assert not report.ok


def test_a_provider_that_cannot_answer_leaves_the_run_unchecked() -> None:
    """Blocking on a failed *list* call turns an advisory check into an outage
    for runs whose inference would have worked fine."""
    report = check({"scenarios": "claude-opus-9"}, [])

    assert not report.checked
    assert report.missing == []
    assert report.ok, "an unverifiable run was reported as broken"
    assert any("could not tell" in w for w in report.warnings)


def test_an_unchecked_result_says_so_rather_than_claiming_a_pass() -> None:
    lines = " ".join(check({"scenarios": "m"}, []).describe())

    assert "unchecked" in lines
    assert "not known to be misconfigured" in lines


# -- a listing is not evidence -----------------------------------------------


def test_a_listed_model_the_resource_will_not_serve_is_still_missing() -> None:
    """The failure this exists for. Foundry's listing is the region *catalog*,
    not an inventory of what is deployed, and the records are identical either
    way — so `claude-sonnet-5` was reported available among 382 and then 404'd
    at the router call with recon already paid for. Without the confirmation
    step this check could not fail on a real name at all."""
    listed = [*SERVED, "claude-sonnet-5"]

    optimistic = check({"scenarios": "claude-sonnet-5"}, listed)
    assert optimistic.ok, "precondition: the listing accepts it"

    report = check(
        {"scenarios": "claude-sonnet-5"},
        listed,
        confirm=lambda name: name != "claude-sonnet-5",
    )
    assert not report.ok
    assert report.missing == ["claude-sonnet-5"]
    assert report.wanted_by == {"claude-sonnet-5": ["scenarios"]}
    assert any("catalog" in w for w in report.warnings)


def test_a_probe_that_cannot_answer_leaves_the_listing_standing() -> None:
    """A 401, a 429 or a timeout says nothing about whether a deployment
    exists. Reading unknown as absent would refuse runs whose inference works —
    the same collapse this module refuses everywhere else."""
    report = check({"scenarios": "claude-opus-5"}, SERVED, confirm=lambda _: None)

    assert report.ok
    assert report.missing == []


def test_a_name_the_listing_already_refused_is_not_probed() -> None:
    """It is already known-missing, so a probe spends a call to learn nothing."""
    asked: list[str] = []

    def confirm(name: str) -> bool | None:
        asked.append(name)
        return True

    check({"scenarios": "claude-opus-9", "triage": "gpt-5-mini"}, SERVED, confirm)
    assert asked == ["gpt-5-mini"]


def test_one_model_wanted_by_several_tasks_is_probed_once() -> None:
    """The answer is a property of the deployment, not of the task asking, and
    one probe per task would scale the check with the routing table."""
    asked: list[str] = []

    def confirm(name: str) -> bool | None:
        asked.append(name)
        return True

    check(
        {"router": "claude-opus-5", "scenarios": "claude-opus-5", "triage": "gpt-5-mini"},
        SERVED,
        confirm,
    )
    assert sorted(asked) == ["claude-opus-5", "gpt-5-mini"]
    assert len(asked) == 2


def test_every_task_wanting_a_refuted_model_is_named() -> None:
    """The report has to say which tasks are affected, or the operator fixes one
    flag and hits the same wall on the next phase."""
    report = check(
        {"router": "claude-opus-5", "scenarios": "claude-opus-5"},
        SERVED,
        confirm=lambda _: False,
    )
    assert report.wanted_by == {"claude-opus-5": ["router", "scenarios"]}


def test_a_refused_model_is_not_offered_as_its_own_alternative() -> None:
    """"`claude-sonnet-5` is not served — try claude-sonnet-5" is what this
    printed live, because `available` is the listing and a probe-refused name is
    still in it."""
    report = check(
        {"scenarios": "claude-sonnet-5"},
        [*SERVED, "claude-sonnet-4-6", "claude-sonnet-5"],
        confirm=lambda name: name != "claude-sonnet-5",
    )
    near = report.near_misses()
    assert "claude-sonnet-5" not in near, "refused model offered as its own fix"
    assert "claude-sonnet-4-6" in near, "the real alternative went missing too"


def test_the_cli_second_guesses_the_listing_through_the_provider() -> None:
    """Wiring, not logic: the confirmation is worth nothing if the CLI never
    passes it. `FakeProvider.probes` stages a name the listing accepts and the
    resource refuses."""
    provider = FakeProvider(
        deployments=[*SERVED, "claude-sonnet-5"],
        probes={"claude-sonnet-5": False},
    )
    report = cli._run_preflight(provider, {"scenarios": "claude-sonnet-5"}, quiet=True)

    assert not report.ok
    assert report.missing == ["claude-sonnet-5"]


def test_everything_present_is_a_clean_pass() -> None:
    report = check({"scenarios": "claude-opus-5", "triage": "gpt-5-mini"}, SERVED)

    assert report.ok and report.checked
    assert report.missing == []


# -- reporting is not choosing -----------------------------------------------


def test_the_report_carries_no_field_that_could_become_a_replacement() -> None:
    """Structural, not textual. The failure this guards is a future edit: the
    check knows what is available, so pairing each missing model with a
    "suggested" one is the obvious next line — and a silent swap changes the
    bill and the queue while the call count stays identical."""
    fields = set(PreflightReport.model_fields)

    assert not fields & {
        "suggested",
        "replacement",
        "substitute",
        "fallback",
        "resolved",
        "chosen",
    }, "the report gained a field that pairs a missing model with another"


def test_the_report_states_that_it_will_not_choose_for_you() -> None:
    text = " ".join(check({"scenarios": "claude-opus-9"}, SERVED).describe()).lower()

    assert "does not substitute" in text
    for phrase in ("falling back to", "using instead", "switched to"):
        assert phrase not in text, f"the report proposes a swap: {phrase!r}"


def test_the_report_names_what_is_available_so_the_operator_can_choose() -> None:
    lines = check({"scenarios": "claude-opus-9"}, SERVED).describe()

    assert any("claude-opus-5" in line for line in lines)


def test_a_missing_deployment_names_the_tasks_that_wanted_it() -> None:
    """Two tasks pinned to one absent alias is one fix, not two."""
    report = check(
        {"router": "ghost", "scenarios": "ghost", "triage": "claude-opus-5"}, SERVED
    )

    assert report.wanted_by == {"ghost": ["router", "scenarios"]}


# -- naming across platforms -------------------------------------------------


def test_a_platform_prefix_does_not_make_a_present_model_look_missing() -> None:
    """Bedrock writes `anthropic.` and a cross-region profile adds `us.`. A
    run configured with the profile id against a foundation-model listing is
    correctly configured."""
    report = check({"scenarios": "us.anthropic.claude-opus-5"}, SERVED)

    assert report.ok, f"a prefixed alias read as missing: {report.missing}"


def test_a_bare_name_matches_a_prefixed_listing() -> None:
    report = check({"scenarios": "claude-opus-5"}, ["anthropic.claude-opus-5"])

    assert report.ok


def test_an_unpriced_deployment_is_a_warning_not_a_failure() -> None:
    """It still runs; it is the projection that cannot cost it."""
    report = check({"scenarios": "some-private-alias"}, ["some-private-alias"])

    assert report.ok
    assert any("no published rate" in w for w in report.warnings)


def test_a_missing_deployment_is_not_also_reported_as_unpriced() -> None:
    """"No published rate, the run will proceed" is a confusing thing to say
    about a model the same report is refusing."""
    report = check({"scenarios": "ghost-model"}, SERVED)

    assert not report.ok
    assert not any("no published rate" in w for w in report.warnings)


# -- a usable failure message ------------------------------------------------


def test_a_failure_lists_the_family_asked_for_not_the_whole_resource() -> None:
    """A resource can serve hundreds of models. A wall of them turns a precise
    error into something an operator scrolls past."""
    resource = [f"filler-model-{n}" for n in range(200)] + [
        "claude-opus-5",
        "claude-opus-4-8",
    ]
    lines = check({"scenarios": "claude-opus-9-turbo"}, resource).describe()
    text = "\n".join(lines)

    assert "closest available:" in text
    assert "claude-opus-5" in text
    assert "filler-model-7" not in text, "unrelated models were listed"
    assert "more" in text, "the count of what was omitted was not stated"


def test_the_whole_list_is_bounded_even_with_no_near_miss() -> None:
    resource = [f"filler-model-{n}" for n in range(200)]
    lines = check({"scenarios": "zzz-nothing-like-it"}, resource).describe()

    assert len(lines) < 25, "an unbounded resource listing reached the operator"


def test_near_misses_are_a_filtered_view_not_a_ranked_suggestion() -> None:
    report = check({"scenarios": "claude-opus-9"}, SERVED)

    assert report.near_misses() == sorted(report.near_misses()), (
        "near misses are ordered by similarity, which reads as a recommendation"
    )


# -- what a run could reach --------------------------------------------------


def test_every_task_a_run_could_reach_is_checked() -> None:
    """A second pass that fails at dispatch has already cost the first one."""
    wanted = deployments_for(
        model="base", analysis_model="cheap", second_model="other-vendor"
    )

    assert set(wanted.values()) == {"base", "cheap", "other-vendor"}
    assert "scenarios (second pass)" in wanted


def test_a_per_task_override_is_what_gets_checked() -> None:
    wanted = deployments_for(model="base", expert_model="frontier")

    assert wanted["scenarios"] == "frontier"
    assert wanted["router"] == "base"


def test_no_second_pass_means_nothing_is_checked_for_one() -> None:
    assert "scenarios (second pass)" not in deployments_for(model="base")


# -- the CLI ----------------------------------------------------------------


def _args(**extra: object) -> argparse.Namespace:
    argv = ["preflight"]
    for key, value in extra.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    return cli._build_parser().parse_args(argv)


def test_preflight_with_no_model_named_refuses_rather_than_checking_nothing() -> None:
    assert cli._cmd_preflight(_args(), {}) == cli.EXIT_CONFIG


def test_a_failed_check_exits_config_so_a_scheduler_notices() -> None:
    provider = FakeProvider(deployments=SERVED)
    report = cli._run_preflight(provider, {"scenarios": "ghost"}, quiet=True)

    assert not report.ok


def test_an_unchecked_run_is_not_reported_as_a_clean_pass() -> None:
    """Exit 3 is this CLI's "finished, but not cleanly" code. A scheduler that
    treats it as success is making the same mistake as one ignoring a parked
    run."""
    provider = FakeProvider(deployments=[])
    report = cli._run_preflight(provider, {"scenarios": "anything"}, quiet=True)

    assert report.ok and not report.checked


def test_the_fake_provider_reports_nothing_by_default() -> None:
    """A fake that claimed to serve everything would make every preflight test
    pass for the wrong reason."""
    assert FakeProvider().list_deployments() == []


def test_a_run_can_opt_out_of_the_check() -> None:
    args = cli._build_parser().parse_args(
        ["run", "acme", "run-001", "--workspace", ".", "--no-preflight"]
    )

    assert args.no_preflight is True


def test_a_run_checks_by_default() -> None:
    args = cli._build_parser().parse_args(
        ["run", "acme", "run-001", "--workspace", "."]
    )

    assert args.no_preflight is False


def test_dash_dash_model_does_not_override_the_per_task_defaults() -> None:
    """The consequence of shipping CLI defaults, pinned because it surprises
    people and costs money when it does.

    `deployments_for` resolves a per-task name ahead of the shared one, and on
    `run`/`plan`/`preflight` every per-task flag carries a default — so the
    shared flag is a fallback that nothing ever falls back to. Someone reading
    `--model gpt-5-mini` reasonably expects the run to use it, and it does not.
    Documented in docs/MODELS.md §5; if this assertion ever flips, that section
    is what has to change with it.
    """
    args = cli._build_parser().parse_args(["preflight", "--model", "gpt-5-mini"])
    wanted = deployments_for(
        model=args.model,
        router_model=args.router_model,
        expert_model=args.expert_model,
        triage_model=args.triage_model,
        analysis_model=args.analysis_model,
        chains_model=args.chains_model,
    )

    assert "gpt-5-mini" not in wanted.values()
    assert wanted["router"] == cli.DEFAULT_ROUTER_MODEL


def test_clearing_a_per_task_flag_is_what_lets_dash_dash_model_through() -> None:
    """The documented escape hatch, so the instruction in MODELS.md §5 is a
    tested one rather than a plausible one."""
    args = cli._build_parser().parse_args(
        ["preflight", "--model", "gpt-5-mini", "--router-model", ""]
    )
    wanted = deployments_for(model=args.model, router_model=args.router_model)

    assert wanted["router"] == "gpt-5-mini"


# -- the report model --------------------------------------------------------


def test_an_empty_report_is_ok_and_says_nothing_alarming() -> None:
    assert PreflightReport().ok
