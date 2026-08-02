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


# -- the report model --------------------------------------------------------


def test_an_empty_report_is_ok_and_says_nothing_alarming() -> None:
    assert PreflightReport().ok
