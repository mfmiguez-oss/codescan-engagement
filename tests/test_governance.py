"""Human accountability for work no human watched.

If every automated decision is final and none is ever checked, there is no
evidence the decisions are good — only the absence of evidence that they are
bad. The two look identical on a dashboard.
"""

from __future__ import annotations

from engagement.governance import RiskTier, is_sampled, review, sample_rate

_DECISIONS = {f"C{n:03d}": "accepted" for n in range(200)}


def test_sampling_is_stable_across_reruns() -> None:
    """A reviewer's queue must not change underneath them."""
    first = review(_DECISIONS, run_id="run-001")
    second = review(_DECISIONS, run_id="run-001")

    assert [d.item_id for d in first.sampled] == [d.item_id for d in second.sampled]


def test_a_different_run_samples_a_different_set() -> None:
    first = {d.item_id for d in review(_DECISIONS, run_id="run-001").sampled}
    second = {d.item_id for d in review(_DECISIONS, run_id="run-002").sampled}

    assert first != second


def test_selection_is_uniform_at_the_configured_rate() -> None:
    """Asserted over many runs, not one.

    Selection is deterministic per run, so a single run is one draw from a
    binomial and can sit well off the rate by chance — `run-001` lands at 4%
    against a 10% rate, which is ~2.8 sigma and entirely legitimate. The
    property that matters is that the *selector* is unbiased, and that only
    shows up across runs.
    """
    rates = [
        len(review(_DECISIONS, run_id=f"run-{n:03d}", tier=RiskTier.standard).sampled)
        / len(_DECISIONS)
        for n in range(40)
    ]
    mean = sum(rates) / len(rates)

    assert 0.085 < mean < 0.115, f"selector is biased: mean {mean:.3f} against 0.10"


def test_a_single_run_is_one_draw_and_may_sit_off_the_rate() -> None:
    """Documents the above so nobody 'fixes' a run that is merely unlucky."""
    fraction = len(review(_DECISIONS, run_id="run-001").sampled) / len(_DECISIONS)

    assert 0.0 < fraction < 0.30


def test_the_critical_tier_reviews_every_decision() -> None:
    """Which is the same as saying this tier is not adjudicated unattended."""
    report = review(_DECISIONS, run_id="run-001", tier=RiskTier.critical)

    assert len(report.sampled) == len(report.decisions)
    assert sample_rate(RiskTier.critical) == 1.0


def test_a_lower_tier_reviews_less_than_a_higher_one() -> None:
    assert sample_rate(RiskTier.low) < sample_rate(RiskTier.standard)
    assert sample_rate(RiskTier.standard) < sample_rate(RiskTier.critical)


def test_disabled_sampling_says_quality_is_unmeasured_not_verified() -> None:
    report = review(_DECISIONS, run_id="run-001", rate=0.0)

    assert report.sampled == []
    assert any("unmeasured, not verified" in w for w in report.warnings)


def test_the_review_backlog_is_reported_as_incomplete_adjudication() -> None:
    report = review(_DECISIONS, run_id="run-001")

    assert any("not fully adjudicated until they are checked" in w for w in report.warnings)


# -- shadow mode -------------------------------------------------------------


def test_a_shadowed_models_decisions_do_not_count() -> None:
    report = review(
        {"C1": "accepted", "C2": "rejected"},
        run_id="run-001",
        shadow_models=["new-model"],
        model_of={"C1": "new-model", "C2": "trusted-model"},
    )

    assert [d.item_id for d in report.shadowed] == ["C1"]
    assert [d.item_id for d in report.binding] == ["C2"]


def test_a_shadowed_decision_is_recorded_not_discarded() -> None:
    """It has to be visible, or shadow mode is just deletion."""
    report = review(
        {"C1": "accepted"},
        run_id="run-001",
        shadow_models=["new-model"],
        model_of={"C1": "new-model"},
    )

    assert len(report.decisions) == 1
    assert report.decisions[0].decision == "accepted"
    assert "does not count until" in report.decisions[0].reason


def test_shadow_status_is_reported() -> None:
    report = review(
        {"C1": "accepted"},
        run_id="run-001",
        shadow_models=["new-model"],
        model_of={"C1": "new-model"},
    )

    assert any("are advisory" in w for w in report.warnings)


def test_without_model_attribution_nothing_is_shadowed() -> None:
    """The safe direction: a decision wrongly treated as binding is visible in
    the queue, while one wrongly discarded is not."""
    report = review({"C1": "accepted"}, run_id="run-001", shadow_models=["new-model"])

    assert report.shadowed == []


def test_an_explicit_rate_overrides_the_tier() -> None:
    report = review(_DECISIONS, run_id="run-001", tier=RiskTier.low, rate=1.0)

    assert len(report.sampled) == len(report.decisions)


def test_a_rate_outside_the_range_is_clamped() -> None:
    assert sample_rate(RiskTier.low, 5.0) == 1.0
    assert sample_rate(RiskTier.low, -1.0) == 0.0


def test_selection_does_not_depend_on_the_decision_itself() -> None:
    """Nothing about a finding can be arranged to avoid review."""
    accepted = is_sampled("run-001", "C042", 0.5)
    assert is_sampled("run-001", "C042", 0.5) == accepted
