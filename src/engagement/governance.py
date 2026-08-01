"""Keeping a human accountable for work no human watched.

An unattended run adjudicates findings with nobody in the loop. That is the
point of it, and it is also the risk: if every automated decision is final and
none is ever checked, there is no evidence the decisions are any good — only
the absence of evidence that they are bad. The two are easy to confuse, and a
dashboard full of green makes them look identical.

Two mechanisms, both from how a mature AI-native SDLC governs its own agents:

**Sampling.** A fraction of automated decisions is flagged for human review, not
because those decisions are suspect but because reviewing a random sample is the
only way to measure the quality of the whole. Selection is *deterministic* —
seeded on the run and the item — so a rerun samples the same items and a
reviewer can be handed a stable list, but nothing about which items get sampled
is predictable from the finding itself.

**Shadow mode.** A newly introduced model or agent contributes findings that are
recorded and reported but do **not** count as adjudicated: they carry no weight
until the agent has demonstrated it agrees with reviewed outcomes. A new
reviewer earns trust rather than being granted it by deployment.

Both are reported into the run's own audit trail, so "how many decisions did
nobody look at" is answerable after the fact instead of assumed.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import Field

from .contracts import StrictModel


class RiskTier(str, Enum):
    """How much of a target's adjudication may go unreviewed.

    Tiering is the lever that lets automation scale without applying the same
    trust everywhere: a payments service and an internal dashboard should not
    get the same fraction of unchecked decisions.
    """

    critical = "critical"
    standard = "standard"
    low = "low"


#: Fraction of automated decisions flagged for human review, per tier. The
#: critical tier is 1.0 — every decision is reviewed, which is the same as
#: saying this tier is not adjudicated unattended at all.
SAMPLE_RATE: dict[RiskTier, float] = {
    RiskTier.critical: 1.0,
    RiskTier.standard: 0.10,
    RiskTier.low: 0.02,
}


class Decision(StrictModel):
    """One automated adjudication, and whether a human is asked to check it."""

    item_id: str
    decision: str
    sampled: bool = False
    shadow: bool = False
    reason: str = ""


class GovernanceReport(StrictModel):
    """What was decided automatically, and what a human is asked to confirm."""

    tier: RiskTier = RiskTier.standard
    rate: float = 0.0
    decisions: list[Decision] = Field(default_factory=list)
    shadow_models: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def sampled(self) -> list[Decision]:
        return [d for d in self.decisions if d.sampled]

    @property
    def shadowed(self) -> list[Decision]:
        return [d for d in self.decisions if d.shadow]

    @property
    def binding(self) -> list[Decision]:
        """Decisions that actually count — neither shadowed nor pending review."""
        return [d for d in self.decisions if not d.shadow]


def sample_rate(tier: RiskTier, override: float | None = None) -> float:
    if override is None:
        return SAMPLE_RATE[tier]
    return max(0.0, min(1.0, override))


def is_sampled(run_id: str, item_id: str, rate: float) -> bool:
    """Deterministically select a stable fraction of items for review.

    Seeded on the run and the item rather than drawn at random, for two
    reasons that pull the same way: a rerun must produce the same review list,
    or a reviewer's queue changes underneath them; and a hash over an opaque id
    is not predictable from the finding's *content*, so nothing about a finding
    can be arranged to avoid review.
    """
    if rate >= 1.0:
        return True
    if rate <= 0.0:
        return False
    digest = hashlib.sha256(f"{run_id}|{item_id}".encode()).digest()
    # First 8 bytes as a fraction of the space. Uniform, and stable across
    # platforms in a way that `hash()` deliberately is not.
    value = int.from_bytes(digest[:8], "big") / float(1 << 64)
    return value < rate


def review(
    decisions: dict[str, str],
    run_id: str,
    tier: RiskTier = RiskTier.standard,
    rate: float | None = None,
    shadow_models: list[str] | None = None,
    model_of: dict[str, str] | None = None,
) -> GovernanceReport:
    """Mark automated decisions for sampling and shadow status.

    ``model_of`` maps an item to the deployment that decided it, so a shadowed
    model's decisions can be identified. Without it nothing is shadowed, which
    is the safe direction: a decision wrongly treated as binding is visible in
    the queue, while one wrongly discarded is not.
    """
    shadow = {m.strip() for m in (shadow_models or []) if m.strip()}
    effective = sample_rate(tier, rate)
    report = GovernanceReport(tier=tier, rate=effective, shadow_models=sorted(shadow))

    for item_id, decision in sorted(decisions.items()):
        model = (model_of or {}).get(item_id, "")
        is_shadow = bool(model and model in shadow)
        report.decisions.append(
            Decision(
                item_id=item_id,
                decision=decision,
                sampled=is_sampled(run_id, item_id, effective),
                shadow=is_shadow,
                reason=(
                    f"{model} is in shadow mode; this decision is recorded but "
                    "does not count until the model has earned trust"
                    if is_shadow
                    else ""
                ),
            )
        )

    if report.shadowed:
        report.warnings.append(
            f"governance: {len(report.shadowed)} decision(s) came from a model in "
            f"shadow mode ({', '.join(report.shadow_models)}) and are advisory — "
            "they are recorded but do not adjudicate anything"
        )
    if report.sampled:
        report.warnings.append(
            f"governance: {len(report.sampled)} of {len(report.decisions)} "
            f"automated decision(s) are flagged for human review at the "
            f"{report.tier.value} tier ({effective:.0%}); the queue is not "
            "fully adjudicated until they are checked"
        )
    elif report.decisions and effective > 0:
        report.warnings.append(
            f"governance: no decision was sampled for review out of "
            f"{len(report.decisions)} at a {effective:.0%} rate — expected for a "
            "small run, but it means nothing here was independently checked"
        )
    elif report.decisions and effective == 0:
        report.warnings.append(
            "governance: sampling is disabled, so no automated decision will be "
            "reviewed by a human. Decision quality is unmeasured, not verified"
        )
    return report
