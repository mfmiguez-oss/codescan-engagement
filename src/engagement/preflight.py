"""Checking a run's models exist before it starts spending.

An unattended run that names a deployment which is not on the resource fails at
first dispatch — after recon has run, after the workspace has been prepared,
and with an error that says "404" rather than "you asked for a model nobody
deployed". Worse, a run that gets three phases in before failing has already
spent the calls it took to get there.

This asks the provider what it serves and compares that against what the run
intends to use, before anything is dispatched.

## A listing is not always evidence

On Foundry it is not. ``/openai/v1/models`` returns the *catalog* of what the
region offers, not an inventory of what this resource has deployed, and the two
cannot be told apart from the payload — a model that answers and one that 404s
carry identical records, down to ``status: "succeeded"`` and
``capabilities.inference: true``. So this check silently could not fail: it
reported "every configured deployment is available (382 on the resource)" for a
model that then 404'd at the router call, with recon already paid for.

Hence ``confirm``: for each name the listing accepts, the provider is asked
about that one deployment on the surface the run will use. A check that cannot
fail is not a check, and here only the question the run itself asks can answer
it. The cost is one token-sized call per distinct configured model.

## The one rule: report availability, never act on it

The obvious next step — "the configured model is missing, so use one that is
present" — is the thing this deliberately does not do. A silent substitution
changes both the bill and the queue while every tally still looks healthy: the
call count is identical, the ledger balances, and the findings are different.
Two further reasons specific to this package: a substituted model may be the
same *vendor* as the second detection pass, which turns corroboration into two
models sharing a blind spot, and sampling support and cache minimums are
per-family, so a swap silently re-decides both.

So preflight refuses, names what is missing, and prints what *is* available so
the operator can choose. Choosing is theirs.

## Unknown is not missing

If the provider cannot answer — no permission to list, an unreachable endpoint,
an empty response — the result is **unchecked**, and an unchecked run proceeds
with a warning. Blocking on a failed *list* call would turn an advisory check
into an outage for runs whose inference would have worked fine. A model that is
known-absent is a different fact from one nobody could ask about, and the two
must not collapse into each other.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from .contracts import StrictModel
from .models import Task, bare_model_id, spec_for

#: How many available deployments a failure message lists. A resource can serve
#: hundreds; a wall of them turns a precise error into something an operator
#: scrolls past, which is the same as not printing it.
MAX_LISTED = 12


def _stem(deployment: str) -> str:
    """The family part of a deployment name, for grouping near misses.

    Two segments rather than one: ``claude`` alone would match every Anthropic
    model on the resource, and ``claude-opus`` is the granularity someone who
    mistyped a version actually wants to see.
    """
    parts = bare_model_id(deployment).replace("_", "-").split("-")
    return "-".join(parts[:2])


class PreflightReport(StrictModel):
    """What the provider says it serves, against what the run intends to use."""

    #: Deployments the provider reported. Empty means it could not tell us.
    available: list[str] = []
    #: Configured deployments the provider does not serve. Refusal-worthy.
    missing: list[str] = []
    #: Which task wanted each missing deployment, so the fix is obvious.
    wanted_by: dict[str, list[str]] = {}
    #: False when the provider could not answer. Not the same as "nothing is
    #: missing" — see the module docstring.
    checked: bool = True
    warnings: list[str] = []

    @property
    def ok(self) -> bool:
        """True when nothing is known to be missing.

        An unchecked run is ``ok``: it has not been shown to be broken, and
        that is the most the check can honestly claim.
        """
        return not self.missing

    def describe(self) -> list[str]:
        """The report as an operator reads it, most actionable first."""
        if not self.checked:
            return [
                "preflight: the provider could not list its deployments, so "
                "nothing was verified. The run is not known to be misconfigured "
                "— it is unchecked."
            ]
        if self.ok:
            return [
                f"preflight: every configured deployment is available "
                f"({len(self.available)} on the resource)."
            ]
        lines = ["preflight FAILED — these deployments are not on the resource:"]
        for deployment in self.missing:
            tasks = ", ".join(self.wanted_by.get(deployment, []))
            lines.append(f"  {deployment}  (wanted by: {tasks})")
        if not self.available:
            lines.append("available: (none reported)")
        else:
            near = self.near_misses()
            if near:
                lines.append("closest available:")
                lines += [f"  {name}" for name in near]
                remaining = len(self.available) - len(near)
                if remaining > 0:
                    lines.append(
                        f"  … and {remaining} more; `engagement preflight` with a "
                        "correct model lists the resource in full"
                    )
            else:
                shown = self.available[:MAX_LISTED]
                lines.append("available:")
                lines += [f"  {name}" for name in shown]
                if len(self.available) > len(shown):
                    lines.append(f"  … and {len(self.available) - len(shown)} more")
        lines.append(
            "Set the deployment names to ones the resource serves. This does not "
            "substitute a model for you: a swap changes the bill and the findings "
            "while every count still looks healthy."
        )
        return lines

    def near_misses(self) -> list[str]:
        """Available deployments that plausibly answer a missing one.

        A resource can serve hundreds of models, and printing all of them turns
        a precise error into a wall an operator scrolls past. Matching on the
        family stem is enough to surface the likely intent — someone who asked
        for ``claude-opus-9-turbo`` wants to see the Claude Opus deployments,
        not every Cohere and Mistral alias on the account.

        Never a suggestion, and deliberately not sorted by similarity: this is
        a filtered view of what exists, not a ranked recommendation.

        A missing name is excluded from its own alternatives. That reads as a
        contradiction otherwise — "this is not served, try these" with the
        refused name in the list — and it became reachable once a listed model
        could be refused by probe: `available` is the listing, so a name the
        resource does not serve is still in it.
        """
        stems = {_stem(name) for name in self.missing}
        stems.discard("")
        if not stems:
            return []
        refused = set(self.missing)
        return [
            name
            for name in self.available
            if name not in refused
            and any(_stem(name).startswith(stem) or stem.startswith(_stem(name))
                    for stem in stems)
        ][:MAX_LISTED]


def _matches(wanted: str, available: set[str], bare: set[str]) -> bool:
    """Whether a configured deployment corresponds to something served.

    Compared bare as well as exactly, because the same model is written
    differently by each platform: Bedrock prefixes ``anthropic.`` and a
    cross-region profile adds ``us.``. A run configured with the profile id
    against a foundation-model listing is correctly configured, and a
    comparison that only matched strings would call it missing.
    """
    if wanted in available:
        return True
    return bare_model_id(wanted) in bare


def check(
    deployments: Mapping[str, str],
    available: list[str],
    confirm: Callable[[str], bool | None] | None = None,
) -> PreflightReport:
    """Compare configured deployments against what a provider reported.

    Pure: the network calls belong to the provider, so this half is testable
    offline and the same function serves Foundry, Bedrock and the fake.

    ``confirm`` asks the provider about one deployment directly, and is what
    makes this check able to fail at all on a provider whose listing is a
    catalog rather than an inventory. Only names the listing *accepted* are
    confirmed — a name already known-missing needs no second opinion, and
    probing it would spend a call to re-learn what is already known.
    """
    named = {task: name.strip() for task, name in deployments.items() if name.strip()}
    if not available:
        return PreflightReport(
            checked=False,
            warnings=[
                "preflight: the provider reported no deployments, so the "
                "configured models were not verified. An empty answer means "
                "'could not tell', not 'serves nothing'"
            ],
        )

    served = set(available)
    bare = {bare_model_id(name) for name in available}
    wanted_by: dict[str, list[str]] = {}
    for task, name in named.items():
        if not _matches(name, served, bare):
            wanted_by.setdefault(name, []).append(task)

    refuted: list[str] = []
    if confirm is not None:
        # Each distinct name once, however many tasks want it: the answer is a
        # property of the deployment, and one probe per task would multiply the
        # cost of the check by the size of the routing table.
        for name in sorted({n for n in named.values() if n not in wanted_by}):
            if confirm(name) is False:
                refuted.append(name)
                for task, wanted in named.items():
                    if wanted == name:
                        wanted_by.setdefault(name, []).append(task)

    report = PreflightReport(
        available=sorted(served),
        missing=sorted(wanted_by),
        wanted_by={key: sorted(value) for key, value in wanted_by.items()},
        checked=True,
    )
    # An unpriced deployment still runs; it is the projection that cannot cost
    # it. Said here because preflight is the last point before spend where an
    # operator is looking at the model names — but only about deployments that
    # actually exist: "no published rate, the run will proceed" is a confusing
    # thing to say about a model the same report is refusing.
    unpriced = sorted(
        {
            name
            for name in named.values()
            if name not in wanted_by and spec_for(bare_model_id(name)) is None
        }
    )
    if unpriced:
        report.warnings.append(
            f"preflight: no published rate for {', '.join(unpriced)} — the run "
            "will proceed and `engagement plan` cannot project its cost"
        )
    if refuted:
        report.warnings.append(
            f"preflight: {', '.join(refuted)} appears in the provider's listing "
            "but the resource does not serve it. The listing is a catalog of "
            "what the region offers, not an inventory of what is deployed here"
        )
    return report


def deployments_for(
    model: str,
    router_model: str = "",
    expert_model: str = "",
    triage_model: str = "",
    analysis_model: str = "",
    chains_model: str = "",
    second_model: str = "",
) -> dict[str, str]:
    """Every deployment a run could reach, keyed by the task that reaches it.

    The *full* set rather than the ones a particular phase happens to use: a
    second detection pass that fails at dispatch has already cost the first
    pass, and finding out at the end is the failure preflight exists to move to
    the beginning.

    Chains resolves to ``chains_model`` first, then ``analysis_model``, then the
    shared model — so a run may spend a higher tier on the cross-finding
    reasoning while PoC drafting stays on the cheap ``analysis_model``.
    """
    resolved = {
        Task.router.value: router_model or model,
        Task.scenarios.value: expert_model or model,
        Task.triage.value: triage_model or model,
        Task.chains.value: chains_model or analysis_model or model,
        Task.poc.value: analysis_model or model,
    }
    if second_model.strip():
        resolved["scenarios (second pass)"] = second_model
    return {task: name for task, name in resolved.items() if name.strip()}
