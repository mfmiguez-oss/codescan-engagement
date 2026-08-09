"""Which model does which task, and what that costs.

An unattended run makes every model choice on its own, so the choice has to be
written down somewhere a human can audit before the bill arrives. This module is
that place: one table mapping each task to a capability tier, one table of what
each tier costs, and a projection the CLI prints *before* dispatch.

The allocation follows one rule — **spend on judgement, economise on volume** —
because the two are anti-correlated across this pipeline:

``router``
    One call per run, and it decides the entire backlog. A router that misses a
    routing unit loses every finding that unit would have produced, and no later
    stage can recover it. Highest tier; the cost is one call.
``scenarios``
    One call per scenario — the bulk of the spend *and* the stage that actually
    finds vulnerabilities. Highest tier, because a cheaper model here does not
    produce a cheaper run, it produces a run that finds less and costs the same
    to review.
``triage``
    One call per candidate, adjudicating a claim against evidence already
    gathered. Bounded, mechanical, and checkable — the workspace validates every
    citation against the checkout regardless. Mid tier.
``chains``
    One call per service. Cross-finding reasoning over a small prompt: rare,
    cheap, and hard. High tier.
``poc``
    Batched drafting from findings that are already established. The hard part
    was the finding; this is writing it up. Lowest tier.

Two things this deliberately does not do. It does not pick a model when none is
configured — an unattended run that guesses a deployment guesses a bill. And it
does not silently downgrade: if the configured deployment for a task is unknown
to the cost table, the projection says so rather than quietly assuming a rate.

**Sampling parameters are a per-family fact, not a global setting.** Recent
Anthropic models (Opus 4.7 and later, Opus 5, Sonnet 5, Fable 5) removed
``temperature``/``top_p``/``top_k`` entirely and reject them with a 400 — so the
determinism lever that works on one deployment is a hard failure on another.
:data:`SAMPLING_SUPPORT` records which families accept them, and
:func:`sampling_for` returns what may actually be sent.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum

from pydantic import Field

from .contracts import StrictModel


class Tier(str, Enum):
    """Capability tier a task needs, independent of any vendor's naming."""

    frontier = "frontier"  # hardest judgement; few calls
    high = "high"
    mid = "mid"
    economy = "economy"  # mechanical, high volume


class Task(str, Enum):
    """Every stage that spends money."""

    router = "router"
    scenarios = "scenarios"
    triage = "triage"
    chains = "chains"
    poc = "poc"


class TaskProfile(StrictModel):
    """Why a task sits where it does — the audit trail for the allocation."""

    task: Task
    tier: Tier
    #: How the call count grows. Recorded because tier alone does not say
    #: whether a choice is cheap: one frontier call is cheaper than a hundred
    #: economy ones.
    volume: str
    rationale: str
    #: What one call of this task actually costs in tokens.
    #:
    #: Per task, not one average across the pipeline. The projection used a
    #: single 6000-in/1200-out pair for every stage, which is close enough for
    #: a scenario (measured 6129/2105) and wrong by 7x for a router chunk
    #: (measured 980 fresh input, 65146 read from cache, 8807 out) — the router
    #: re-reads the whole recon on every chunk and answers with a document.
    #: A run projected at $3.90 billed about $18.
    #:
    #: Cache tokens are carried separately because they are billed separately:
    #: a read is a tenth of fresh input and a write is a quarter more. Folding
    #: 65k cached tokens in at the fresh rate would replace one wrong number
    #: with another.
    avg_input_tokens: int = 6000
    avg_output_tokens: int = 1200
    avg_cache_read_tokens: int = 0
    avg_cache_write_tokens: int = 0


#: The allocation. Ordered by the pipeline's own sequence.
PROFILES: dict[Task, TaskProfile] = {
    Task.router: TaskProfile(
        task=Task.router,
        tier=Tier.frontier,
        volume="1 per chunk of the backlog",
        rationale=(
            "Decides the whole backlog. A missed routing unit loses every finding "
            "it would have produced, and no later stage can recover it, so the "
            "strongest model is the cheapest insurance in the pipeline. It is no "
            "longer one call: the backlog is split into chunks of a dozen "
            "obligations, and a live pygoat run took 25."
        ),
        # measured, pygoat run-001 2026-08-09: 25 calls, 980 fresh input and
        # 65146 cache-read per call, 8807 out. The fresh input is small and the
        # cached recon is enormous, which is the opposite shape to every other
        # stage — projecting this one from a pipeline-wide average cannot work.
        avg_input_tokens=1000,
        avg_output_tokens=8800,
        avg_cache_read_tokens=65000,
        avg_cache_write_tokens=8900,
    ),
    Task.scenarios: TaskProfile(
        task=Task.scenarios,
        tier=Tier.frontier,
        volume="1 per scenario (the bulk of the run)",
        rationale=(
            "The stage that actually finds vulnerabilities. Economising here does "
            "not produce a cheaper run — it produces a run that finds less and "
            "costs the same to review."
        ),
        # measured, same run: 250 calls, 6129 in / 2105 out per call
        avg_input_tokens=6100,
        avg_output_tokens=2100,
        avg_cache_read_tokens=1600,
        avg_cache_write_tokens=530,
    ),
    Task.triage: TaskProfile(
        task=Task.triage,
        tier=Tier.mid,
        volume="1 per candidate",
        rationale=(
            "Adjudicates a claim against evidence already gathered, and the "
            "workspace re-validates every citation against the checkout whatever "
            "the model says. Bounded and checkable, so a mid tier holds."
        ),
        # not yet measured: the one live run that reached candidates spent its
        # budget before triage dispatched. Sized as a scenario answer without
        # the source window, and marked here so the guess is not mistaken for a
        # measurement when someone reconciles a bill against this table.
        avg_input_tokens=4000,
        avg_output_tokens=1500,
    ),
    Task.chains: TaskProfile(
        task=Task.chains,
        tier=Tier.high,
        volume="1 per service",
        rationale=(
            "Cross-finding reasoning over a short prompt: rare, cheap per call, "
            "and genuinely hard. High tier costs almost nothing at this volume."
        ),
    ),
    Task.poc: TaskProfile(
        task=Task.poc,
        tier=Tier.economy,
        volume="1 per 10 critical findings, cap 40",
        rationale=(
            "Drafting a procedure for a finding that is already established. The "
            "hard part was finding it; this is writing it up, and it is advisory "
            "output that a human reviews before acting on. Only findings that come "
            "out critical are drafted automatically, so the volume tracks the "
            "top of the queue rather than the size of it."
        ),
    ),
}


class ModelSpec(StrictModel):
    """What a deployment costs and what it will accept.

    Rates are US dollars per million tokens, as published for the Anthropic API
    — which is also what Microsoft Foundry bills at, through the Marketplace.
    Amazon Bedrock is partner-operated and priced separately, so a Bedrock run
    projects with these rates only as an approximation, and says so.
    """

    #: Deployment or model id as it is written in configuration.
    id: str
    family: str
    tier: Tier
    input_per_mtok: float
    output_per_mtok: float
    #: False when the API rejects temperature/top_p/top_k outright.
    accepts_sampling: bool = True
    note: str = ""

    @property
    def cache_read_per_mtok(self) -> float:
        """A cache read is a tenth of fresh input, across the whole family.

        Derived rather than tabulated: it is a published *ratio*, so writing it
        out per model invites eight numbers to drift apart when one of them is
        updated. The router reads 65k cached tokens per chunk, so a projection
        that ignored this was quietly ten percent light on every run.
        """
        return self.input_per_mtok * 0.1

    @property
    def cache_write_per_mtok(self) -> float:
        """Writing a cache entry costs a quarter more than fresh input."""
        return self.input_per_mtok * 1.25


#: Published rates, current as of 2026-08-01. A deployment absent from this
#: table still runs — the projection reports it as unpriced rather than
#: inventing a number, because a fabricated cost estimate is worse than none.
CATALOGUE: dict[str, ModelSpec] = {
    spec.id: spec
    for spec in (
        ModelSpec(
            id="claude-fable-5",
            family="claude",
            tier=Tier.frontier,
            input_per_mtok=10.0,
            output_per_mtok=50.0,
            accepts_sampling=False,
            note="thinking always on; sampling parameters removed (400 if sent)",
        ),
        ModelSpec(
            id="claude-opus-5",
            family="claude",
            tier=Tier.frontier,
            input_per_mtok=5.0,
            output_per_mtok=25.0,
            accepts_sampling=False,
            note="sampling parameters removed (400 if sent)",
        ),
        ModelSpec(
            id="claude-opus-4-8",
            family="claude",
            tier=Tier.frontier,
            input_per_mtok=5.0,
            output_per_mtok=25.0,
            accepts_sampling=False,
        ),
        ModelSpec(
            id="claude-opus-4-7",
            family="claude",
            tier=Tier.high,
            input_per_mtok=5.0,
            output_per_mtok=25.0,
            accepts_sampling=False,
        ),
        ModelSpec(
            id="claude-sonnet-5",
            family="claude",
            tier=Tier.high,
            input_per_mtok=3.0,
            output_per_mtok=15.0,
            accepts_sampling=False,
            note="non-default sampling values rejected",
        ),
        ModelSpec(
            id="claude-sonnet-4-6",
            family="claude",
            tier=Tier.high,
            input_per_mtok=3.0,
            output_per_mtok=15.0,
        ),
        ModelSpec(
            id="claude-haiku-4-5",
            family="claude",
            tier=Tier.economy,
            input_per_mtok=1.0,
            output_per_mtok=5.0,
            note="accepts sampling parameters; 200K context",
        ),
    )
}


#: Families whose recent generations reject sampling parameters outright.
#: Matched as a prefix against the deployment id, lowercased.
_SAMPLING_REMOVED: tuple[str, ...] = (
    "claude-fable",
    "claude-mythos",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-sonnet-5",
)

#: Families that accept a seed for reproducible sampling.
_SEED_SUPPORTED: tuple[str, ...] = ("gpt-", "o3", "o4")

#: Families that accept ``output_config.effort``. An allowlist rather than a
#: deny-list, because sending it where it is unsupported **fails the whole
#: call** — Haiku 4.5 and Sonnet 4.5 reject it outright — while omitting it only
#: forgoes a saving. Effort is the cheapest lever on both spend and wall clock,
#: since it shortens the answer and answer length is what both are made of,
#: which is exactly why it must not be sent blind.
_EFFORT_SUPPORTED: tuple[str, ...] = (
    "claude-fable",
    "claude-mythos",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-opus-4-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
)

#: Levels the API defines. ``xhigh`` and ``max`` arrived after Opus 4.5, which
#: takes only the first three — but a rejected level is a 400 an operator can
#: read, unlike a silently dropped one, so the level is passed through as given.
EFFORT_LEVELS: frozenset[str] = frozenset({"low", "medium", "high", "xhigh", "max"})


def accepts_effort(deployment: str) -> bool:
    """Whether this deployment will accept an effort level at all."""
    lowered = bare_model_id(deployment)
    return any(lowered.startswith(prefix) for prefix in _EFFORT_SUPPORTED)


def effort_for(deployment: str, effort: str) -> dict[str, object]:
    """The ``output_config`` this deployment will accept, if any.

    Empty when no effort was asked for, or when the family rejects the
    parameter. The caller sends exactly what comes back, so a family gaining or
    losing support is one edit here rather than a change at every dispatch site
    — the same contract as :func:`sampling_for`.
    """
    level = effort.strip().lower()
    if not level or not accepts_effort(deployment):
        return {}
    return {"output_config": {"effort": level}}


def spec_for(deployment: str) -> ModelSpec | None:
    """The catalogue entry for a deployment, if it has one."""
    return CATALOGUE.get(deployment.strip())


#: Vendor and geo prefixes a platform prepends to a model id. Bedrock writes
#: ``anthropic.claude-opus-5`` and cross-region profiles add ``us.``/``eu.``, so
#: a match against the bare family name never fires unless these come off first.
#: This was a live defect: the Bedrock path sent temperature to a model that
#: rejects it, which is a 400 on the whole call rather than a degraded answer.
_ID_PREFIXES: tuple[str, ...] = ("us.", "eu.", "apac.", "anthropic.")


def bare_model_id(deployment: str) -> str:
    """Strip platform routing prefixes down to the family-bearing id."""
    lowered = deployment.strip().lower()
    changed = True
    while changed:
        changed = False
        for prefix in _ID_PREFIXES:
            if lowered.startswith(prefix):
                lowered = lowered[len(prefix) :]
                changed = True
    return lowered


def accepts_sampling(deployment: str) -> bool:
    """Whether this deployment will accept temperature/top_p at all.

    Prefix-matched rather than table-only, because a deployment alias is chosen
    by whoever configured the resource and will not always match a catalogue id.
    Defaulting to *not* sending on a recognised family is the safe direction: a
    missing temperature costs a little determinism, while sending one to a model
    that removed it fails the whole call.
    """
    lowered = bare_model_id(deployment)
    if any(lowered.startswith(prefix) for prefix in _SAMPLING_REMOVED):
        return False
    spec = spec_for(lowered) or spec_for(deployment)
    return spec.accepts_sampling if spec else True


def accepts_seed(deployment: str) -> bool:
    """Whether a seed may be sent — an OpenAI-surface parameter only."""
    lowered = bare_model_id(deployment)
    return any(prefix in lowered for prefix in _SEED_SUPPORTED)


def sampling_for(deployment: str, temperature: float, seed: int | None) -> dict[str, object]:
    """The determinism parameters this deployment will actually accept.

    Returns an empty mapping for families that removed them. The caller sends
    exactly what comes back, so a family that gained or lost support is one edit
    here rather than a change at every dispatch site.
    """
    if not accepts_sampling(deployment):
        return {}
    params: dict[str, object] = {"temperature": temperature}
    if seed is not None and accepts_seed(deployment):
        params["seed"] = seed
    return params


#: Vendor per family prefix, for the two-pass rule below. Deliberately coarse:
#: the question is only "would these two models fail the same way?", and models
#: from one vendor share training data, tokenizer lineage and refusal behaviour.
_VENDORS: tuple[tuple[str, str], ...] = (
    ("claude", "anthropic"),
    ("gpt-", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("codex", "openai"),
    ("mistral", "mistral"),
    ("codestral", "mistral"),
    ("llama", "meta"),
    ("cohere", "cohere"),
    ("command", "cohere"),
    ("titan", "amazon"),
    ("nova", "amazon"),
    ("gemini", "google"),
    ("grok", "xai"),
    ("phi", "microsoft"),
    ("deepseek", "deepseek"),
)


def vendor_of(deployment: str) -> str:
    """Which vendor trained this model, as far as the id reveals.

    ``unknown`` when the id says nothing — treated as its own vendor, so two
    unrecognised aliases are never *assumed* to be independent.
    """
    lowered = bare_model_id(deployment)
    for prefix, vendor in _VENDORS:
        if lowered.startswith(prefix) or f".{prefix}" in lowered:
            return vendor
    return "unknown"


class SingleVendorError(RuntimeError):
    """Two detection passes were configured on one vendor's models."""


def check_two_vendor_passes(deployments: list[str], allow_single: bool = False) -> list[str]:
    """Refuse a second pass that cannot disagree with the first.

    The value of a second pass is *independence*. Two models from one vendor
    share training data, tokenizer lineage and refusal behaviour, so they miss
    the same things in the same places — and a second pass that agrees for
    structural reasons produces a corroboration count that reads like evidence
    and is not. The whole point of the count is that it means something.

    Returns the warnings a caller should report. Raises when the configuration
    would produce false corroboration and ``allow_single`` was not set.
    """
    named = [d.strip() for d in deployments if d.strip()]
    if len(named) < 2:
        return []

    vendors = [vendor_of(d) for d in named]
    warnings: list[str] = []
    if "unknown" in vendors:
        unrecognised = [d for d, v in zip(named, vendors, strict=True) if v == "unknown"]
        warnings.append(
            f"detection: vendor could not be determined for {', '.join(unrecognised)}; "
            "independence between passes is assumed, not verified"
        )
    if len(set(vendors)) > 1:
        return warnings

    message = (
        f"both detection passes use {vendors[0]} models ({', '.join(named)}). "
        "Two models from one vendor share training data and refusal behaviour, so "
        "they miss the same things — the corroboration count would read as "
        "evidence without being any. Use models from different vendors, or set "
        "ENGAGEMENT_ALLOW_SINGLE_VENDOR=1 to accept a weaker second pass."
    )
    if not allow_single:
        raise SingleVendorError(message)
    warnings.append(f"detection: {message}")
    return warnings


class Allocation(StrictModel):
    """One task, the deployment it will use, and what that will cost."""

    task: Task
    tier: Tier
    deployment: str
    projected_calls: int = 0
    input_per_mtok: float | None = None
    output_per_mtok: float | None = None
    priced: bool = False
    #: What one call of this task costs in tokens, carried from its profile so
    #: the renderer does not have to reach back for it.
    per_call_input: int = 0
    per_call_output: int = 0
    per_call_cache_read: int = 0
    per_call_cache_write: int = 0

    def projected_cost(self) -> float | None:
        """Dollars for this task's whole projected spend, or ``None`` unpriced.

        Takes no token arguments any more. It used to, and every caller passed
        the same flat pipeline-wide average — which meant the one place that
        knew a router chunk is nothing like a scenario answer had no way to say
        so. The per-call shape now travels on the allocation itself.
        """
        if not self.priced or self.input_per_mtok is None or self.output_per_mtok is None:
            return None
        calls = self.projected_calls
        read_rate = self.input_per_mtok * 0.1
        write_rate = self.input_per_mtok * 1.25
        return (
            calls * self.per_call_input / 1_000_000 * self.input_per_mtok
            + calls * self.per_call_output / 1_000_000 * self.output_per_mtok
            + calls * self.per_call_cache_read / 1_000_000 * read_rate
            + calls * self.per_call_cache_write / 1_000_000 * write_rate
        )


class Plan(StrictModel):
    """The whole run's model allocation, printable before a call is made."""

    allocations: list[Allocation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def unpriced(self) -> list[str]:
        return sorted({a.deployment for a in self.allocations if not a.priced})


def build_plan(
    deployments: Mapping[str, str],
    scenarios: int = 0,
    candidates: int = 0,
    services: int = 1,
    findings: int = 0,
    poc_batch: int = 10,
    max_poc: int = 40,
    critical_findings: int | None = None,
    obligations: int = 0,
    router_chunk_obligations: int = 12,
) -> Plan:
    """Project each task's model and call count before anything is dispatched.

    The call-count model mirrors the stages exactly: one router call *per chunk
    of the backlog*, one per scenario, one per candidate, one per service for
    chains, and one per batch of PoC drafts up to the cap. Getting this wrong in
    the optimistic direction would be the worst kind of error — a budget that
    looks affordable until the run is already halfway through it.

    The router used to be projected at one call flat. That was true when it made
    one, and stopped being true when the backlog started being chunked: a live
    pygoat run took 25, each answering with about 8800 tokens. Pass
    ``obligations`` — the count recon produced — and the projection is
    ``ceil(obligations / chunk size)``. It is a *floor*, because a chunk whose
    answer truncates is split and re-asked, which adds calls.

    ``obligations`` is unknown before recon, and the honest answer then is not
    "1". It is a warning that this line is the one number in the table that
    cannot be projected yet.

    Drafting is critical-only, so ``critical_findings`` is what drives the PoC
    count. Left unset it falls back to the whole queue, which over-projects: a
    projection that is too high costs an operator a raised eyebrow, and one that
    is too low costs them a run that stops halfway.
    """
    plan = Plan()
    drafted = findings if critical_findings is None else max(0, critical_findings)
    running = bool(scenarios or candidates)
    chunk_size = max(1, router_chunk_obligations)
    if obligations > 0:
        router_calls = -(-obligations // chunk_size)
    else:
        router_calls = 1 if running else 0
    counts = {
        Task.router: router_calls,
        Task.scenarios: max(0, scenarios),
        Task.triage: max(0, candidates),
        Task.chains: max(0, services),
        Task.poc: -(-min(max(0, drafted), max_poc) // poc_batch) if drafted else 0,
    }
    if running and obligations <= 0:
        plan.warnings.append(
            "router: shown at 1 call because the obligation count is not known "
            "until recon has run. The router takes one call per "
            f"{chunk_size} obligations — a live pygoat run took 25 — so the "
            "router line and the total below are floors, not estimates. Re-run "
            "plan with --obligations after recon for a real number"
        )
    elif obligations > 0:
        plan.warnings.append(
            f"router: {router_calls} call(s) is a floor for {obligations} "
            f"obligation(s) at {chunk_size} per chunk. Even division is the best "
            "case: a path too heavy for one chunk is cut into disjoint slices "
            "that cannot be packed with each other, and a chunk whose answer "
            "truncates is split and re-asked. A live pygoat run turned 166 "
            f"obligations into 23 chunks against this formula's 14, so size for "
            f"roughly {int(router_calls * 1.6)}. How far it runs over depends on "
            "how unevenly the obligations sit, which recon knows and this does not"
        )

    for task, profile in PROFILES.items():
        deployment = (deployments.get(task.value) or "").strip()
        if not deployment:
            plan.warnings.append(
                f"model: no deployment set for {task.value}; that stage will not run"
            )
            continue
        spec = spec_for(deployment)
        allocation = Allocation(
            task=task,
            tier=profile.tier,
            deployment=deployment,
            projected_calls=counts[task],
            priced=spec is not None,
            input_per_mtok=spec.input_per_mtok if spec else None,
            output_per_mtok=spec.output_per_mtok if spec else None,
            per_call_input=profile.avg_input_tokens,
            per_call_output=profile.avg_output_tokens,
            per_call_cache_read=profile.avg_cache_read_tokens,
            per_call_cache_write=profile.avg_cache_write_tokens,
        )
        plan.allocations.append(allocation)
        if spec is not None and spec.tier is not profile.tier:
            plan.warnings.append(
                f"model: {task.value} wants the {profile.tier.value} tier but "
                f"{deployment} is {spec.tier.value} — {profile.rationale.split('.')[0]}."
            )

    if plan.unpriced():
        plan.warnings.append(
            "cost: no published rate for "
            f"{', '.join(plan.unpriced())} — the projection below omits them "
            "rather than guessing a rate"
        )
    return plan


def render_plan(plan: Plan) -> str:
    """The plan as a table an operator reads before authorising the run.

    No token arguments. They were two pipeline-wide averages applied to every
    stage, so the caller could not have supplied a right answer even knowing
    one: a router chunk and a scenario answer differ by 7x in output and 65x in
    cached input. Each allocation now carries its own measured shape.
    """
    lines = [
        f"{'task':<11}{'tier':<10}{'deployment':<24}{'calls':>7}{'est. $':>10}",
        "-" * 62,
    ]
    total = 0.0
    any_priced = False
    for allocation in plan.allocations:
        cost = allocation.projected_cost()
        if cost is not None:
            total += cost
            any_priced = True
        rendered = f"{cost:>10.2f}" if cost is not None else f"{'unpriced':>10}"
        lines.append(
            f"{allocation.task.value:<11}{allocation.tier.value:<10}"
            f"{allocation.deployment[:23]:<24}{allocation.projected_calls:>7}{rendered}"
        )
    if any_priced:
        lines.append("-" * 62)
        lines.append(f"{'projected':<52}{total:>10.2f}")
    return "\n".join(lines)
