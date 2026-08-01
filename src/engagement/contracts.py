"""Core data contracts.

Strict models: unknown fields are an error, so a workspace that changes shape
underneath the driver fails loudly at the boundary instead of silently losing a
field halfway through a run.

The vocabulary here is deliberately the workflow's, not the CLI's: the driver
reasons about phases, scenarios and dispositions, and never about command
strings. That is what lets the same driver run against a real workspace, a
fake one in the gate, or a future non-CLI implementation.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Phase(str, Enum):
    """The durable phases of a run, in the order they must happen.

    Derived from workspace state on every iteration rather than tracked in the
    driver: a run that is resumed, retried, or picked up by a different worker
    reads its position off the files, so there is no in-memory progress to lose.
    """

    initialize = "initialize"
    recon = "recon"
    router = "router"
    scenarios = "scenarios"
    triage = "triage"
    export = "export"
    complete = "complete"


#: Phases whose work is a model call. The rest are deterministic and free, which
#: is why the budget governor only ever gates these.
BILLABLE_PHASES: frozenset[Phase] = frozenset(
    {Phase.router, Phase.scenarios, Phase.triage}
)


class Priority(str, Enum):
    critical = "critical"
    high = "high"
    normal = "normal"
    low = "low"


#: Processing order when the budget cannot cover the whole backlog. Highest
#: value first; ties keep the workspace's own ordering, which is stable.
PRIORITY_RANK: dict[Priority, int] = {
    Priority.critical: 0,
    Priority.high: 1,
    Priority.normal: 2,
    Priority.low: 3,
}


class Disposition(str, Enum):
    """What happened to one unit of work.

    ``parked`` is the one that matters: a scenario nobody could conclude is not
    a scenario that passed, and it must survive into the report rather than
    being counted as clean.
    """

    completed = "completed"
    parked = "parked"
    unfunded = "unfunded"
    failed = "failed"


class RunRef(StrictModel):
    """Identifies one run of one target."""

    target: str
    run_id: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.target}/{self.run_id}"


class ScenarioRef(StrictModel):
    scenario_id: str
    expert: str
    priority: Priority = Priority.normal


class RenderedPrompt(StrictModel):
    """A prompt, and the digest the recorder will check an answer against.

    The digest travels with the text because only the workspace knows which
    *bytes* the recorder hashes. A driver that decoded the prompt and re-encoded
    it to hash would be computing the digest of a different byte sequence
    wherever line endings, encoding, or a BOM differ from what is on disk — and
    would be rejected for a mismatch it could not see.
    """

    text: str
    digest: str


class RunState(StrictModel):
    """The workspace's own answer to "where is this run?"."""

    phase: Phase
    scenarios_total: int = 0
    scenarios_pending: int = 0
    candidates_pending: int = 0


class ScenarioOutcome(StrictModel):
    """What the workspace recorded for one scenario.

    ``missing_context`` carries the model's own account of what it lacked,
    taken from the proof obligations it could not resolve. It is the only
    input to a context expansion that is worth anything: re-dispatching an
    unchanged prompt is superstition, but re-dispatching one that answers a
    stated need is new information.
    """

    status: str
    missing_context: list[str] = Field(default_factory=list)


class ParkedScenario(StrictModel):
    """A scenario that ended without a conclusion, durable enough to act on.

    Written to the run folder rather than only counted in memory: a parked
    scenario is unreviewed work, and unreviewed work that exists only in a
    process's stdout is indistinguishable from work that was never attempted
    once that process exits.
    """

    scenario_id: str
    expert: str
    priority: Priority = Priority.normal
    reason: str = "needs_context"
    #: The model's own statements about what it could not resolve.
    missing_context: list[str] = Field(default_factory=list)
    attempts: int = 1
    #: Whether a context expansion was dispatched, and what it carried.
    expanded: bool = False
    supplied_paths: list[str] = Field(default_factory=list)
    #: Paths the model asked for that could not be supplied — a bound, so it is
    #: reported rather than dropped. Includes anything refused by the path jail.
    unresolved_paths: list[str] = Field(default_factory=list)


class WorkOutcome(StrictModel):
    """One scenario or candidate, and what became of it."""

    item_id: str
    disposition: Disposition
    detail: str = ""


class ScoredFinding(StrictModel):
    """One ranked finding, in this package's own vocabulary.

    The triage backbone owns scoring and lives behind an optional extra, so its
    ``Finding`` type must not leak into the stages that read the queue. This is
    the projection those stages depend on: enough to reason about a finding, and
    nothing that ties the advisory layer to one backbone.
    """

    id: str
    repo: str
    title: str
    severity: str = "medium"
    risk_score: float = 0.0
    path: str = ""
    evidence: str = ""
    kev: bool = False
    epss: float | None = None
    component: str = ""
    ecosystem: str = ""
    version: str = ""
    #: Set by the lifecycle pass. ``unknown`` until something checks, which is
    #: deliberately distinct from ``supported`` — see :mod:`engagement.lifecycle`.
    lifecycle: str = "unknown"
    #: Points the lifecycle state added to ``risk_score``. Recorded rather than
    #: folded in, so the backbone's own score is always recoverable.
    lifecycle_adjust: float = 0.0

    @property
    def base_score(self) -> float:
        """The score before any lifecycle adjustment."""
        return self.risk_score - self.lifecycle_adjust


class Chain(StrictModel):
    """An ordered sequence of findings that combine into a worse outcome.

    Chains are **cross-finding**, so they are held beside the queue and reference
    findings by id rather than being stored on any one of them. The fingerprint
    hashes the *finding set*, which is stable across runs even though a chain's
    generated id is not — so an analyst decision about a chain survives a rescan
    that renumbers everything.
    """

    id: str
    title: str
    finding_ids: list[str] = Field(default_factory=list)
    narrative: str = ""
    impact: str = ""
    likelihood: float = 0.0
    score: float = 0.0

    @property
    def fingerprint(self) -> str:
        raw = "|".join(sorted(self.finding_ids))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class Poc(StrictModel):
    """A drafted proof of concept — what an operator *would* do, never what ran.

    Nothing in this package executes a step, and the rendered pack says so on
    its first line. ``preconditions`` is the field that carries the analyst
    value: whether the path is actually open is decided there, not by the fact
    that a weakness exists.
    """

    finding_id: str
    available: bool = False
    summary: str = ""
    preconditions: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    expected_evidence: str = ""

    @property
    def is_drafted(self) -> bool:
        return bool(self.steps or self.summary)


class RunReport(StrictModel):
    """The result of an unattended run.

    Counts are reported per disposition rather than as one total, because the
    only number that could mislead is a finding count without the denominator
    beside it: how much of the backlog was actually reached.
    """

    ref: RunRef
    phase: Phase
    scenarios: list[WorkOutcome] = Field(default_factory=list)
    candidates: list[WorkOutcome] = Field(default_factory=list)
    model_calls: int = 0
    warnings: list[str] = Field(default_factory=list)
    sarif_path: str | None = None
    #: Scenarios that ended without a conclusion, with why and what was tried.
    parked: list[ParkedScenario] = Field(default_factory=list)
    parked_path: str | None = None
    #: Credential-shaped values withheld from the model. A bound, so reported.
    redactions: int = 0

    def _count(self, items: list[WorkOutcome], disposition: Disposition) -> int:
        return sum(1 for item in items if item.disposition == disposition)

    @property
    def scenarios_completed(self) -> int:
        return self._count(self.scenarios, Disposition.completed)

    @property
    def scenarios_parked(self) -> int:
        return self._count(self.scenarios, Disposition.parked)

    @property
    def scenarios_unfunded(self) -> int:
        return self._count(self.scenarios, Disposition.unfunded)

    @property
    def reviewed_fraction(self) -> float:
        """Completed share of the backlog — the denominator for every count."""
        if not self.scenarios:
            return 1.0
        return self.scenarios_completed / len(self.scenarios)

    def is_complete(self) -> bool:
        """True only when nothing was left behind for any reason."""
        return not any(
            item.disposition != Disposition.completed
            for item in [*self.scenarios, *self.candidates]
        )
