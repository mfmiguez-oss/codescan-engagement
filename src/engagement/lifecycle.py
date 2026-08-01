"""Package lifecycle: deprecation, end of support, end of life.

A CVE-shaped pipeline has a blind spot, and it is a large one. Every stage
upstream of here keys on *known vulnerabilities* — a scanner reports what has
been published against a component, and the queue ranks it. A component that is
merely **unmaintained** has no CVE, produces no finding, and therefore reads as
clean. It is not clean. It is the one class of exposure that cannot be patched,
because nobody is left to publish the patch.

So lifecycle is treated as a first-class condition rather than a modifier:

- **A component past end of life is itself a finding**, minted here, with no CVE
  behind it. Nothing else in the pipeline would ever raise it.
- **A vulnerable component past end of life is worse than a vulnerable one**, so
  findings against it carry a recorded, reversible adjustment. The adjustment
  sits beside the backbone's score rather than overwriting it — a score you
  cannot take apart is a score an analyst has to take on faith.

Three states, deliberately distinguished, because they carry different
obligations and collapsing them loses the difference between "plan the upgrade"
and "you are on your own":

``deprecated``
    The maintainer has marked it superseded — an npm deprecation, a PyPI yank, a
    successor named in the docs. Fixes may still arrive. It is a migration
    signal, and the earliest one available.
``eos`` (end of support)
    Standard support has ended. Security fixes may still come through extended
    or paid support, and may not. It is a *contractual* state, not a technical
    one, which is exactly why it must not be reported as end of life.
``eol`` (end of life)
    No further updates of any kind, security included. The next vulnerability
    published against it will never be fixed in the version you are running.

The whole module is deterministic and offline — a date comparison against a
feed, never a model call. Lifecycle is a *fact* about a release calendar, and a
question with a checkable answer should never be handed to something that
guesses. It is the same reasoning that keeps KEV and EPSS on feeds.

**Unknown is never reported as supported.** A component the feed does not cover
is recorded as ``unknown`` and counted in the summary. The two mean opposite
things and rank identically if conflated, which is the same failure the missing
KEV feed already has a warning for.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path

from pydantic import Field

from .contracts import ScoredFinding, StrictModel


class LifecycleError(RuntimeError):
    """The lifecycle feed was unreadable or malformed."""


class LifecycleState(str, Enum):
    supported = "supported"
    deprecated = "deprecated"
    eos = "eos"
    eol = "eol"
    unknown = "unknown"


#: Ranked worst-first. ``unknown`` is deliberately *not* the least severe: it
#: outranks ``supported`` because an uncovered component is an open question,
#: and an open question must never sort below a settled good answer.
STATE_RANK: dict[LifecycleState, int] = {
    LifecycleState.eol: 0,
    LifecycleState.eos: 1,
    LifecycleState.deprecated: 2,
    LifecycleState.unknown: 3,
    LifecycleState.supported: 4,
}

#: Points added to a finding whose component is in this state. Bounded and small
#: on purpose: lifecycle changes the *fixability* of a finding, not its
#: exploitability, and a modifier that can outrank the evidence is a modifier
#: that hides it.
STATE_ADJUSTMENT: dict[LifecycleState, float] = {
    LifecycleState.eol: 15.0,
    LifecycleState.eos: 8.0,
    LifecycleState.deprecated: 5.0,
    LifecycleState.unknown: 0.0,
    LifecycleState.supported: 0.0,
}

#: Severity minted on a standalone lifecycle finding. An unmaintained dependency
#: is a real but non-acute exposure — high would crowd out exploited CVEs at the
#: top of a queue, and low would let it sink out of sight.
_FINDING_SEVERITY: dict[LifecycleState, str] = {
    LifecycleState.eol: "high",
    LifecycleState.eos: "medium",
    LifecycleState.deprecated: "medium",
}

_STANDALONE_SCORE: dict[LifecycleState, float] = {
    LifecycleState.eol: 55.0,
    LifecycleState.eos: 40.0,
    LifecycleState.deprecated: 30.0,
}


class Cycle(StrictModel):
    """One release line of a product, and the dates that end it."""

    cycle: str
    eos: date | None = None
    eol: date | None = None

    def state_on(self, as_of: date) -> LifecycleState:
        """The state this cycle is in, on a given day.

        End of life is checked first: a cycle past both dates is past end of
        life, and reporting it as merely unsupported would understate it.
        """
        if self.eol is not None and as_of >= self.eol:
            return LifecycleState.eol
        if self.eos is not None and as_of >= self.eos:
            return LifecycleState.eos
        return LifecycleState.supported


class PackageLifecycle(StrictModel):
    """What the feed knows about one package."""

    ecosystem: str = ""
    name: str
    deprecated: bool = False
    reason: str = ""
    replacement: str = ""
    cycles: list[Cycle] = Field(default_factory=list)
    source: str = ""

    @property
    def key(self) -> str:
        return _key(self.ecosystem, self.name)

    def cycle_for(self, version: str) -> Cycle | None:
        """The release line a version belongs to.

        Matched longest-cycle-first so ``4.2`` wins over ``4`` when both are
        published — a feed that lists both means the narrower line has its own
        calendar, and picking the broader one would report the wrong dates.
        """
        normalized = _normalize_version(version)
        if not normalized:
            return None
        candidates = [
            cycle
            for cycle in self.cycles
            if normalized == cycle.cycle or normalized.startswith(f"{cycle.cycle}.")
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda cycle: len(cycle.cycle))

    def assess(self, version: str, as_of: date) -> tuple[LifecycleState, Cycle | None]:
        """Worst applicable state for a version, with the cycle that decided it."""
        cycle = self.cycle_for(version)
        by_date = cycle.state_on(as_of) if cycle is not None else LifecycleState.unknown
        if self.deprecated and STATE_RANK[LifecycleState.deprecated] < STATE_RANK[by_date]:
            return LifecycleState.deprecated, cycle
        if by_date is LifecycleState.unknown and not self.deprecated:
            # the package is covered but this version is not: an uncovered
            # version is an open question, not a supported one
            return LifecycleState.unknown, None
        return by_date, cycle


class Assessment(StrictModel):
    """One component's lifecycle verdict, with what produced it."""

    component: str
    ecosystem: str = ""
    version: str = ""
    state: LifecycleState = LifecycleState.unknown
    cycle: str = ""
    eos_date: date | None = None
    eol_date: date | None = None
    reason: str = ""
    replacement: str = ""
    source: str = ""

    @property
    def is_adverse(self) -> bool:
        return self.state in _FINDING_SEVERITY

    @property
    def detail(self) -> str:
        """One line an analyst can act on, without opening the feed."""
        parts: list[str] = []
        if self.state is LifecycleState.eol:
            when = f" on {self.eol_date.isoformat()}" if self.eol_date else ""
            parts.append(
                f"Release line {self.cycle or self.version or '?'} reached end of life"
                f"{when}: it receives no further updates, security fixes included."
            )
        elif self.state is LifecycleState.eos:
            when = f" on {self.eos_date.isoformat()}" if self.eos_date else ""
            parts.append(
                f"Release line {self.cycle or self.version or '?'} reached end of "
                f"standard support{when}. Security fixes are not guaranteed and may "
                "require an extended-support agreement."
            )
        elif self.state is LifecycleState.deprecated:
            parts.append("The maintainer has marked this package deprecated.")
        if self.reason:
            parts.append(f"Stated reason: {self.reason}")
        if self.replacement:
            parts.append(f"Suggested replacement: {self.replacement}")
        if self.source:
            parts.append(f"Source: {self.source}")
        return " ".join(parts)


class LifecycleReport(StrictModel):
    """What the lifecycle pass found, and what it could not see."""

    assessments: list[Assessment] = Field(default_factory=list)
    #: Findings minted for adverse components — exposures with no CVE behind them.
    findings: list[ScoredFinding] = Field(default_factory=list)
    #: Components the feed did not cover. Reported, never assumed supported.
    unknown_components: list[str] = Field(default_factory=list)
    adjusted: int = 0
    feed_loaded: bool = False
    as_of: date | None = None
    warnings: list[str] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        tally = {state.value: 0 for state in LifecycleState}
        for assessment in self.assessments:
            tally[assessment.state.value] += 1
        return tally

    @property
    def adverse(self) -> list[Assessment]:
        return [item for item in self.assessments if item.is_adverse]


def _key(ecosystem: str, name: str) -> str:
    return f"{ecosystem.strip().lower()}:{name.strip().lower()}"


def _normalize_version(version: str) -> str:
    """Strip range operators and pre-release noise down to a dotted release."""
    text = version.strip().lstrip("^~>=<v ").strip()
    head = text.split("+")[0].split("-")[0]
    parts = [piece for piece in head.split(".") if piece.isdigit()]
    return ".".join(parts)


def _as_date(value: object, field: str, where: str) -> date | None:
    if value in (None, "", False):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise LifecycleError(f"{where}: {field}={value!r} is not an ISO date") from exc


def load_feed(path: Path) -> dict[str, PackageLifecycle]:
    """Read a lifecycle feed. A malformed entry is an error, never a skip.

    Silently dropping an unreadable row would mean a package with a real end-of-
    life date being reported as uncovered — the feed failing open, in the one
    direction that produces a falsely clean answer.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise LifecycleError(f"lifecycle feed unreadable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"lifecycle feed is not valid JSON: {exc}") from exc

    entries = raw.get("packages") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise LifecycleError("lifecycle feed has no 'packages' list")

    feed: dict[str, PackageLifecycle] = {}
    default_source = str(raw.get("source", "")) if isinstance(raw, dict) else ""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LifecycleError(f"packages[{index}] is not an object")
        name = str(entry.get("name", "")).strip()
        if not name:
            raise LifecycleError(f"packages[{index}] has no name")
        where = f"packages[{index}] ({name})"
        cycles: list[Cycle] = []
        for cycle_index, raw_cycle in enumerate(entry.get("cycles", []) or []):
            if not isinstance(raw_cycle, dict):
                raise LifecycleError(f"{where}: cycles[{cycle_index}] is not an object")
            cycles.append(
                Cycle(
                    cycle=str(raw_cycle.get("cycle", "")).strip(),
                    eos=_as_date(raw_cycle.get("eos"), "eos", where),
                    eol=_as_date(raw_cycle.get("eol"), "eol", where),
                )
            )
        package = PackageLifecycle(
            ecosystem=str(entry.get("ecosystem", "")).strip(),
            name=name,
            deprecated=bool(entry.get("deprecated", False)),
            reason=str(entry.get("reason", "")),
            replacement=str(entry.get("replacement", "")),
            cycles=cycles,
            source=str(entry.get("source", "")) or default_source,
        )
        feed[package.key] = package
    return feed


def _mint_id(ecosystem: str, name: str, version: str, state: LifecycleState) -> str:
    """A stable local identity for a lifecycle finding.

    Keyed on the component and the state rather than on the run, so the same
    unmaintained dependency is the same finding next week and an analyst's
    decision about it survives a rescan.
    """
    raw = f"lifecycle|{_key(ecosystem, name)}|{_normalize_version(version)}|{state.value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _component_of(finding: ScoredFinding) -> tuple[str, str, str] | None:
    if not finding.component:
        return None
    return finding.ecosystem, finding.component, finding.version


def assess(
    findings: list[ScoredFinding],
    feed: dict[str, PackageLifecycle] | None,
    repo: str = "",
    as_of: date | None = None,
    inventory: list[tuple[str, str, str]] | None = None,
) -> LifecycleReport:
    """Assess every component in the queue, and mint findings for adverse ones.

    ``inventory`` supplements the components carried on findings, because the
    blind spot this stage exists to close is precisely the package that produced
    *no* finding — a dependency list that only ever arrives through findings can
    never contain one.
    """
    today = as_of or datetime.now(UTC).date()
    report = LifecycleReport(feed_loaded=feed is not None, as_of=today)
    if feed is None:
        report.warnings.append(
            "lifecycle: no feed supplied — no component was checked for "
            "deprecation, end of support or end of life. An unmaintained "
            "dependency produces no CVE and would otherwise read as clean"
        )
        return report

    components: dict[str, tuple[str, str, str]] = {}
    for finding in findings:
        found = _component_of(finding)
        if found is not None:
            components[_key(found[0], found[1])] = found
    for entry in inventory or []:
        components.setdefault(_key(entry[0], entry[1]), entry)

    if not components:
        report.warnings.append(
            "lifecycle: no components were identified in this queue, so nothing "
            "was checked. A source-only review carries no dependency inventory — "
            "supply one to cover deprecation and end of life"
        )
        return report

    by_id = {finding.id: finding for finding in findings}
    for key, (ecosystem, name, version) in sorted(components.items()):
        package = feed.get(key) or feed.get(_key("", name))
        if package is None:
            report.unknown_components.append(f"{ecosystem or '?'}:{name}")
            report.assessments.append(
                Assessment(
                    component=name,
                    ecosystem=ecosystem,
                    version=version,
                    state=LifecycleState.unknown,
                )
            )
            continue

        state, cycle = package.assess(version, today)
        assessment = Assessment(
            component=name,
            ecosystem=ecosystem or package.ecosystem,
            version=version,
            state=state,
            cycle=cycle.cycle if cycle else "",
            eos_date=cycle.eos if cycle else None,
            eol_date=cycle.eol if cycle else None,
            reason=package.reason,
            replacement=package.replacement,
            source=package.source,
        )
        report.assessments.append(assessment)
        if state is LifecycleState.unknown:
            report.unknown_components.append(f"{ecosystem or '?'}:{name}")
        if assessment.is_adverse:
            report.findings.append(_mint_finding(assessment, repo))

    _apply(findings, report, by_id)
    _summarize(report)
    return report


def _mint_finding(assessment: Assessment, repo: str) -> ScoredFinding:
    """Raise the lifecycle condition as a finding in its own right."""
    label = {
        LifecycleState.eol: "End of life",
        LifecycleState.eos: "End of standard support",
        LifecycleState.deprecated: "Deprecated package",
    }[assessment.state]
    version = f" {assessment.version}" if assessment.version else ""
    return ScoredFinding(
        id=_mint_id(
            assessment.ecosystem, assessment.component, assessment.version, assessment.state
        ),
        repo=repo,
        title=f"{label}: {assessment.component}{version}",
        severity=_FINDING_SEVERITY[assessment.state],
        risk_score=_STANDALONE_SCORE[assessment.state],
        evidence=assessment.detail,
        component=assessment.component,
        ecosystem=assessment.ecosystem,
        version=assessment.version,
    )


def _apply(
    findings: list[ScoredFinding],
    report: LifecycleReport,
    by_id: dict[str, ScoredFinding],
) -> None:
    """Record the lifecycle state on each finding, and adjust adverse ones.

    The adjustment is added to ``risk_score`` and recorded in
    ``lifecycle_adjust`` at the same time, so the original score is always
    recoverable by subtraction — an adjustment that cannot be undone is an
    assertion, not an explanation.
    """
    states = {
        _key(item.ecosystem, item.component): item for item in report.assessments
    }
    for finding in findings:
        if not finding.component:
            continue
        assessment = states.get(_key(finding.ecosystem, finding.component))
        if assessment is None:
            continue
        finding.lifecycle = assessment.state.value
        delta = STATE_ADJUSTMENT[assessment.state]
        if delta:
            finding.lifecycle_adjust = delta
            finding.risk_score = min(100.0, finding.risk_score + delta)
            report.adjusted += 1
    _ = by_id


def _summarize(report: LifecycleReport) -> None:
    counts = report.counts()
    eol, eos, deprecated = counts["eol"], counts["eos"], counts["deprecated"]
    if eol:
        report.warnings.append(
            f"lifecycle: {eol} component(s) are past end of life — no security fix "
            "will be published for them, so the only remediation is replacement"
        )
    if eos:
        report.warnings.append(
            f"lifecycle: {eos} component(s) are past end of standard support; "
            "security fixes are not guaranteed without an extended-support agreement"
        )
    if deprecated:
        report.warnings.append(
            f"lifecycle: {deprecated} component(s) are deprecated by their maintainer"
        )
    if report.unknown_components:
        report.warnings.append(
            f"lifecycle: {len(report.unknown_components)} component(s) are not "
            "covered by the feed and are reported as unknown — unknown is not "
            f"supported ({', '.join(sorted(report.unknown_components)[:8])}"
            f"{', …' if len(report.unknown_components) > 8 else ''})"
        )
