"""The other half of the product: what happens to findings after a run.

An engagement proves vulnerabilities. It does not decide which of them matters
most across an estate — that needs exploit intelligence, an explainable score,
and a rank that survives comparison with findings from every other source.

That work used to live behind an optional extra resolving to a private git
reference. It now lives in :mod:`engagement.backbone`, ported into this package,
so scoring is available to every install rather than to whoever holds
credentials. The protocol and adapter shape stays: the driver-facing code
depends on :class:`TriagePipeline`, not on the backbone, so an estate that wants
a different scorer can supply one.

Two properties are preserved deliberately across the handoff:

- **A missing feed is reported, not silently zeroed.** Scoring without KEV or
  EPSS is legitimate — the severity proxy is a documented fallback — but a queue
  scored that way must say so, because "nothing is exploited" and "we did not
  look" produce the same ranking and mean opposite things.
- **The engagement's own dispositions travel with it.** A queue derived from a
  run that reviewed 40% of its backlog is a 40% queue, and the ingest summary
  carries that rather than leaving it behind in the run report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import Field

from .backbone import (
    EnrichmentError,
    Finding,
    dedup,
    enrich,
    load_epss,
    parse_sarif,
    rank,
    score_finding,
)
from .contracts import RunReport, ScoredFinding, StrictModel
from .feeds import FeedError
from .feeds import load_kev as load_kev_catalogue


class TriageError(RuntimeError):
    """The triage backbone refused the input."""


class TriageSummary(StrictModel):
    """What ingesting one run's findings produced."""

    findings: int = 0
    kev_findings: int = 0
    top_score: float | None = None
    csv_path: str | None = None
    enriched: bool = False
    warnings: list[str] = Field(default_factory=list)
    #: How many independent detection passes fed this queue, and how many
    #: findings more than one of them reported.
    passes: int = 1
    corroborated: int = 0
    #: The ranked queue, projected into this package's own contract. Carried so
    #: the advisory, lifecycle and export stages read one shape regardless of
    #: which pipeline produced it.
    queue: list[ScoredFinding] = Field(default_factory=list)


class TriagePipeline(Protocol):
    def ingest(
        self,
        sarif: Path,
        repo: str,
        out_dir: Path,
        feeds: Path | None = None,
        extra_sarif: dict[str, Path] | None = None,
    ) -> TriageSummary: ...


class BackbonePipeline:
    """The deterministic backbone: parse, dedup, enrich, score, rank.

    No model, no network. The CSV is written by :mod:`engagement.export`
    downstream rather than here — this stage produces the ranked queue, and the
    worklist is a rendering of it that also needs movement against the previous
    run, which this stage has no view of.
    """

    name = "backbone"

    def ingest(
        self,
        sarif: Path,
        repo: str,
        out_dir: Path,
        feeds: Path | None = None,
        extra_sarif: dict[str, Path] | None = None,
    ) -> TriageSummary:
        summary = TriageSummary()
        # Parse the SARIF file directly rather than sweeping a directory: a
        # directory sweep matching *.json passes over a .sarif file in silence,
        # which is the one outcome this pipeline must never produce.
        parsed: list[Finding] = []
        for label, path in {"pass-1": sarif, **(extra_sarif or {})}.items():
            report = parse_sarif(path, repo)
            for error in report.errors:
                summary.warnings.append(
                    f"ingest: {label} {error.source} {error.entry}: {error.message}"
                )
            # Tag every finding with the pass that produced it. `dedup` merges on
            # fingerprint and sets `corroboration = len(scanners)`, so two
            # independent passes that agree become one finding reported by two —
            # which is what makes the corroboration count mean something.
            for finding in report.findings:
                parsed.append(finding.model_copy(update={"scanners": [label]}))

        findings = dedup(parsed)
        summary.passes = 1 + len(extra_sarif or {})
        if summary.passes > 1:
            agreed = sum(1 for finding in findings if finding.corroboration > 1)
            summary.corroborated = agreed
            summary.warnings.append(
                f"detection: {summary.passes} independent passes found "
                f"{len(findings)} distinct finding(s); {agreed} were reported by "
                f"more than one pass and {len(findings) - agreed} by only one — "
                "a single-pass finding is not thereby false, only uncorroborated"
            )

        kev_path = (feeds / "kev.json") if feeds else None
        epss_path = (feeds / "epss.csv") if feeds else None
        if kev_path and epss_path:
            try:
                catalogue = load_kev_catalogue(kev_path)
                findings = enrich(findings, catalogue.ids, load_epss(epss_path))
                summary.enriched = True
                # Checked here rather than only at fetch time: this is the path
                # that actually scores against it, and an old catalogue scores
                # every CVE added since it was taken as un-exploited — silently,
                # because nothing about a stale file looks wrong.
                age = catalogue.age_days()
                if catalogue.is_stale():
                    summary.warnings.append(
                        f"enrichment: the KEV catalogue is {age} days old "
                        f"(released {catalogue.date_released[:10]}) — CVEs added "
                        "since then score as un-exploited. Run 'engagement fetch-kev'"
                    )
                elif age is None:
                    summary.warnings.append(
                        "enrichment: the KEV catalogue carries no release date, so "
                        "its age cannot be checked — it may be arbitrarily stale"
                    )
            except (EnrichmentError, FeedError) as exc:
                summary.warnings.append(
                    f"enrichment: {exc} — scores fall back to the severity proxy, "
                    "so ranking here reflects declared severity, not known exploitation"
                )
        else:
            summary.warnings.append(
                "enrichment: no KEV/EPSS feeds supplied — scores fall back to the "
                "severity proxy. An unexploited finding and an unchecked one rank "
                "the same, which is not the same claim"
            )

        scored = rank([score_finding(finding) for finding in findings])
        out_dir.mkdir(parents=True, exist_ok=True)

        summary.findings = len(scored)
        summary.kev_findings = sum(1 for finding in scored if finding.kev)
        summary.top_score = scored[0].risk_score if scored else None
        summary.queue = [project(finding) for finding in scored]
        return summary


def project(finding: Finding) -> ScoredFinding:
    """Narrow a backbone ``Finding`` onto the contract every later stage reads.

    The backbone carries scoring machinery — breakdowns, adjustments, raw
    detection counts — that the advisory and export stages have no business
    depending on. Narrowing here keeps that surface from leaking into five other
    modules.
    """
    location = finding.location
    component = finding.component
    return ScoredFinding(
        id=finding.fingerprint,
        repo=finding.repo,
        title=finding.title,
        severity=finding.severity.value,
        risk_score=finding.risk_score or 0.0,
        path=location.path if location else "",
        evidence=finding.evidence,
        kev=finding.kev,
        epss=finding.epss,
        component=component.name if component else "",
        ecosystem=(component.ecosystem or "") if component else "",
        version=(component.version or "") if component else "",
        detected_by=list(finding.scanners),
    )


def ingest_run(
    report: RunReport,
    repo: str,
    out_dir: Path,
    feeds: Path | None = None,
    pipeline: TriagePipeline | None = None,
    extra_sarif: dict[str, Path] | None = None,
) -> TriageSummary:
    """Score and rank the findings a run produced.

    The run's own coverage travels into the summary: a queue built from a
    partially reviewed backlog is a partial queue, and saying so here is the
    difference between a ranked list and a ranked list that can be trusted as
    complete.
    """
    if not report.sarif_path:
        raise TriageError("the run produced no SARIF export to ingest")

    summary = (pipeline or BackbonePipeline()).ingest(
        Path(report.sarif_path), repo, out_dir, feeds, extra_sarif
    )
    if not report.is_complete():
        summary.warnings.append(
            f"coverage: this queue comes from a run that reviewed "
            f"{report.reviewed_fraction:.0%} of its backlog "
            f"({report.scenarios_parked} parked, {report.scenarios_unfunded} "
            "unfunded) — it ranks what was reviewed, not what exists"
        )
    return summary
