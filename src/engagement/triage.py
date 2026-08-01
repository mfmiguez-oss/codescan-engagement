"""The other half of the product: what happens to findings after a run.

An engagement proves vulnerabilities. It does not decide which of them matters
most across an estate — that needs exploit intelligence, an explainable score,
and a rank that survives comparison with findings from every other source. That
work already exists in the codescan triage backbone, so this module is a port
onto it rather than a second implementation of it.

The same shape as :mod:`engagement.workspace`: a protocol the driver-facing code
depends on, an adapter that delegates to the real pipeline, and lazy imports so
the base package installs without it.

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

from .contracts import RunReport, ScoredFinding, StrictModel


class TriageError(RuntimeError):
    """The triage backbone was unavailable or refused the input."""


class TriageSummary(StrictModel):
    """What ingesting one run's findings produced."""

    findings: int = 0
    kev_findings: int = 0
    top_score: float | None = None
    csv_path: str | None = None
    enriched: bool = False
    warnings: list[str] = Field(default_factory=list)
    #: The ranked queue, projected into this package's own contract. Carried so
    #: the advisory and lifecycle stages can read it without importing the
    #: backbone; defaulted empty so an alternative pipeline stays valid without
    #: supplying one.
    queue: list[ScoredFinding] = Field(default_factory=list)


class TriagePipeline(Protocol):
    def ingest(
        self, sarif: Path, repo: str, out_dir: Path, feeds: Path | None = None
    ) -> TriageSummary: ...


class TriagekitPipeline:
    """Adapter onto `triagekit`'s deterministic backbone.

    Imported lazily and by name, so this package installs and its gate runs
    without the triage extra present. The backbone is deterministic — dedup,
    enrichment, weighted score, KEV floor, rank — so nothing here needs a model
    or a network.
    """

    name = "triagekit"

    def ingest(
        self, sarif: Path, repo: str, out_dir: Path, feeds: Path | None = None
    ) -> TriageSummary:
        try:
            from triagekit.dedup import dedup
            from triagekit.enrich import EnrichmentError, enrich, load_epss, load_kev
            from triagekit.export import write_csv
            from triagekit.ingest import parse_sarif
            from triagekit.scoring import rank, score_finding
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise TriageError(
                "the triage backbone is not installed; install the 'triage' "
                "extra to score and rank engagement findings"
            ) from exc

        summary = TriageSummary()
        # parse the SARIF file directly rather than sweeping a directory: the
        # directory sweep matches *.json only, so a .sarif file would be passed
        # over in silence — the one outcome this pipeline must never produce
        report = parse_sarif(sarif, repo)
        for error in report.errors:
            summary.warnings.append(f"ingest: {error.source} {error.entry}: {error.message}")

        findings = dedup(report.findings)

        kev_path = (feeds / "kev.json") if feeds else None
        epss_path = (feeds / "epss.csv") if feeds else None
        if kev_path and epss_path:
            try:
                findings = enrich(findings, load_kev(kev_path), load_epss(epss_path))
                summary.enriched = True
            except EnrichmentError as exc:
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
        csv_path = out_dir / "queue.csv"
        write_csv(scored, csv_path)

        summary.findings = len(scored)
        summary.kev_findings = sum(1 for finding in scored if finding.kev)
        summary.top_score = scored[0].risk_score if scored else None
        summary.csv_path = str(csv_path)
        summary.queue = [_project(finding) for finding in scored]
        return summary


def _project(finding: object) -> ScoredFinding:
    """Narrow a backbone ``Finding`` onto this package's own contract.

    By attribute rather than by import: the backbone type is behind an optional
    extra, and a projection that needed it present at type-check time would drag
    the whole dependency into a module that must import without it.
    """
    location = getattr(finding, "location", None)
    component = getattr(finding, "component", None)
    severity = getattr(finding, "severity", None)
    return ScoredFinding(
        id=str(getattr(finding, "fingerprint", "")),
        repo=str(getattr(finding, "repo", "")),
        title=str(getattr(finding, "title", "")),
        severity=str(getattr(severity, "value", severity or "medium")),
        risk_score=float(getattr(finding, "risk_score", 0.0) or 0.0),
        path=str(getattr(location, "path", "") or "") if location else "",
        evidence=str(getattr(finding, "evidence", "") or ""),
        kev=bool(getattr(finding, "kev", False)),
        epss=getattr(finding, "epss", None),
        component=str(getattr(component, "name", "") or "") if component else "",
        ecosystem=str(getattr(component, "ecosystem", "") or "") if component else "",
        version=str(getattr(component, "version", "") or "") if component else "",
    )


def ingest_run(
    report: RunReport,
    repo: str,
    out_dir: Path,
    feeds: Path | None = None,
    pipeline: TriagePipeline | None = None,
) -> TriageSummary:
    """Score and rank the findings a run produced.

    The run's own coverage travels into the summary: a queue built from a
    partially reviewed backlog is a partial queue, and saying so here is the
    difference between a ranked list and a ranked list that can be trusted as
    complete.
    """
    if not report.sarif_path:
        raise TriageError("the run produced no SARIF export to ingest")

    summary = (pipeline or TriagekitPipeline()).ingest(
        Path(report.sarif_path), repo, out_dir, feeds
    )
    if not report.is_complete():
        summary.warnings.append(
            f"coverage: this queue comes from a run that reviewed "
            f"{report.reviewed_fraction:.0%} of its backlog "
            f"({report.scenarios_parked} parked, {report.scenarios_unfunded} "
            "unfunded) — it ranks what was reviewed, not what exists"
        )
    return summary
