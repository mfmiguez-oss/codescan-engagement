"""A threat model of the repository under review, written per run.

The queue answers "which finding first". The report answers "how much was
reviewed". Neither answers the question someone asks *before* they start
fixing things: **what does this system expose, to whom, and what would go
wrong** — which is the question a threat model is for, and the one an analyst
otherwise reconstructs by hand from four artifacts.

Everything here is assembled from what the run already produced. **No model is
called.** The entry points come from recon's request boundaries, the assets
from the components on findings and the lifecycle pass, the threats from the
scored queue, and the combinations from chain discovery. A threat model that
needed a model call would be a fifth thing to distrust; this one is a
projection of evidence already gathered, and it is deterministic — the same run
produces the same document.

Two disciplines carry over from the report, for the same reasons:

**Coverage comes first.** A threat model built from a review that reached 40%
of its backlog is a threat model of 40% of the system, and a reader who does
not know that will treat a quiet section as a safe one. So the fraction is
stated before any threat, and the sections that could be thin for a reason say
which reason.

**Everything rendered is attacker-influenced.** Titles, paths and component
names come from the repository under review, and this document is opened in
editors, rendered on intranets and pasted into tickets. Markup is stripped and
lengths are bounded on the way in.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .analysis import AnalysisSummary
from .contracts import RunReport, ScoredFinding
from .lifecycle import STATE_RANK, LifecycleReport
from .signals import BOUNDARY_EXPOSURE, ExposureMap

#: Inline markup stripped from every value that came out of the repository.
#: The document is Markdown *and* Mermaid, so this has to satisfy both: a pipe
#: ends a table cell, a backtick opens code, an angle bracket opens a tag in a
#: renderer that allows HTML, and a double quote closes a Mermaid node label —
#: which is the one that fails silently, because the diagram simply stops
#: rendering rather than rendering wrongly.
_UNSAFE = re.compile(r"[<>|`\"\r\n]")

#: Findings drawn in the diagram. A repository with two hundred findings does
#: not produce a readable graph, and a diagram nobody can read is worse than a
#: table — it looks like information.
MAX_DIAGRAM_FINDINGS = 12

#: Rows in the threat table. The queue is the complete list; this document
#: names the top of it and says how many it did not name.
MAX_THREAT_ROWS = 40


def _safe(value: object, limit: int = 200) -> str:
    """One value from the repository under review, made inert for Markdown."""
    return _UNSAFE.sub(" ", str(value if value is not None else "")).strip()[:limit]


def _node_id(prefix: str, index: int) -> str:
    """Mermaid node ids are minted, never taken from the data.

    A path or a finding id from the repository would otherwise become graph
    syntax, and the failure mode is a diagram that silently stops rendering.
    """
    return f"{prefix}{index}"


def _coverage(report: RunReport) -> list[str]:
    reviewed = report.reviewed_fraction
    if report.is_complete():
        return [
            "> **Coverage: every scenario reached a conclusion.** This model "
            "covers the whole backlog the router produced.",
            "",
        ]
    return [
        f"> **Coverage: {reviewed:.0%} of the backlog was reviewed.** "
        f"{report.scenarios_parked} scenario(s) were parked and "
        f"{report.scenarios_unfunded} went unfunded. Everything below describes "
        "what *was* reviewed. A quiet area of this document is an area nobody "
        "reached, not an area found safe.",
        "",
    ]


def _entry_points(exposure: ExposureMap | None) -> list[str]:
    """The attack surface, from recon's request boundaries."""
    out = ["## Entry points", ""]
    if exposure is None or not exposure.loaded:
        out += [
            "No recon boundary data was available for this run, so the "
            "reachable surface was not established. **This is not a finding of "
            "\"no entry points\"** — it means nothing walked the source for "
            "them, and every finding below was scored at the no-boundary "
            "baseline.",
            "",
        ]
        return out

    by_type: Counter[str] = Counter(exposure.types_by_path.values())
    out += [
        f"Recon found **{exposure.boundaries} request boundar(ies)** across "
        f"{len(exposure.by_path)} file(s) — the places where input from outside "
        "the system first reaches it.",
        "",
        "| Boundary | Files | Reachable by |",
        "|---|---|---|",
    ]
    for boundary, count in sorted(
        by_type.items(), key=lambda item: (-BOUNDARY_EXPOSURE.get(item[0], 0), item[0])
    ):
        score = BOUNDARY_EXPOSURE.get(boundary, BOUNDARY_EXPOSURE["request_boundary"])
        reach = (
            "anyone, unauthenticated"
            if score >= 90
            else "anyone who can reach the service"
            if score >= 70
            else "a party that already holds a session"
        )
        out.append(f"| `{_safe(boundary, 60)}` | {count} | {reach} |")
    out.append("")
    return out


def _assets(findings: list[ScoredFinding], lifecycle: LifecycleReport | None) -> list[str]:
    """Components the system depends on, and whether anyone maintains them."""
    out = ["## Assets and dependencies", ""]
    components = sorted(
        {f.component for f in findings if f.component.strip()}
    )
    if not components and (lifecycle is None or not lifecycle.assessments):
        out += [
            "No component inventory was supplied, so this run saw only the "
            "components that happened to appear on a finding. A source-only "
            "review carries no dependency inventory — supply one with "
            "`--inventory` or `--snyk-export` to model the supply chain.",
            "",
        ]
        return out

    if lifecycle is not None and lifecycle.feed_loaded:
        adverse = sorted(lifecycle.adverse, key=lambda a: STATE_RANK[a.state])
        if adverse:
            out += [
                f"**{len(adverse)} component(s) are unmaintained.** An "
                "unmaintained dependency carries no CVE precisely because "
                "nobody is looking, which is what makes it a threat rather "
                "than a chore.",
                "",
                "| Component | Version | State |",
                "|---|---|---|",
            ]
            for item in adverse[:MAX_THREAT_ROWS]:
                out.append(
                    f"| `{_safe(item.component, 80)}` | "
                    f"{_safe(item.version or '—', 40)} | {item.state.value} |"
                )
            out.append("")
        else:
            out += ["No component is deprecated, unsupported or past end of life.", ""]
        if lifecycle.unknown_components:
            out += [
                f"{len(lifecycle.unknown_components)} component(s) are not "
                "covered by the lifecycle feed. **Unknown is not supported** — "
                "they were not checked.",
                "",
            ]
    else:
        out += [
            "No lifecycle feed was supplied, so no component was checked for "
            "deprecation, end of support or end of life.",
            "",
        ]

    if components:
        shown = components[:MAX_THREAT_ROWS]
        listed = ", ".join(f"`{_safe(name, 60)}`" for name in shown)
        more = (
            f" …and {len(components) - len(shown)} more"
            if len(components) > len(shown)
            else ""
        )
        out += [f"Components appearing on findings: {listed}{more}.", ""]
    return out


def _threats(findings: list[ScoredFinding]) -> list[str]:
    """The findings, as threats, ranked as the queue ranks them."""
    out = ["## Threats", ""]
    if not findings:
        out += [
            "This run produced no findings. Read that against the coverage "
            "line above: it is a statement about what was reviewed, not about "
            "what exists.",
            "",
        ]
        return out

    ranked = sorted(findings, key=lambda f: (-f.risk_score, f.id))
    shown = ranked[:MAX_THREAT_ROWS]
    out += [
        "| Rank | Threat | Severity | Score | Where | Reachable | Exploited |",
        "|---|---|---|---|---|---|---|",
    ]
    for rank, finding in enumerate(shown, start=1):
        where = _safe(finding.path or finding.component or "—", 70)
        reachable = (
            _safe(finding.exposure_boundary, 40)
            if finding.exposure_boundary
            else ("—" if not finding.exposure else "no boundary found")
        )
        out.append(
            f"| {rank} | {_safe(finding.title, 90) or finding.id} | "
            f"{_safe(finding.severity, 20)} | {finding.risk_score:.1f} | "
            f"`{where}` | {reachable} | {'KEV' if finding.kev else '—'} |"
        )
    out.append("")
    if len(ranked) > len(shown):
        out += [
            f"{len(ranked) - len(shown)} further finding(s) are in `queue.csv`. "
            "This table is the top of the queue, not the whole of it.",
            "",
        ]
    return out


def _chains(analysis: AnalysisSummary | None) -> list[str]:
    out = ["## Combinations", ""]
    if analysis is None or not analysis.chains:
        out += [
            "No attack chains were discovered. Chain discovery is advisory and "
            "runs only with `--chains`; its absence says nothing about whether "
            "these findings combine.",
            "",
        ]
        return out
    out += [
        "Findings that combine into an outcome worse than any of them alone.",
        "",
    ]
    for chain in sorted(analysis.chains, key=lambda c: c.score, reverse=True):
        ids = ", ".join(f"`{_safe(item, 40)}`" for item in chain.finding_ids)
        out += [
            f"### {_safe(chain.title, 120) or chain.id}",
            "",
            f"- **Score** {chain.score:.1f} · **Likelihood** {chain.likelihood:.2f}",
            f"- **Findings** {ids}",
        ]
        if chain.narrative:
            out += ["", _safe(chain.narrative, 1200)]
        out.append("")
    return out


def _diagram(
    findings: list[ScoredFinding], exposure: ExposureMap | None
) -> list[str]:
    """The system as reviewed: what is reachable, and what is wrong behind it.

    Bounded to the highest-scoring findings. A graph of two hundred nodes is
    not a diagram, and drawing one would make an unreadable picture look like
    a complete one.
    """
    ranked = sorted(findings, key=lambda f: (-f.risk_score, f.id))[
        :MAX_DIAGRAM_FINDINGS
    ]
    if not ranked:
        return []

    nodes: list[str] = []
    edges: list[str] = []
    internal = False
    for index, finding in enumerate(ranked, start=1):
        node = _node_id("F", index)
        label = _safe(finding.title, 60) or _safe(finding.id, 40)
        style = "kev" if finding.kev else "bad"
        nodes.append(f'  {node}["{label}<br/><i>{finding.risk_score:.0f}</i>"]:::{style}')
        boundary = finding.exposure_boundary
        if boundary:
            edges.append(f'  EXT -->|"{_safe(boundary, 30)}"| {node}')
        else:
            internal = True
            edges.append(f"  INT --> {node}")

    lines = [
        "## The system as reviewed",
        "",
        "```mermaid",
        "flowchart LR",
        "  classDef edge fill:#5f1e1e,stroke:#d94a4a,color:#fff",
        "  classDef comp fill:#1e3a5f,stroke:#4a90d9,color:#fff",
        "  classDef bad fill:#5f4a1e,stroke:#d9a94a,color:#fff",
        "  classDef kev fill:#5f1e1e,stroke:#d94a4a,color:#fff",
        '  EXT["outside the system"]:::edge',
    ]
    if internal:
        lines.append(
            '  INT["reached from inside<br/><i>no boundary found</i>"]:::comp'
        )
    lines += nodes + edges + ["```", ""]
    if len(findings) > len(ranked):
        lines += [
            f"The {len(ranked)} highest-scoring of {len(findings)} finding(s). "
            "The rest are in the table above and in `queue.csv`.",
            "",
        ]
    return lines


def _bounds(
    report: RunReport,
    findings: list[ScoredFinding],
    analysis: AnalysisSummary | None,
) -> list[str]:
    """What this document does not cover. The section that keeps it honest."""
    out = ["## What this model does not cover", ""]
    items: list[str] = []
    if report.scenarios_parked:
        items.append(
            f"{report.scenarios_parked} scenario(s) were parked without a "
            "conclusion — see `parked-scenarios.json`."
        )
    if report.scenarios_unfunded:
        items.append(
            f"{report.scenarios_unfunded} scenario(s) were never dispatched "
            "because the budget ran out."
        )
    if report.passes < 2:
        items.append(
            "One detection pass ran, so every finding here is uncorroborated. "
            "That is not the same as unconfirmed."
        )
    uncorroborated = [f for f in findings if len(f.detected_by) < 2]
    if report.passes >= 2 and uncorroborated:
        items.append(
            f"{len(uncorroborated)} finding(s) were seen by only one pass; they "
            "are kept, and reported as uncorroborated rather than dropped."
        )
    if report.redactions:
        items.append(
            f"{report.redactions} credential-shaped value(s) were withheld from "
            "the model and restored afterwards."
        )
    if analysis is not None and analysis.pocs_undrafted:
        items.append(
            f"{len(analysis.pocs_undrafted)} finding(s) carry no proof-of-concept "
            "draft. Drafting is automatic only for findings that come out "
            "critical; anything else is drafted on request."
        )
    items.append(
        "This model describes the code as reviewed. It says nothing about "
        "deployment, configuration, network position or the people operating "
        "the system."
    )
    out += [f"- {item}" for item in items]
    out.append("")
    return out


def render(
    report: RunReport,
    findings: list[ScoredFinding],
    repo: str = "",
    exposure: ExposureMap | None = None,
    lifecycle: LifecycleReport | None = None,
    analysis: AnalysisSummary | None = None,
    generated_at: str | None = None,
) -> str:
    """The threat model as one Markdown document, diagrams included."""
    stamp = generated_at or datetime.now(UTC).strftime("%Y-%m-%d")
    title = _safe(repo or str(report.ref), 120)
    lines = [
        f"# Threat model — {title}",
        "",
        f"Run `{_safe(report.ref, 80)}` · generated {stamp} · "
        f"{len(findings)} finding(s)",
        "",
        "Assembled from this run's own evidence — recon boundaries, the scored "
        "queue, the lifecycle pass and chain discovery. **No model was called "
        "to write it**, so it is a projection of what was found rather than a "
        "fifth opinion about it.",
        "",
    ]
    lines += _coverage(report)
    lines += _entry_points(exposure)
    lines += _assets(findings, lifecycle)
    lines += _threats(findings)
    lines += _diagram(findings, exposure)
    lines += _chains(analysis)
    lines += _bounds(report, findings, analysis)
    return "\n".join(lines).rstrip() + "\n"


def write(
    report: RunReport,
    findings: list[ScoredFinding],
    out_dir: Path,
    repo: str = "",
    exposure: ExposureMap | None = None,
    lifecycle: LifecycleReport | None = None,
    analysis: AnalysisSummary | None = None,
) -> Path:
    """Write `threat-model.md` beside the run's other outputs."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "threat-model.md"
    path.write_text(
        render(report, findings, repo, exposure, lifecycle, analysis),
        encoding="utf-8",
    )
    return path
