"""A self-contained analyst view of one run.

Findings, a parked queue, and a ranked CSV are the right *storage*, and the
wrong thing to hand a person. This renders them into a single HTML file with no
external assets — no CDN, no fonts, no scripts fetched at open time — so it can
be attached to a ticket, mailed, or opened from a blob container behind a
private endpoint without reaching the network.

It is deliberately **read-only**. Every state change belongs to an
authenticated principal (see :mod:`engagement.identity`), and a page that let
an anonymous reader close a finding would undo the invariant the whole estate
is built on. Reading needs no server; deciding needs identity, and identity
needs the control plane this package does not yet have.

The coverage banner is the point of the page. A queue is only meaningful
against the denominator that produced it, so the fraction of the backlog
actually reviewed is the first thing rendered, before any finding.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from .analysis import AnalysisSummary
from .contracts import Disposition, RunReport
from .lifecycle import STATE_RANK, LifecycleReport
from .triage import TriageSummary

_STYLE = """
:root { color-scheme: light dark; --bg:#fff; --fg:#1a1a1a; --muted:#5a5a5a;
  --line:#e2e2e2; --card:#f7f7f8; --ok:#1e7f4a; --warn:#8a6100; --bad:#a11; }
@media (prefers-color-scheme: dark) { :root { --bg:#111214; --fg:#e8e8ea;
  --muted:#9a9aa2; --line:#2a2b30; --card:#1a1b1f; --ok:#4ad990; --warn:#d9b44a;
  --bad:#e06a6a; } }
* { box-sizing: border-box; }
body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
  font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
main { max-width: 68rem; margin: 0 auto; }
h1 { font-size:1.5rem; margin:0 0 .25rem; }
h2 { font-size:1.1rem; margin:2rem 0 .75rem; }
.sub { color:var(--muted); margin:0 0 1.5rem; }
.banner { border:1px solid var(--line); border-left:4px solid var(--ok);
  background:var(--card); border-radius:6px; padding:1rem 1.25rem; margin-bottom:1.5rem; }
.banner.partial { border-left-color:var(--warn); }
.banner strong { font-size:1.15rem; }
.grid { display:flex; flex-wrap:wrap; gap:1.5rem; margin:.5rem 0 0; }
.grid div { min-width:7rem; }
.grid span { display:block; color:var(--muted); font-size:.8rem;
  text-transform:uppercase; letter-spacing:.04em; }
.grid b { font-size:1.35rem; font-weight:600; }
.scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:.92rem; }
th,td { text-align:left; padding:.5rem .65rem; border-bottom:1px solid var(--line);
  vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.78rem;
  text-transform:uppercase; letter-spacing:.04em; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.88em; }
.tag { display:inline-block; padding:.1rem .45rem; border-radius:4px;
  font-size:.78rem; border:1px solid var(--line); }
.bad { color:var(--bad); } .warn { color:var(--warn); } .ok { color:var(--ok); }
.empty { color:var(--muted); font-style:italic; }
footer { margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--line);
  color:var(--muted); font-size:.85rem; }
"""


def _rows(report: RunReport) -> str:
    if not report.parked:
        return '<p class="empty">Nothing parked — every scenario reached a conclusion.</p>'
    out = [
        "<div class='scroll'><table><thead><tr><th>Scenario</th><th>Expert</th>"
        "<th>Priority</th><th>Why it is parked</th><th>Context supplied</th>"
        "</tr></thead><tbody>"
    ]
    for item in report.parked:
        supplied = ", ".join(item.supplied_paths) or "—"
        unresolved = (
            f"<br><span class='bad'>not supplied: {escape(', '.join(item.unresolved_paths))}</span>"
            if item.unresolved_paths
            else ""
        )
        gap = "<br>".join(escape(statement) for statement in item.missing_context) or "—"
        out.append(
            f"<tr><td><code>{escape(item.scenario_id)}</code></td>"
            f"<td>{escape(item.expert)}</td>"
            f"<td><span class='tag'>{escape(item.priority.value)}</span></td>"
            f"<td>{escape(item.reason)}<br><span class='empty'>{gap}</span></td>"
            f"<td><code>{escape(supplied)}</code>{unresolved}</td></tr>"
        )
    out.append("</tbody></table></div>")
    return "".join(out)


def _outcomes(report: RunReport) -> str:
    interesting = [
        item
        for item in report.scenarios
        if item.disposition is not Disposition.completed
    ]
    if not interesting:
        return ""
    rows = "".join(
        f"<tr><td><code>{escape(item.item_id)}</code></td>"
        f"<td><span class='tag'>{escape(item.disposition.value)}</span></td>"
        f"<td>{escape(item.detail)}</td></tr>"
        for item in interesting
    )
    return (
        "<h2>Work not completed</h2><div class='scroll'><table><thead><tr>"
        "<th>Item</th><th>Disposition</th><th>Detail</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )


def _lifecycle(life: LifecycleReport | None) -> str:
    """The lifecycle table — and, when nothing was checked, the fact that nothing was.

    An empty section here would read as "no unmaintained dependencies", which is
    the one conclusion this stage must never let a reader draw by accident.
    """
    if life is None:
        return ""
    if not life.feed_loaded:
        return (
            "<h2>Package lifecycle</h2><p class='warn'>No lifecycle feed was "
            "supplied, so no component was checked for deprecation, end of "
            "support or end of life. This is not a finding of "
            "&ldquo;none&rdquo;.</p>"
        )
    counts = life.counts()
    tiles = "".join(
        f"<div><span>{label}</span><b class='{css}'>{counts[key]}</b></div>"
        for label, key, css in (
            ("End of life", "eol", "bad"),
            ("End of support", "eos", "warn"),
            ("Deprecated", "deprecated", "warn"),
            ("Unknown", "unknown", "warn"),
            ("Supported", "supported", "ok"),
        )
    )
    adverse = life.adverse
    if not adverse:
        body = (
            "<p class='empty'>No component is deprecated, unsupported or past end "
            "of life.</p>"
        )
    else:
        rows = "".join(
            f"<tr><td><code>{escape(item.component)}</code></td>"
            f"<td>{escape(item.version or '—')}</td>"
            f"<td>{escape(item.ecosystem or '—')}</td>"
            f"<td><span class='tag'>{escape(item.state.value)}</span></td>"
            f"<td>{escape(item.detail)}</td></tr>"
            for item in sorted(adverse, key=lambda a: STATE_RANK[a.state])
        )
        body = (
            "<div class='scroll'><table><thead><tr><th>Component</th><th>Version</th>"
            "<th>Ecosystem</th><th>State</th><th>What it means</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    unknown = (
        f"<p class='warn'>{len(life.unknown_components)} component(s) are not "
        "covered by the feed. Unknown is not supported — they were not checked.</p>"
        if life.unknown_components
        else ""
    )
    return (
        f"<h2>Package lifecycle</h2><div class='grid'>{tiles}</div>{body}{unknown}"
    )


def _movement(movement: dict[str, int] | None) -> str:
    """What changed since the last run — the second thing an analyst looks for.

    After "how much was reviewed", the next question is always "what is
    different". Without it a returning reader re-reads a hundred unchanged rows
    to find the three that moved.
    """
    if movement is None:
        return ""
    if not any(movement.values()):
        return ""
    tiles = "".join(
        f"<div><span>{label}</span><b class='{css}'>{movement.get(key, 0)}</b></div>"
        for label, key, css in (
            ("Got worse", "increased", "bad"),
            ("Got better", "decreased", "ok"),
            ("New", "new", "warn"),
            ("Unchanged", "unchanged", ""),
        )
    )
    note = (
        "<p class='sub'>Movement is measured against the previous run's baseline. "
        "A first run reports everything as unknown rather than new.</p>"
        if movement.get("unchanged", 0) == 0 and movement.get("increased", 0) == 0
        else ""
    )
    return f"<h2>What changed</h2><div class='grid'>{tiles}</div>{note}"


def _chains(analysis: AnalysisSummary | None) -> str:
    if analysis is None or not analysis.chains:
        return ""
    rows = "".join(
        f"<tr><td>{escape(chain.title)}</td>"
        f"<td>{chain.score:.1f}</td>"
        f"<td>{chain.likelihood:.2f}</td>"
        f"<td>{escape(', '.join(chain.finding_ids))}</td>"
        f"<td>{escape(chain.narrative)}</td></tr>"
        for chain in sorted(analysis.chains, key=lambda c: c.score, reverse=True)
    )
    return (
        "<h2>Attack chains</h2><div class='scroll'><table><thead><tr><th>Chain</th>"
        "<th>Score</th><th>Likelihood</th><th>Findings</th><th>Narrative</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _pocs(analysis: AnalysisSummary | None) -> str:
    if analysis is None:
        return ""
    drafted = analysis.drafted
    if not drafted and not analysis.pocs_undrafted:
        return ""
    note = (
        "<p class='sub'>Drafts, not exploits. Nothing here was executed; each "
        "entry states what an operator would do in a test environment.</p>"
    )
    if not drafted:
        return (
            f"<h2>PoC drafts</h2>{note}<p class='empty'>Nothing was drafted for this "
            f"run ({len(analysis.pocs_undrafted)} finding(s) undrafted).</p>"
        )
    items = "".join(
        f"<li><b>{escape(poc.summary[:200] or poc.finding_id)}</b>"
        f"<br><span class='empty'>{len(poc.steps)} step(s), "
        f"{len(poc.preconditions)} precondition(s)</span></li>"
        for poc in drafted
    )
    undrafted = (
        f"<p class='warn'>{len(analysis.pocs_undrafted)} finding(s) carry no draft. "
        "That is a bound on this appendix, not a judgement that no PoC exists.</p>"
        if analysis.pocs_undrafted
        else ""
    )
    pack = (
        f"<p>Full pack: <code>{escape(analysis.pocs_path)}</code></p>"
        if analysis.pocs_path
        else ""
    )
    return f"<h2>PoC drafts</h2>{note}<ul>{items}</ul>{undrafted}{pack}"


def render(
    report: RunReport,
    triage: TriageSummary | None = None,
    lifecycle: LifecycleReport | None = None,
    analysis: AnalysisSummary | None = None,
    movement: dict[str, int] | None = None,
) -> str:
    """Render one run as a standalone HTML page."""
    reviewed = report.reviewed_fraction
    complete = report.is_complete()
    banner_class = "banner" if complete else "banner partial"
    headline = (
        "Every scenario reached a conclusion."
        if complete
        else f"This run reviewed {reviewed:.0%} of its backlog."
    )
    caveat = (
        ""
        if complete
        else "<p class='sub' style='margin:.5rem 0 0'>Findings below are what "
        "<em>was</em> reviewed. Parked and unfunded scenarios are not known to "
        "be clean.</p>"
    )

    tiles = [
        ("Reviewed", f"{reviewed:.0%}"),
        ("Completed", str(report.scenarios_completed)),
        ("Parked", str(report.scenarios_parked)),
        ("Unfunded", str(report.scenarios_unfunded)),
        ("Model calls", str(report.model_calls)),
    ]
    if triage is not None:
        tiles += [("Findings", str(triage.findings)), ("KEV", str(triage.kev_findings))]
    if lifecycle is not None and lifecycle.feed_loaded:
        tiles.append(("EOL", str(lifecycle.counts()["eol"])))
    if analysis is not None and analysis.chains:
        tiles.append(("Chains", str(len(analysis.chains))))
    grid = "".join(f"<div><span>{label}</span><b>{value}</b></div>" for label, value in tiles)

    warnings = (
        "<h2>Warnings</h2><ul>"
        + "".join(f"<li>{escape(item)}</li>" for item in report.warnings)
        + "</ul>"
        if report.warnings
        else ""
    )
    intelligence = ""
    if triage is not None and not triage.enriched:
        intelligence = (
            "<p class='warn'>Scored without KEV/EPSS feeds: ranking reflects "
            "declared severity, not known exploitation.</p>"
        )

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Engagement {escape(str(report.ref))}</title>"
        f"<style>{_STYLE}</style></head><body><main>"
        f"<h1>Engagement {escape(str(report.ref))}</h1>"
        f"<p class='sub'>Phase {escape(report.phase.value)}</p>"
        f"<div class='{banner_class}'><strong>{headline}</strong>{caveat}"
        f"<div class='grid'>{grid}</div></div>"
        f"{intelligence}"
        f"{_movement(movement)}"
        f"{_lifecycle(lifecycle)}"
        f"{_chains(analysis)}"
        f"{_pocs(analysis)}"
        f"<h2>Parked scenarios</h2>{_rows(report)}"
        f"{_outcomes(report)}"
        f"{warnings}"
        "<footer>Read-only. Validation states are set through an authenticated "
        "control plane, never from this page.</footer>"
        "</main></body></html>"
    )


def write(
    report: RunReport,
    out: Path,
    triage: TriageSummary | None = None,
    lifecycle: LifecycleReport | None = None,
    analysis: AnalysisSummary | None = None,
    movement: dict[str, int] | None = None,
) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(report, triage, lifecycle, analysis, movement), encoding="utf-8")
    return out
