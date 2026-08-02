"""The per-run threat model: honest about coverage, inert about content.

Two families of test carry this. The first is about **honesty** — a threat
model built from a run that reached 40% of its backlog describes 40% of a
system, and a reader who is not told that will read a quiet section as a safe
one. The second is about **containment** — every value in the document came out
of a repository under review, and it lands in Markdown renderers and Mermaid.
"""

from __future__ import annotations

from pathlib import Path

from engagement.analysis import AnalysisSummary
from engagement.contracts import (
    Chain,
    Disposition,
    Phase,
    RunRef,
    RunReport,
    ScoredFinding,
    WorkOutcome,
)
from engagement.lifecycle import LifecycleReport
from engagement.signals import ExposureMap
from engagement.threatmodel import MAX_DIAGRAM_FINDINGS, render, write

REF = RunRef(target="acme", run_id="run-001")


def _finding(
    id: str = "F-1",
    title: str = "SQL injection in the report filter",
    score: float = 90.0,
    **extra: object,
) -> ScoredFinding:
    return ScoredFinding(
        id=id, repo="acme/api", title=title, risk_score=score, **extra
    )


def _complete() -> RunReport:
    return RunReport(
        ref=REF,
        phase=Phase.complete,
        scenarios=[WorkOutcome(item_id="S1", disposition=Disposition.completed)],
    )


def _partial() -> RunReport:
    return RunReport(
        ref=REF,
        phase=Phase.export,
        scenarios=[
            WorkOutcome(item_id="S1", disposition=Disposition.completed),
            WorkOutcome(item_id="S2", disposition=Disposition.parked),
            WorkOutcome(item_id="S3", disposition=Disposition.unfunded),
        ],
    )


# -- honesty -----------------------------------------------------------------


def test_coverage_is_stated_before_any_threat() -> None:
    """A model of part of a system read as a model of the system is the whole
    failure this document could cause."""
    text = render(_partial(), [_finding()])

    coverage = text.index("Coverage:")
    threats = text.index("## Threats")
    assert coverage < threats
    assert "not an area found safe" in text


def test_a_complete_run_says_so_rather_than_quoting_a_percentage() -> None:
    text = render(_complete(), [_finding()])

    assert "every scenario reached a conclusion" in text.lower()


def test_no_findings_is_not_reported_as_nothing_to_find() -> None:
    text = render(_complete(), [])

    assert "not about what exists" in text


def test_a_missing_input_is_named_rather_than_left_empty() -> None:
    """An empty section reads as "none". Each one that could be thin for a
    reason has to say which reason."""
    text = render(_partial(), [_finding(component="requests")])

    assert "not a finding of" in text, "absent recon read as no entry points"
    assert "No lifecycle feed was supplied" in text
    assert "advisory and" in text, "absent chains read as no chains existing"


def test_a_source_only_review_says_it_has_no_dependency_inventory() -> None:
    """A run that saw no components at all is a different gap from one whose
    lifecycle feed was missing, and reads differently."""
    text = render(_complete(), [_finding()])

    assert "no dependency inventory" in text
    assert "--inventory" in text


def test_parked_and_unfunded_work_is_named_in_the_bounds() -> None:
    text = render(_partial(), [_finding()])
    bounds = text[text.index("## What this model does not cover") :]

    assert "parked" in bounds
    assert "budget ran out" in bounds


def test_a_single_pass_run_says_its_findings_are_uncorroborated() -> None:
    text = render(_complete(), [_finding()])

    assert "uncorroborated" in text


def test_the_model_states_what_it_is_not_about() -> None:
    """Static review says nothing about deployment or the people running it."""
    text = render(_complete(), [_finding()])

    assert "deployment, configuration, network position" in text


# -- containment -------------------------------------------------------------


def test_a_hostile_finding_title_cannot_break_the_document() -> None:
    """Titles come from the repository under review and land in a Markdown
    table, where a pipe ends a cell and a backtick opens code."""
    hostile = _finding(
        title="evil | <script>alert(1)</script> | `x` \n new row",
        path="a|b<c>d",
    )
    text = render(_complete(), [hostile])

    body = text[text.index("## Threats") : text.index("## The system as reviewed")]
    for row in body.splitlines():
        if row.startswith("| ") and "---" not in row and "Rank" not in row:
            assert row.count("|") == 8, f"a value broke the table: {row}"
    assert "<script>" not in text


def test_a_quote_in_a_title_cannot_close_a_mermaid_label() -> None:
    """The silent one: the diagram stops rendering rather than rendering
    wrongly, so nothing looks broken until someone notices it is missing."""
    text = render(
        _complete(),
        [_finding(title='say "hello" ]:::kev --> EVIL', exposure_boundary="webhook")],
    )
    diagram = text[text.index("```mermaid") : text.index("```", text.index("```mermaid") + 3)]

    assert diagram.count('"') % 2 == 0, "an unbalanced quote broke the diagram"
    # Every declaration line names a minted id. An injected `]:::kev --> EVIL`
    # that escaped its label would show up here as a node this did not mint.
    declared = [
        line.strip()
        for line in diagram.splitlines()
        if line.startswith("  ") and "classDef" not in line
    ]
    assert all(
        line.startswith(("EXT", "INT", "F")) for line in declared
    ), f"the diagram grew a node from finding text: {declared}"


def test_diagram_node_ids_are_minted_not_taken_from_findings() -> None:
    """A path or an id from the repository becomes graph syntax otherwise, and
    the failure is a diagram that silently stops rendering."""
    text = render(
        _complete(),
        [_finding(id='bad"]-->EVIL[', title="ok", exposure_boundary="webhook")],
    )
    diagram = text[text.index("```mermaid") : text.index("```", text.index("```mermaid") + 3)]

    assert "EVIL" not in diagram
    assert 'F1["' in diagram


def test_the_diagram_is_bounded_and_says_what_it_omitted() -> None:
    """A graph of two hundred nodes is not a diagram, and drawing one makes an
    unreadable picture look like a complete one."""
    findings = [_finding(id=f"F-{n}", score=float(n)) for n in range(40)]
    text = render(_complete(), findings)
    diagram = text[text.index("```mermaid") : text.index("```", text.index("```mermaid") + 3)]

    assert diagram.count('"]:::') <= MAX_DIAGRAM_FINDINGS + 2
    assert "highest-scoring of 40" in text


def test_a_run_with_no_findings_draws_no_diagram() -> None:
    assert "```mermaid" not in render(_complete(), [])


# -- the content it is built from --------------------------------------------


def test_entry_points_come_from_recon_boundaries() -> None:
    exposure = ExposureMap(
        by_path={"src/hooks.py": 90.0},
        types_by_path={"src/hooks.py": "webhook"},
        boundaries=1,
    )
    text = render(_complete(), [_finding()], exposure=exposure)

    assert "webhook" in text
    assert "anyone, unauthenticated" in text or "anyone who can reach" in text


def test_an_unmaintained_component_is_a_threat_not_a_chore() -> None:
    from engagement.lifecycle import Assessment, LifecycleState

    life = LifecycleReport(
        feed_loaded=True,
        assessments=[
            Assessment(
                component="requests",
                version="2.19.1",
                state=LifecycleState.eol,
                reason="past end of life",
            )
        ],
    )
    text = render(_complete(), [_finding()], lifecycle=life)

    assert "requests" in text
    assert "nobody is looking" in text


def test_chains_are_rendered_with_their_findings() -> None:
    analysis = AnalysisSummary(
        chains=[
            Chain(
                id="CH-1",
                title="SSRF into the internal admin API",
                finding_ids=["F-1", "F-2"],
                narrative="reach the metadata service, then pivot",
                score=88.0,
                likelihood=0.7,
            )
        ]
    )
    text = render(_complete(), [_finding()], analysis=analysis)

    assert "SSRF into the internal admin API" in text
    assert "`F-1`" in text


def test_the_threat_model_is_deterministic_and_calls_no_model() -> None:
    """It is a projection of evidence already gathered. A threat model that
    needed a model call would be a fifth thing to distrust."""
    findings = [_finding(), _finding(id="F-2", title="XSS", score=40.0)]
    first = render(_complete(), findings, generated_at="2026-08-02")
    second = render(_complete(), findings, generated_at="2026-08-02")

    assert first == second


# -- it lands with the rest --------------------------------------------------


def test_it_is_written_beside_the_other_outputs(tmp_path: Path) -> None:
    path = write(_complete(), [_finding()], out_dir=tmp_path, repo="acme/api")

    assert path == tmp_path / "threat-model.md"
    assert path.read_text(encoding="utf-8").startswith("# Threat model — acme/api")


def test_the_diagram_renders_in_the_file_itself(tmp_path: Path) -> None:
    """"Readable directly in the md file" — no build step, no image reference."""
    text = write(_complete(), [_finding()], out_dir=tmp_path).read_text(
        encoding="utf-8"
    )

    assert "```mermaid" in text
    assert text.count("```") % 2 == 0
    assert "![" not in text
