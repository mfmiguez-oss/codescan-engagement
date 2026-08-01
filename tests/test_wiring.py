"""Cross-boundary checks: a surface that exists is a surface that is reached.

Every defect this repository has shipped past a green suite lived in a gap
*between* layers, not inside one: a ceiling the template set and nothing read, a
container command that was never installed, an audit sink the CLI owned and
never wired. Each unit was correct and each boundary was not, and a suite that
only ever tests within a layer cannot see that.

So these tests deliberately cross. They assert that every flag the parser
accepts reaches the code that acts on it, and that the artifacts a run promises
are the artifacts it writes.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from engagement import analysis, cli, lifecycle, siem
from engagement.audit import AuditLog, MemorySink
from engagement.contracts import ScoredFinding
from engagement.triage import TriageSummary


def _parse(*argv: str) -> object:
    return cli._build_parser().parse_args(argv)


def _run_args(*extra: str) -> object:
    return _parse("run", "acme", "run-001", "--workspace", ".", *extra)


# -- every new flag exists, and reaches something ----------------------------


def test_the_new_flags_parse() -> None:
    args = _run_args(
        "--chains",
        "--pocs",
        "--analysis-model",
        "gpt-5-mini",
        "--lifecycle-feed",
        "feeds/lifecycle.json",
        "--inventory",
        "sbom.json",
        "--siem",
        "out.json",
        "--siem-format",
        "cef",
    )
    assert args.chains and args.pocs  # type: ignore[attr-defined]
    assert args.analysis_model == "gpt-5-mini"  # type: ignore[attr-defined]
    assert args.siem_format == "cef"  # type: ignore[attr-defined]


def test_every_run_flag_is_read_somewhere_in_the_command() -> None:
    """The failure mode this catches: a flag that parses and is never consulted.

    ``ENGAGEMENT_MAX_CALLS`` was set by the deployment template and read by
    nothing for a whole release, and the suite was green throughout.
    """
    source = "\n".join(
        inspect.getsource(function)
        for function in (
            cli._cmd_run,
            cli._run_lifecycle,
            cli._run_analysis,
            cli._load_inventory,
        )
    )
    for flag in (
        "chains",
        "pocs",
        "analysis_model",
        "lifecycle_feed",
        "inventory",
        "siem",
        "siem_format",
        "snyk_export",
        "baseline",
        "second_model",
        "second_sarif",
    ):
        assert f"args.{flag}" in source, f"--{flag.replace('_', '-')} parses but is never read"


def test_the_new_subcommands_are_registered_and_dispatch() -> None:
    kev = _parse("fetch-kev", "--out", "kev.json")
    plan = _parse("plan", "--model", "claude-opus-5", "--scenarios", "4")

    assert kev.func is cli._cmd_fetch_kev  # type: ignore[attr-defined]
    assert plan.func is cli._cmd_plan  # type: ignore[attr-defined]
    assert plan.scenarios == 4  # type: ignore[attr-defined]


def test_the_plan_command_covers_every_billable_task() -> None:
    """A task missing from the plan is spend nobody projected."""
    from engagement.models import Task

    source = inspect.getsource(cli._cmd_plan)
    for task in Task:
        assert f"Task.{task.name}" in source, f"{task.value} is not in the projected plan"


def test_the_siem_subcommand_is_registered_and_dispatches() -> None:
    args = _parse("export-siem", "audit.jsonl", "--out", "out.json", "--format", "ecs")

    assert args.func is cli._cmd_export_siem  # type: ignore[attr-defined]
    assert args.fmt == "ecs"  # type: ignore[attr-defined]


def test_every_siem_format_the_parser_accepts_is_one_the_renderer_knows() -> None:
    args = _parse("export-siem", "a", "--out", "b")
    choices = next(
        action.choices
        for action in cli._build_parser()._subparsers._group_actions[0]  # type: ignore[union-attr]
        .choices["export-siem"]
        ._actions
        if action.dest == "fmt"
    )
    assert set(choices or ()) == set(siem.FORMATS)
    assert args.fmt in siem.FORMATS  # type: ignore[attr-defined]


# -- the lifecycle stage is reached even when nothing is configured ----------


def test_lifecycle_runs_without_a_feed_and_reports_that_it_did_nothing() -> None:
    """Silence here is indistinguishable from a fleet with no dead dependencies."""
    args = _run_args()
    args.feeds = None  # type: ignore[attr-defined]
    args.lifecycle_feed = None  # type: ignore[attr-defined]
    args.inventory = None  # type: ignore[attr-defined]
    summary = TriageSummary(
        queue=[ScoredFinding(id="f1", repo="acme/app", title="x", component="django")]
    )
    sink = MemorySink()

    report = cli._run_lifecycle(args, summary, "acme/app", AuditLog(sink))

    assert not report.feed_loaded
    assert any("no feed" in warning for warning in report.warnings)
    assert [event.kind for event in sink.events] == ["lifecycle_assessed"]


def test_a_lifecycle_finding_joins_the_queue_it_would_otherwise_be_missing_from(
    tmp_path: Path,
) -> None:
    feed = tmp_path / "lifecycle.json"
    feed.write_text(
        '{"packages": [{"ecosystem": "pypi", "name": "django", '
        '"cycles": [{"cycle": "3.2", "eol": "2024-04-01"}]}]}',
        encoding="utf-8",
    )
    args = _run_args()
    args.feeds = None  # type: ignore[attr-defined]
    args.lifecycle_feed = feed  # type: ignore[attr-defined]
    args.inventory = None  # type: ignore[attr-defined]
    summary = TriageSummary(
        findings=1,
        queue=[
            ScoredFinding(
                id="f1",
                repo="acme/app",
                title="x",
                component="django",
                ecosystem="pypi",
                version="3.2.1",
            )
        ],
    )

    report = cli._run_lifecycle(args, summary, "acme/app", AuditLog(MemorySink()))

    assert len(report.findings) == 1
    assert summary.findings == 2, "the minted finding never reached the queue"
    assert any("End of life" in finding.title for finding in summary.queue)


def test_the_lifecycle_audit_event_is_one_the_siem_exporter_knows() -> None:
    """A stage that emits an event the exporter cannot classify ships it blank."""
    assert "lifecycle_assessed" in siem.ALLOWED_DETAILS
    assert "analysis_finished" in siem.ALLOWED_DETAILS


def test_every_detail_the_lifecycle_event_emits_is_allowed_out() -> None:
    args = _run_args()
    args.feeds = None  # type: ignore[attr-defined]
    args.lifecycle_feed = None  # type: ignore[attr-defined]
    args.inventory = None  # type: ignore[attr-defined]
    sink = MemorySink()
    cli._run_lifecycle(args, TriageSummary(), "acme/app", AuditLog(sink))

    emitted = set(sink.events[0].detail)
    assert emitted <= siem.ALLOWED_DETAILS["lifecycle_assessed"], (
        f"these details would be dropped on export: "
        f"{emitted - siem.ALLOWED_DETAILS['lifecycle_assessed']}"
    )


# -- the analysis stage refuses rather than half-running ---------------------


def test_analysis_without_a_deployment_reports_rather_than_guessing() -> None:
    args = _run_args("--chains")
    args.analysis_model = ""  # type: ignore[attr-defined]
    args.model = ""  # type: ignore[attr-defined]

    result = cli._run_analysis(
        args, TriageSummary(), driver=None, repo="r", run_dir=Path("."), audit_log=AuditLog()  # type: ignore[arg-type]
    )

    assert result is not None
    assert any("no deployment" in warning for warning in result.warnings)


def test_analysis_is_skipped_entirely_when_neither_flag_is_given() -> None:
    args = _run_args()

    assert (
        cli._run_analysis(
            args, TriageSummary(), driver=None, repo="r", run_dir=Path("."), audit_log=AuditLog()  # type: ignore[arg-type]
        )
        is None
    )


def test_the_report_renderer_accepts_what_the_run_produces() -> None:
    """The signature drifted once already; a positional mismatch is silent."""
    from engagement.report import write

    parameters = list(inspect.signature(write).parameters)
    assert parameters == ["report", "out", "triage", "lifecycle", "analysis", "movement"]


def test_the_documented_caps_are_the_ones_the_code_applies() -> None:
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(
        encoding="utf-8"
    )
    assert str(analysis.MAX_POC_FINDINGS) in readme
    assert str(analysis.MAX_CHAIN_FINDINGS) in readme


def test_every_lifecycle_state_has_an_adjustment_and_a_rank() -> None:
    for state in lifecycle.LifecycleState:
        assert state in lifecycle.STATE_ADJUSTMENT
        assert state in lifecycle.STATE_RANK
