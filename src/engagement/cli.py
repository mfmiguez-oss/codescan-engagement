"""``engagement run`` — drive one run to completion, or to its budget.

Exit codes carry the outcome, because the only consumer of an unattended run is
another program: **0** everything reached a conclusion, **3** the run finished
but left work parked or unfunded, **2** configuration was refused, **1** the run
failed. Three is deliberately not zero — a run that reviewed half its backlog
is not a clean run, and a scheduler must be able to tell the difference without
parsing prose.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from .analysis import AnalysisSummary, analyse
from .audit import AuditLog, FileSink, default_audit_path, read_events
from .budget import Budget, Ledger
from .contracts import Disposition, Phase, RunRef, RunReport
from .driver import Driver, Policy
from .egress import build_policy
from .export import movement_summary, write_manifest, write_queue
from .feeds import CISA_KEV_URL, FeedError, fetch_kev, load_snyk, write_kev
from .governance import RiskTier, review
from .identity import Action, Unauthorized, authorize, machine
from .lifecycle import LifecycleError, LifecycleReport, assess, load_feed
from .models import SingleVendorError, Task, build_plan, check_two_vendor_passes, render_plan
from .providers import ProviderError, build_provider
from .report import write as write_report
from .siem import FORMATS, summarize
from .siem import export as siem_export
from .signals import apply_chaining, apply_exposure, load_boundaries
from .triage import TriageError, TriageSummary, ingest_run
from .workspace import CliWorkspace, WorkspaceError, seed_workspace, vendored_workspace

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_INCOMPLETE = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="engagement")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Drive one run unattended.")
    run.add_argument("target")
    run.add_argument("run_id")
    run.add_argument(
        "--workspace", type=Path, required=True, help="OpenHack workspace root."
    )
    run.add_argument("--model", default="", help="Deployment for every phase.")
    run.add_argument("--router-model", default="")
    run.add_argument("--expert-model", default="")
    run.add_argument("--triage-model", default="")
    run.add_argument(
        "--expert", action="append", default=[], help="Scope recon to this expert; repeatable."
    )
    # No argparse default: the flag must be distinguishable from "unset" so
    # the environment can supply one. Precedence is flag > environment > the
    # bounded built-in.
    run.add_argument("--max-calls", type=int, help="Overrides ENGAGEMENT_MAX_CALLS.")
    run.add_argument("--max-tokens", type=int, help="Overrides ENGAGEMENT_MAX_TOKENS.")
    run.add_argument("--max-retries", type=int, default=1)
    run.add_argument("--no-sarif", action="store_true")
    run.add_argument("--sarif-out", type=Path)
    run.add_argument(
        "--triage",
        action="store_true",
        help="Score and rank the findings through the codescan triage backbone.",
    )
    run.add_argument("--feeds", type=Path, help="Directory holding kev.json and epss.csv.")
    run.add_argument("--repo", default="", help="Repository name recorded on findings.")
    run.add_argument(
        "--resume-parked",
        action="store_true",
        help="Re-attempt the scenarios a previous run left parked.",
    )
    run.add_argument(
        "--chains",
        action="store_true",
        help="Discover attack chains across the queue. Costs one call per service.",
    )
    run.add_argument(
        "--pocs",
        action="store_true",
        help="Draft a proof of concept per finding, highest risk first. Never executed.",
    )
    run.add_argument(
        "--analysis-model",
        default="",
        help="Deployment for --chains and --pocs (default: --model).",
    )
    run.add_argument(
        "--lifecycle-feed",
        type=Path,
        help="Package lifecycle feed (deprecation / EOS / EOL). Defaults to "
        "<feeds>/lifecycle.json when --feeds is given.",
    )
    run.add_argument(
        "--inventory",
        type=Path,
        help="JSON list of components to lifecycle-check beyond those on findings.",
    )
    run.add_argument(
        "--snyk-export",
        type=Path,
        help="A Snyk export whose components join the lifecycle check. Offline; "
        "no credentials. This is usually what closes the EOL blind spot.",
    )
    run.add_argument(
        "--second-model",
        default="",
        help="Deployment for a second, independent detection pass. Must be a "
        "different vendor from --expert-model; refused otherwise.",
    )
    run.add_argument(
        "--second-sarif",
        type=Path,
        help="Override the second pass's SARIF with one produced out of band. "
        "Not needed for --second-model: the driver drives both passes.",
    )
    run.add_argument(
        "--baseline",
        type=Path,
        help="Previous run's baseline, for severity movement. Rolled forward here.",
    )
    run.add_argument(
        "--risk-tier",
        choices=[t.value for t in RiskTier],
        default=RiskTier.standard.value,
        help="How much adjudication may go unreviewed. 'critical' samples every "
        "decision for human review, which is the same as not adjudicating "
        "unattended at all.",
    )
    run.add_argument(
        "--sample-rate",
        type=float,
        help="Override the tier's human-review sampling rate (0.0-1.0).",
    )
    run.add_argument(
        "--shadow-model",
        action="append",
        default=[],
        help="A model whose decisions are recorded but do not count until it has "
        "earned trust. Repeatable.",
    )
    run.add_argument(
        "--siem",
        type=Path,
        help="Also write the audit trail here in a SIEM-ready format.",
    )
    run.add_argument("--siem-format", choices=list(FORMATS), default="ecs")
    run.add_argument("--report", type=Path, help="Write a self-contained HTML view here.")
    run.add_argument(
        "--audit",
        type=Path,
        help="Audit trail path (default: <run>/audit.jsonl). Always written.",
    )
    run.add_argument("--json", action="store_true", help="Print the report as JSON.")
    run.set_defaults(func=_cmd_run)

    init = sub.add_parser(
        "init-workspace",
        help="Seed a writable workspace root from the vendored methodology.",
    )
    init.add_argument("destination", type=Path)
    init.add_argument(
        "--from", dest="source", type=Path, help="An OpenHack checkout to copy instead."
    )
    init.set_defaults(func=_cmd_init_workspace)

    siem = sub.add_parser(
        "export-siem",
        help="Convert a run's audit trail into a SIEM-ready file.",
    )
    siem.add_argument("audit", type=Path, help="Audit trail to convert.")
    siem.add_argument("--out", type=Path, required=True)
    siem.add_argument("--format", dest="fmt", choices=list(FORMATS), default="ecs")
    siem.add_argument("--run", default="", help="Correlation id stamped on every event.")
    siem.set_defaults(func=_cmd_export_siem)

    kev = sub.add_parser(
        "fetch-kev", help="Download the CISA Known Exploited Vulnerabilities catalogue."
    )
    kev.add_argument("--out", type=Path, required=True, help="Where to cache the catalogue.")
    kev.add_argument("--url", default=CISA_KEV_URL)
    kev.set_defaults(func=_cmd_fetch_kev)

    plan = sub.add_parser("plan", help="Show the model allocation and projected spend.")
    plan.add_argument("--model", default="", help="Deployment for every task.")
    plan.add_argument("--router-model", default="")
    plan.add_argument("--expert-model", default="")
    plan.add_argument("--triage-model", default="")
    plan.add_argument("--analysis-model", default="")
    plan.add_argument("--scenarios", type=int, default=0)
    plan.add_argument("--candidates", type=int, default=0)
    plan.add_argument("--services", type=int, default=1)
    plan.add_argument("--findings", type=int, default=0)
    plan.set_defaults(func=_cmd_plan)

    return parser


def _cmd_fetch_kev(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Pull the catalogue from CISA. The only command that reaches the network."""
    del env
    try:
        catalogue = fetch_kev(args.url)
    except FeedError as exc:
        print(f"could not fetch KEV: {exc}", file=sys.stderr)
        return EXIT_ERROR
    path = write_kev(catalogue, args.out)
    print(f"{len(catalogue.ids)} exploited CVE(s) -> {path}")
    print(f"  catalogue : {catalogue.catalog_version or 'unversioned'}")
    print(f"  released  : {catalogue.date_released or 'undated'}")
    age = catalogue.age_days()
    if age is not None:
        print(f"  age       : {age} day(s)")
    return EXIT_OK


def _cmd_plan(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Print the allocation before a run, so spend is a decision not a surprise."""
    shared = args.model or env.get("ENGAGEMENT_MODEL", "")
    deployments = {
        Task.router.value: args.router_model or shared,
        Task.scenarios.value: args.expert_model or shared,
        Task.triage.value: args.triage_model or shared,
        Task.chains.value: args.analysis_model or shared,
        Task.poc.value: args.analysis_model or shared,
    }
    plan = build_plan(
        deployments,
        scenarios=args.scenarios,
        candidates=args.candidates,
        services=args.services,
        findings=args.findings,
    )
    print(render_plan(plan))
    for warning in plan.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return EXIT_OK


def _cmd_export_siem(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    del env
    if not args.audit.exists():
        print(f"no audit trail at {args.audit}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        path, count = siem_export(args.audit, args.out, args.fmt, args.run)
    except (OSError, ValueError) as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"{count} event(s) -> {path} ({args.fmt})")
    for kind, total in sorted(summarize(read_events(args.audit)).items()):
        print(f"  {kind:<18} {total}")
    return EXIT_OK


def _cmd_init_workspace(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    try:
        root = seed_workspace(args.destination, args.source)
    except WorkspaceError as exc:
        print(f"could not seed a workspace: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    origin = args.source or vendored_workspace()
    print(f"workspace ready at {root} (from {origin})")
    print(f"  next: engagement run <target> <run-id> --workspace {root}")
    return EXIT_OK


def _bound(flag: int | None, env: Mapping[str, str], name: str, default: int) -> int:
    """Resolve a ceiling from the flag, then the environment, then the default.

    A malformed environment value is refused rather than ignored. Falling back
    to the built-in would mean an operator who set a budget silently got a
    different one — which is the same failure as a bound that does not apply,
    only harder to notice because the configuration *looks* set.
    """
    if flag is not None:
        return flag
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer") from exc
    if value < 1:
        raise ValueError(f"{name}={value} must be at least 1")
    return value


def _cmd_run(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    egress = build_policy(env)
    try:
        provider = build_provider(env, egress=egress)
    except ProviderError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    policy = Policy(
        experts=list(args.expert),
        model=args.model or env.get("ENGAGEMENT_MODEL", ""),
        router_model=args.router_model,
        expert_model=args.expert_model,
        triage_model=args.triage_model,
        max_retries=args.max_retries,
        emit_sarif=not args.no_sarif,
    )
    if not policy.has_model():
        print(
            "refusing to run: no model deployment set — pass --model or set "
            "ENGAGEMENT_MODEL. An unattended run never guesses a deployment.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    try:
        second = args.second_model.strip()
        if second:
            for warning in check_two_vendor_passes(
                [policy.expert_model or policy.model, second],
                allow_single=env.get("ENGAGEMENT_ALLOW_SINGLE_VENDOR", "") == "1",
            ):
                print(f"warning: {warning}", file=sys.stderr)
            policy.second_expert_model = second
    except SingleVendorError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        authorize(machine(), Action.run_scan)
    except Unauthorized as exc:  # pragma: no cover - defensive
        print(f"refusing to run: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        budget = Budget(
            max_calls=_bound(args.max_calls, env, "ENGAGEMENT_MAX_CALLS", Budget().max_calls),
            max_total_tokens=_bound(
                args.max_tokens, env, "ENGAGEMENT_MAX_TOKENS", Budget().max_total_tokens
            ),
        )
    except ValueError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    ledger = Ledger(budget=budget)
    # An unattended run with no trail cannot answer what it sent or spent, so
    # the sink is wired here rather than left to a caller to remember.
    audit_path = args.audit or default_audit_path(
        args.workspace, args.target, args.run_id
    )
    audit_log = AuditLog(FileSink(audit_path))
    driver = Driver(
        workspace=CliWorkspace(root=args.workspace),
        provider=provider,
        ledger=ledger,
        policy=policy,
        audit=audit_log,
    )
    ref = RunRef(target=args.target, run_id=args.run_id)

    try:
        if args.resume_parked:
            report = driver.resume_parked(ref, sarif_out=args.sarif_out)
        elif policy.has_second_pass():
            report = driver.run_two_pass(ref, sarif_out=args.sarif_out)
        else:
            report = driver.run(ref, sarif_out=args.sarif_out)
    except WorkspaceError as exc:
        print(f"run failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    warnings = list(report.warnings)
    run_dir = args.workspace / "runs" / args.target / args.run_id
    repo = args.repo or f"{args.target}/{args.run_id}"
    summary = None
    lifecycle_report = None
    analysis = None
    if args.triage:
        try:
            # The driver produces the second pass itself; --second-sarif only
            # overrides it, for a pass produced out of band.
            second_path = args.second_sarif or (
                Path(report.second_sarif_path) if report.second_sarif_path else None
            )
            extra = {}
            if second_path and Path(second_path).exists():
                extra[f"pass-2:{args.second_model or 'second'}"] = Path(second_path)
            elif second_path:
                warnings.append(
                    f"detection: no SARIF at {second_path}; this queue comes "
                    "from one pass, so every finding is uncorroborated"
                )
            summary = ingest_run(
                report, repo=repo, out_dir=run_dir, feeds=args.feeds, extra_sarif=extra
            )
            warnings.extend(summary.warnings)
        except TriageError as exc:
            # a triage failure must not discard a completed run's findings
            warnings.append(f"triage: {exc}")

    movement = None
    if summary is not None:
        lifecycle_report = _run_lifecycle(args, summary, repo, audit_log)
        warnings.extend(lifecycle_report.warnings)
        analysis = _run_analysis(args, summary, driver, repo, run_dir, audit_log)
        if analysis is not None:
            warnings.extend(analysis.warnings)
        signal_report = apply_exposure(
            summary.queue, load_boundaries(run_dir / "recon-output" / "recon-items.jsonl")
        )
        if analysis is not None:
            apply_chaining(summary.queue, analysis.chains, signal_report)
        warnings.extend(signal_report.warnings)

        # written last, so the worklist reflects lifecycle findings and the
        # adjustments the earlier stages made rather than a pre-enrichment queue
        queue_path, rows, queue_warnings = write_queue(
            summary.queue,
            out_dir=run_dir,
            run_id=args.run_id,
            baseline_path=args.baseline,
            sources={f.id: ["openhack"] for f in summary.queue},
        )
        warnings.extend(queue_warnings)
        write_manifest(rows, run_dir / "queue.json", args.run_id)
        summary.csv_path = str(queue_path)
        movement = movement_summary(rows)

    governance = review(
        {item.item_id: item.detail for item in report.candidates},
        run_id=args.run_id,
        tier=RiskTier(args.risk_tier),
        rate=args.sample_rate,
        shadow_models=list(args.shadow_model),
        model_of={
            item.item_id: policy.model_for(Phase.triage) for item in report.candidates
        },
    )
    warnings.extend(governance.warnings)
    audit_log.record(
        "governance_reviewed",
        tier=governance.tier.value,
        rate=governance.rate,
        decisions=len(governance.decisions),
        sampled=len(governance.sampled),
        shadowed=len(governance.shadowed),
    )
    if egress.denied:
        # A blocked destination is the clearest signal that something tried to
        # reach somewhere nobody configured, and an unattended run has nobody
        # watching it happen.
        warnings.append(
            f"egress: {len(egress.denied)} call(s) were refused to "
            f"{', '.join(sorted(set(egress.denied))[:5])}"
        )
        audit_log.record("egress_denied", count=len(egress.denied))

    if args.siem:
        try:
            path, count = siem_export(
                audit_path, args.siem, args.siem_format, f"{args.target}/{args.run_id}"
            )
            print(f"  siem      : {path} ({count} event(s), {args.siem_format})")
        except (OSError, ValueError) as exc:
            warnings.append(f"siem: trail not exported ({exc})")

    if args.report:
        try:
            path = write_report(
                report, args.report, summary, lifecycle_report, analysis, movement
            )
            print(f"  report    : {path}")
        except OSError as exc:
            warnings.append(f"report: not written ({exc})")

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print_report(report)
        if summary is not None:
            print(
                f"  queue     : {summary.findings} finding(s), "
                f"{summary.kev_findings} KEV, top score "
                f"{summary.top_score if summary.top_score is not None else '-'}"
            )
            if summary.csv_path:
                print(f"  csv       : {summary.csv_path}")
        if governance.sampled or governance.shadowed:
            print(
                f"  review    : {len(governance.sampled)} of "
                f"{len(governance.decisions)} decision(s) flagged for a human "
                f"({governance.tier.value} tier), {len(governance.shadowed)} shadowed"
            )
        if movement is not None:
            print(
                f"  movement  : {movement['increased']} worse, "
                f"{movement['decreased']} better, {movement['new']} new, "
                f"{movement['unchanged']} unchanged"
            )
        if lifecycle_report is not None and lifecycle_report.feed_loaded:
            counts = lifecycle_report.counts()
            print(
                f"  lifecycle : {counts['eol']} EOL, {counts['eos']} EOS, "
                f"{counts['deprecated']} deprecated, {counts['unknown']} unknown"
            )
        if analysis is not None:
            print(
                f"  analysis  : {len(analysis.chains)} chain(s), "
                f"{len(analysis.drafted)} PoC draft(s) in {analysis.model_calls} call(s)"
            )
            if analysis.pocs_path:
                print(f"  pack      : {analysis.pocs_path}")
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    return EXIT_OK if report.is_complete() else EXIT_INCOMPLETE


def _run_lifecycle(
    args: argparse.Namespace,
    summary: TriageSummary,
    repo: str,
    audit_log: AuditLog,
) -> LifecycleReport:
    """Check every component for deprecation, end of support and end of life.

    Runs whenever there is a queue, with or without a feed: the no-feed path
    reports that nothing was checked, which is the whole point. Silence here
    would be indistinguishable from a fleet with no unmaintained dependencies.
    """
    feed_path = args.lifecycle_feed or (args.feeds / "lifecycle.json" if args.feeds else None)
    feed = None
    warnings: list[str] = []
    if feed_path is not None and Path(feed_path).exists():
        try:
            feed = load_feed(Path(feed_path))
        except LifecycleError as exc:
            warnings.append(f"lifecycle: feed not loaded ({exc})")
    elif feed_path is not None:
        warnings.append(f"lifecycle: no feed at {feed_path}")

    inventory = _load_inventory(args.inventory, warnings)
    snyk_path = args.snyk_export
    if snyk_path is not None:
        try:
            found = load_snyk(Path(snyk_path))
            warnings.extend(found.warnings)
            known = set(inventory)
            inventory += [entry for entry in found.tuples() if entry not in known]
        except FeedError as exc:
            warnings.append(
                f"snyk: export not read ({exc}) — its components are not "
                "lifecycle-checked, which is not the same as finding them supported"
            )
    report = assess(summary.queue, feed, repo=repo, inventory=inventory)
    report.warnings[:0] = warnings
    if report.findings:
        # lifecycle findings have no CVE behind them, so they exist only if this
        # stage puts them in the queue
        summary.queue.extend(report.findings)
        summary.findings = len(summary.queue)
    counts = report.counts()
    audit_log.record(
        "lifecycle_assessed",
        eol=counts["eol"],
        eos=counts["eos"],
        deprecated=counts["deprecated"],
        unknown=counts["unknown"],
        supported=counts["supported"],
        adjusted=report.adjusted,
        feed_loaded=report.feed_loaded,
    )
    return report


def _load_inventory(path: Path | None, warnings: list[str]) -> list[tuple[str, str, str]]:
    """Read a component inventory: ``[{ecosystem, name, version}, …]``."""
    if path is None:
        return []
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(f"lifecycle: inventory not read ({exc}) — nothing added from it")
        return []
    entries = raw.get("components") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        warnings.append("lifecycle: inventory has no component list — nothing added from it")
        return []
    out: list[tuple[str, str, str]] = []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name"):
            out.append(
                (
                    str(entry.get("ecosystem", "")),
                    str(entry["name"]),
                    str(entry.get("version", "")),
                )
            )
    return out


def _run_analysis(
    args: argparse.Namespace,
    summary: TriageSummary,
    driver: Driver,
    repo: str,
    run_dir: Path,
    audit_log: AuditLog,
) -> AnalysisSummary | None:
    """Run the advisory stages, spending from the run's own ledger."""
    if not (args.chains or args.pocs):
        return None
    deployment = args.analysis_model or args.model or ""
    if not deployment:
        return AnalysisSummary(
            warnings=[
                "analysis: no deployment for --chains/--pocs — pass --analysis-model "
                "or --model. Nothing was analysed"
            ]
        )
    result = analyse(
        summary.queue,
        dispatcher=driver.dispatcher,
        deployment=deployment,
        out_dir=run_dir,
        repo=repo,
        want_chains=args.chains,
        want_pocs=args.pocs,
    )
    audit_log.record(
        "analysis_finished",
        chains=len(result.chains),
        pocs_drafted=len(result.drafted),
        pocs_undrafted=len(result.pocs_undrafted),
        chains_unanalysed=len(result.chains_unanalysed),
        calls=result.model_calls,
    )
    return result


def _print_report(report: RunReport) -> None:
    print(f"run {report.ref}: phase={report.phase.value} calls={report.model_calls}")
    print(
        f"  scenarios : {report.scenarios_completed} completed, "
        f"{report.scenarios_parked} parked, {report.scenarios_unfunded} unfunded "
        f"of {len(report.scenarios)}"
    )
    triaged = sum(
        1 for item in report.candidates if item.disposition == Disposition.completed
    )
    print(f"  candidates: {triaged} triaged of {len(report.candidates)}")
    print(f"  reviewed  : {report.reviewed_fraction:.0%} of the backlog")
    if report.sarif_path:
        print(f"  sarif     : {report.sarif_path}")
    if report.redactions:
        print(f"  redacted  : {report.redactions} credential-shaped value(s)")


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    resolved = env if env is not None else os.environ
    result = args.func(args, resolved)
    return int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
