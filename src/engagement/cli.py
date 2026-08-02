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

from .analysis import AnalysisSummary, analyse, draft_requested, to_markdown
from .api import ApiConfig, ControlPlane, build_app
from .audit import AuditLog, FileSink, default_audit_path, read_events
from .auth import OidcVerifier, RoleMapping, StaticVerifier, TokenVerifier
from .budget import Budget, Ledger
from .console import render as render_console
from .contracts import Disposition, Phase, RunRef, RunReport
from .decisions import JsonlDecisionStore
from .dispatch import Dispatcher
from .driver import Driver, Policy
from .egress import build_policy
from .export import movement_summary, read_manifest, write_manifest, write_queue
from .feeds import CISA_KEV_URL, FeedError, fetch_kev, load_snyk, write_kev
from .governance import RiskTier, review
from .identity import Action, Role, Unauthorized, authorize, machine, operator
from .lifecycle import LifecycleError, LifecycleReport, assess, load_feed
from .models import SingleVendorError, Task, build_plan, check_two_vendor_passes, render_plan
from .preflight import PreflightReport, deployments_for
from .preflight import check as preflight_check
from .providers import ModelProvider, ProviderError, build_provider
from .report import write as write_report
from .runs import RunLauncher
from .secrets import SecretError, SecretResolver, resolve_optional
from .secrets import build_plan as build_secret_plan
from .serving import ManifestQueue, RunPocDrafter
from .siem import FORMATS, summarize
from .siem import export as siem_export
from .signals import SignalReport, apply_exposure, load_boundaries
from .threatmodel import write as write_threat_model
from .triage import TriageError, TriageSummary, ingest_run
from .workspace import CliWorkspace, WorkspaceError, seed_workspace, vendored_workspace

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_INCOMPLETE = 3

#: Provider group or app-role values mapped to this system's roles. Duplicated
#: from `asgi` rather than shared because the two entrypoints serve different
#: deployments and one changing its directory should not silently change the
#: other; `test_wiring` asserts they agree.
CONSOLE_ROLE_CLAIMS = {
    "Engagement.Scanner": Role.scanner,
    "Engagement.Analyst": Role.analyst,
    "Engagement.Approver": Role.approver,
    "Engagement.Admin": Role.admin,
}


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
    run.add_argument(
        "--router-chunk-units",
        type=int,
        default=Policy().router_chunk_units,
        help=(
            "Routing units per router call. The backlog is split across calls "
            "and merged; lower this if a chunk keeps overrunning its output "
            "ceiling. Note --max-tokens is a whole-run token budget, not this."
        ),
    )
    run.add_argument(
        "--router-max-output-tokens",
        type=int,
        default=Policy().router_max_output_tokens,
        help="Output ceiling for one router call (default sized for a chunk).",
    )
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
        help="Draft a proof of concept for each finding that comes out critical. "
        "Never executed. Anything below critical: see the draft-poc command.",
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
    run.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the check that every configured deployment exists. The check "
        "costs one listing call and refuses before anything is spent.",
    )
    run.set_defaults(func=_cmd_run)

    pre = sub.add_parser(
        "preflight",
        help="Check that every configured deployment exists, before spending.",
    )
    pre.add_argument("--model", default="", help="Deployment for every phase.")
    pre.add_argument("--router-model", default="")
    pre.add_argument("--expert-model", default="")
    pre.add_argument("--triage-model", default="")
    pre.add_argument("--analysis-model", default="")
    pre.add_argument("--second-model", default="")
    pre.set_defaults(func=_cmd_preflight)

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

    secrets = sub.add_parser(
        "secrets", help="Show where each secret comes from, without reading any."
    )
    secrets.set_defaults(func=_cmd_secrets)

    console = sub.add_parser(
        "console",
        help="Serve the analyst console over a run directory.",
    )
    console.add_argument("run_dir", type=Path, help="Run directory holding queue.json.")
    console.add_argument("--host", default="127.0.0.1")
    console.add_argument("--port", type=int, default=8000)
    console.add_argument(
        "--decisions",
        type=Path,
        default=None,
        help="Decision log (default: <run_dir>/decisions.jsonl).",
    )
    console.add_argument(
        "--model",
        default="",
        help="Deployment for on-request PoC drafts. Omitted, drafting is off.",
    )
    console.add_argument(
        "--dev-token",
        default="",
        help="Accept this bearer token as a local analyst+approver, for "
        "development only. Refused unless --host is a loopback address.",
    )
    console.add_argument(
        "--allow-runs",
        action="store_true",
        help="Let a signed-in scanner start scans from the console. Off by "
        "default: a control plane serving a queue has no business starting "
        "runs, and this one reads repositories and spends money.",
    )
    console.add_argument(
        "--run-max-calls",
        type=int,
        default=200,
        help="Ceiling for a run started from the console. The deployment's "
        "choice, never the caller's.",
    )
    console.set_defaults(func=_cmd_console)

    poc = sub.add_parser(
        "draft-poc",
        help="Draft a PoC for findings a run did not draft for automatically.",
    )
    poc.add_argument("run_dir", type=Path, help="Run directory holding queue.json.")
    poc.add_argument(
        "--finding",
        action="append",
        default=[],
        metavar="ID",
        help="Finding id to draft for. Repeat, or pass a comma-separated list.",
    )
    poc.add_argument("--model", default="", help="Deployment to draft with.")
    poc.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Where to write the pack (default: <run_dir>/pocs-requested.md).",
    )
    poc.add_argument("--max-calls", type=int, default=None)
    poc.add_argument("--audit", type=Path, default=None)
    poc.set_defaults(func=_cmd_draft_poc)

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
    plan.add_argument(
        "--critical",
        type=int,
        default=None,
        help="Findings expected to come out critical — only those are drafted "
        "for. Omitted, the projection assumes every finding is, and over-projects.",
    )
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


def _cmd_secrets(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Print the resolution plan. Reads no secret and prints no value."""
    del args
    plan = build_secret_plan(env)
    for line in plan.describe():
        print(f"  {line}")
    hosts = plan.vault_hosts
    print(f"  egress    : {', '.join(hosts) if hosts else 'no vault configured'}")
    if hosts:
        allowed = build_policy(env).allowed
        missing = [h for h in hosts if h not in allowed]
        print(
            "  allowlist : ok"
            if not missing
            else f"  allowlist : MISSING {', '.join(missing)} — the fetch would be refused"
        )
    return EXIT_OK


def _run_preflight(
    provider: ModelProvider,
    deployments: dict[str, str],
    quiet: bool = False,
) -> PreflightReport:
    """Ask the provider what it serves and report against what is configured."""
    report = preflight_check(deployments, provider.list_deployments())
    if not quiet:
        for line in report.describe():
            print(line, file=sys.stderr if not report.ok else sys.stdout)
    for warning in report.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return report


def _cmd_preflight(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Check the deployments a run would use, without running it."""
    deployments = deployments_for(
        model=args.model or env.get("ENGAGEMENT_MODEL", ""),
        router_model=args.router_model,
        expert_model=args.expert_model,
        triage_model=args.triage_model,
        analysis_model=args.analysis_model,
        second_model=args.second_model,
    )
    if not deployments:
        print(
            "nothing to check: no deployment named. Pass --model or set "
            "ENGAGEMENT_MODEL.",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    try:
        api_key = resolve_optional(SecretResolver(env), build_secret_plan(env).refs[0])
        provider = build_provider(env, egress=build_policy(env), api_key=api_key or None)
    except (SecretError, ProviderError) as exc:
        print(f"cannot preflight: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    report = _run_preflight(provider, deployments)
    if not report.ok:
        return EXIT_CONFIG
    # An unchecked result is not a pass and not a failure. Exit 3 is this CLI's
    # existing "finished, but not cleanly" code, and a scheduler that treats it
    # as success is making the same mistake as one that ignores a parked run.
    return EXIT_OK if report.checked else EXIT_INCOMPLETE


def _workspace_root(run_dir: Path) -> Path:
    """`<workspace>/runs/<target>/<run-id>` back to `<workspace>`.

    Derived rather than asked for, so the operator names one path and the
    console can still discover sibling runs. A run directory that is not of
    that shape yields itself, which means the console serves exactly the run it
    was pointed at — the previous behaviour, and the safe one.
    """
    resolved = run_dir.resolve()
    if len(resolved.parents) >= 3 and resolved.parent.parent.name == "runs":
        return resolved.parents[2]
    return resolved


def _cmd_console(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Serve the analyst console over one run.

    Two ways to authenticate, and the second one is fenced. Normally the
    console verifies OIDC tokens exactly as the deployed control plane does.
    ``--dev-token`` accepts one fixed string instead, so an analyst can work a
    queue on their own machine without standing up an identity provider — and
    it is **refused unless the listener is on loopback**, because the whole
    point of the identity model is that "human" has a referent, and a shared
    string reachable from a network is not one.
    """
    if not (args.run_dir / "queue.json").exists():
        print(
            f"no queue manifest at {args.run_dir / 'queue.json'} — the console "
            "shows a run's findings, so the run has to have produced some",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    loopback = args.host in {"127.0.0.1", "::1", "localhost"}
    if args.dev_token and not loopback:
        print(
            "refusing to serve: --dev-token is a shared string, not an "
            f"identity, and --host {args.host} is reachable from a network. "
            "Bind to 127.0.0.1, or configure OIDC.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    verifier: TokenVerifier
    if args.dev_token:
        # The development principal is granted exactly what this invocation
        # enabled: `scanner` only when `--allow-runs` was passed. A token that
        # always carried it would make the opt-in meaningless locally, which is
        # where the opt-in is most likely to be tested.
        dev_roles = ["Engagement.Analyst", "Engagement.Approver"]
        if args.allow_runs:
            dev_roles.append("Engagement.Scanner")
        verifier = StaticVerifier(
            tokens={
                args.dev_token: {
                    "oid": f"dev:{env.get('ENGAGEMENT_OPERATOR', 'local')}",
                    "name": env.get("ENGAGEMENT_OPERATOR", "local operator"),
                    "roles": dev_roles,
                }
            }
        )
        print("warning: serving with a development token; identity is asserted, "
              "not verified", file=sys.stderr)
    else:
        missing = [
            name
            for name in ("ENGAGEMENT_JWKS_URI", "ENGAGEMENT_ISSUER", "ENGAGEMENT_API_AUDIENCE")
            if not env.get(name, "").strip()
        ]
        if missing:
            print(
                "refusing to serve: " + ", ".join(missing) + " not set. Without "
                "them every token would be accepted on trust. Pass --dev-token "
                "on a loopback host to work locally instead.",
                file=sys.stderr,
            )
            return EXIT_CONFIG
        verifier = OidcVerifier(
            jwks_uri=env["ENGAGEMENT_JWKS_URI"],
            issuer=env["ENGAGEMENT_ISSUER"],
            audience=env["ENGAGEMENT_API_AUDIENCE"],
        )

    drafter = None
    deployment = args.model or env.get("ENGAGEMENT_MODEL", "")
    if deployment:
        try:
            api_key = resolve_optional(
                SecretResolver(env), build_secret_plan(env).refs[0]
            )
            provider = build_provider(
                env, egress=build_policy(env), api_key=api_key or None
            )
        except (SecretError, ProviderError) as exc:
            print(f"refusing to serve: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        drafter = RunPocDrafter(args.run_dir, provider, deployment)

    runner = None
    workspace = _workspace_root(args.run_dir)
    if args.allow_runs:
        if not deployment:
            print(
                "refusing to serve: --allow-runs needs a deployment to run "
                "with. Pass --model or set ENGAGEMENT_MODEL.",
                file=sys.stderr,
            )
            return EXIT_CONFIG
        runner = RunLauncher(
            workspace=workspace,
            env=dict(env),
            model=deployment,
            max_calls=args.run_max_calls,
        )

    plane = ControlPlane(
        verifier,
        JsonlDecisionStore(args.decisions or args.run_dir / "decisions.jsonl"),
        ApiConfig(
            tenant=env.get("ENGAGEMENT_TENANT_ID", ""),
            authorize_url=env.get("ENGAGEMENT_AUTHORIZE_URL", ""),
            token_url=env.get("ENGAGEMENT_TOKEN_URL", ""),
            client_id=env.get("ENGAGEMENT_CLIENT_ID", ""),
            api_audience=env.get("ENGAGEMENT_API_AUDIENCE", ""),
            environment=env.get("ENGAGEMENT_ENVIRONMENT", str(args.run_dir.name)),
            allow_token_entry=bool(args.dev_token),
        ),
        RoleMapping(mapping=CONSOLE_ROLE_CLAIMS),
        drafter,
        ManifestQueue(args.run_dir, workspace=workspace),
        runner,
    )

    try:
        import uvicorn
    except ImportError:
        print(
            "serving the console needs the 'api' extra: pip install "
            "'codescan-engagement[api]'",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    print(f"console on http://{args.host}:{args.port}/ over {args.run_dir}")
    print(f"  workspace : {workspace}")
    print(f"  drafting  : {'on (' + deployment + ')' if drafter else 'off'}")
    print(
        "  runs      : "
        + (f"on, ceiling {args.run_max_calls} calls" if runner else "off")
    )
    uvicorn.run(
        build_app(plane, console_html=render_console()),
        host=args.host,
        port=args.port,
        log_level="warning",
    )
    return EXIT_OK


def _cmd_draft_poc(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    """Draft PoCs for findings the automatic critical-only rule passed over.

    The command exists because the rule is deliberately narrow: a run drafts for
    what came out critical, and an analyst who wants one for anything else asks
    for it here, by id, against the queue that run produced.
    """
    wanted = [
        item.strip()
        for raw in args.finding
        for item in str(raw).split(",")
        if item.strip()
    ]
    if not wanted:
        print(
            "refusing to draft: name at least one finding with --finding",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    try:
        principal = operator(env.get("ENGAGEMENT_OPERATOR", ""))
        authorize(principal, Action.draft_poc)
    except Unauthorized as exc:
        print(f"refusing to draft: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    manifest = args.run_dir / "queue.json"
    if not manifest.exists():
        print(
            f"no queue manifest at {manifest} — a requested draft is made against "
            "a run's own findings, so the run has to have produced some",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    try:
        findings = read_manifest(manifest)
    except (OSError, ValueError) as exc:
        print(f"could not read {manifest}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    deployment = args.model or env.get("ENGAGEMENT_MODEL", "")
    if not deployment:
        print(
            "refusing to draft: no model deployment — pass --model or set "
            "ENGAGEMENT_MODEL",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    egress = build_policy(env)
    try:
        api_key = resolve_optional(SecretResolver(env), build_secret_plan(env).refs[0])
        provider = build_provider(env, egress=egress, api_key=api_key or None)
    except (SecretError, ProviderError) as exc:
        print(f"refusing to draft: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        budget = Budget(
            max_calls=_bound(
                args.max_calls, env, "ENGAGEMENT_MAX_CALLS", Budget().max_calls
            )
        )
    except ValueError as exc:
        print(f"refusing to draft: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    audit_log = AuditLog(FileSink(args.audit or args.run_dir / "audit.jsonl"))
    audit_log.record(
        "poc_requested",
        actor=principal.actor(),
        findings=len(wanted),
        deployment=deployment,
    )
    summary = draft_requested(
        findings, Dispatcher(provider, Ledger(budget=budget), audit_log), deployment, wanted
    )
    audit_log.record(
        "poc_request_finished",
        actor=principal.actor(),
        drafted=len(summary.drafted),
        undrafted=len(summary.pocs_undrafted),
        calls=summary.model_calls,
    )

    out = args.out or args.run_dir / "pocs-requested.md"
    pack = to_markdown(summary, findings)
    if pack:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(pack, encoding="utf-8")
        summary.pocs_path = str(out)
        print(f"{len(summary.drafted)} draft(s) -> {out}")
    else:
        print("nothing was drafted")
    print(f"  requested : {len(wanted)}")
    print(f"  calls     : {summary.model_calls}")
    for warning in summary.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return EXIT_OK if summary.drafted else EXIT_ERROR


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
        critical_findings=args.critical,
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
    # Order matters: the allowlist is built first (it already contains the
    # vault host, derived from the same configuration), then the secret is
    # fetched through it, then the provider is built with the resolved key.
    egress = build_policy(env)
    secret_plan = build_secret_plan(env)
    resolver = SecretResolver(env)
    try:
        api_key = resolve_optional(resolver, secret_plan.refs[0])
    except SecretError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        provider = build_provider(env, egress=egress, api_key=api_key or None)
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
        router_chunk_units=args.router_chunk_units,
        router_max_output_tokens=args.router_max_output_tokens,
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

    # Before the workspace is touched and before a single call is dispatched:
    # a run that discovers a missing deployment three phases in has already
    # spent everything it took to get there.
    if not args.no_preflight:
        checked = _run_preflight(
            provider,
            deployments_for(
                model=policy.model,
                router_model=policy.router_model,
                expert_model=policy.expert_model,
                triage_model=policy.triage_model,
                analysis_model=args.analysis_model,
                second_model=policy.second_expert_model,
            ),
            quiet=True,
        )
        if not checked.ok:
            for line in checked.describe():
                print(line, file=sys.stderr)
            return EXIT_CONFIG
        if not checked.checked:
            print(
                "warning: preflight could not verify the deployments; the run "
                "is proceeding unchecked",
                file=sys.stderr,
            )

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
        # exposure first: PoC drafting selects on the *final* score, so every
        # deterministic adjustment has to be in before the advisory stages read
        # it. Chaining is the one exception — it is produced by the chain stage
        # itself, so `analyse` applies it between its own two stages.
        boundaries = load_boundaries(run_dir / "recon-output" / "recon-items.jsonl")
        signal_report = apply_exposure(summary.queue, boundaries)
        analysis = _run_analysis(
            args, summary, driver, repo, run_dir, audit_log, signal_report
        )
        if analysis is not None:
            warnings.extend(analysis.warnings)
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

        # Written last, from every stage's output, and with no model call: the
        # threat model is a projection of evidence already gathered, so it has
        # to come after the evidence is complete.
        report.threat_model_path = str(
            write_threat_model(
                report,
                summary.queue,
                out_dir=run_dir,
                repo=repo,
                exposure=boundaries,
                lifecycle=lifecycle_report,
                analysis=analysis,
            )
        )

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
    signals: SignalReport,
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
        signals=signals,
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
    if report.threat_model_path:
        print(f"  threat    : {report.threat_model_path}")
    if report.redactions:
        print(f"  redacted  : {report.redactions} credential-shaped value(s)")


def load_dotenv(path: Path, env: Mapping[str, str]) -> dict[str, str]:
    """Merge a `.env` beside the invocation *under* the real environment.

    **A real environment variable always wins.** An operator who exported a
    value meant it, and a file that silently overrode it would make the actual
    configuration of a run unknowable from the outside — the same failure this
    package refuses a run over when two providers are configured.

    Parsed here rather than with a dependency: the format needed is `KEY=value`
    with `#` comments, and a short reader is less surface than a package. A
    malformed line is skipped rather than fatal — a `.env` is an operator
    convenience, and refusing to start over a stray line would be worse than
    ignoring it. Nothing read here is ever printed: `engagement secrets` shows
    where a value comes from, never what it is.
    """
    merged = dict(env)
    if not path.exists():
        return merged
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key and key not in env:
            merged[key] = value.strip().strip("\"'")
    return merged


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    resolved = env if env is not None else load_dotenv(Path(".env"), os.environ)
    result = args.func(args, resolved)
    return int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
