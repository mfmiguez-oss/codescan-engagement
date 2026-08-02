"""The analyst console: the page, the routes behind it, and what it refuses.

The console is the first surface in this package that a person can *write*
from, so the tests that matter are the ones about authority: that the page
never decides who may do what, that the queue it shows is joined to the store
rather than to whatever was last clicked, and that the one development
shortcut is fenced to loopback.

The page itself is checked for the property that its content is
attacker-influenced by construction — a queue carries titles and paths
recovered from a repository under review, so nothing may be written into the
document as markup.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from engagement import cli
from engagement.api import SECURITY_HEADERS, ApiConfig, ControlPlane, Problem
from engagement.auth import RoleMapping, StaticVerifier
from engagement.console import render
from engagement.contracts import ScoredFinding
from engagement.decisions import MemoryDecisionStore
from engagement.export import to_rows, write_manifest
from engagement.identity import Principal, Role, ValidationState
from engagement.serving import ManifestQueue

MAPPING = RoleMapping(
    mapping={
        "Engagement.Analyst": Role.analyst,
        "Engagement.Approver": Role.approver,
        "Engagement.Scanner": Role.scanner,
    }
)


class _Queue:
    def __init__(self, findings: list[dict[str, Any]] | None = None) -> None:
        self._findings = findings if findings is not None else [
            {"id": "F-1", "title": "SQL injection", "severity": "critical"}
        ]

    def findings(self, run: str | None = None) -> list[dict[str, Any]]:
        if run == "missing/run":
            raise ValueError("no such run")
        return self._findings

    def runs(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "acme/run-001",
                "target": "acme",
                "run_id": "run-001",
                "findings": len(self._findings),
                "modified": 0.0,
                "has_threat_model": True,
            }
        ]

    def detail(self, fingerprint: str, run: str | None = None) -> dict[str, Any]:
        finding = next(
            (row for row in self._findings if row.get("id") == fingerprint), None
        )
        return {
            "finding": finding,
            "chains": [],
            "chains_ran": False,
            "poc": None,
            "pocs_ran": False,
        }


def _claims(*roles: str, oid: str = "oid-1") -> dict[str, object]:
    return {"oid": oid, "sub": "p", "name": "Ada", "tid": "acme", "roles": list(roles)}


def _plane(queue: Any = None, **config: object) -> tuple[ControlPlane, MemoryDecisionStore]:
    store = MemoryDecisionStore()
    verifier = StaticVerifier(
        tokens={
            "analyst": _claims("Engagement.Analyst"),
            "approver": _claims("Engagement.Analyst", "Engagement.Approver", oid="oid-2"),
            "scanner": _claims("Engagement.Scanner", oid="oid-3"),
            "stranger": _claims(oid="oid-4"),
        }
    )
    plane = ControlPlane(
        verifier,
        store,
        ApiConfig(tenant="acme", **config),  # type: ignore[arg-type]
        MAPPING,
        None,
        queue,
    )
    return plane, store


# -- the page ----------------------------------------------------------------


def test_the_console_is_one_self_contained_document() -> None:
    """Same rule as the report: it has to work behind a private endpoint with
    no route to a CDN, and the CSP can then forbid every other origin."""
    page = render()

    for absent in ("http://", "https://", "//cdn", "src="):
        assert absent not in page, f"the console reaches for {absent}"


def _code(page: str) -> str:
    """The page with its own comments removed.

    Checked against the code rather than the document because the comments
    explain precisely which sinks are avoided, and a test that searched the
    whole page would be failed by its own rationale.
    """
    lines = [line for line in page.splitlines() if not line.strip().startswith("//")]
    return "\n".join(lines)


def test_the_page_never_writes_queue_data_as_markup() -> None:
    """A finding title is attacker-influenced text. The page builds nodes and
    assigns textContent; an innerHTML assignment here would be an XSS sink fed
    straight from a repository under review."""
    code = _code(render())

    assert "innerHTML" not in code
    assert "insertAdjacentHTML" not in code
    assert "document.write" not in code
    assert "textContent" in code


def test_the_token_is_never_put_in_persistent_storage() -> None:
    """In memory only: a value the page must attach deliberately cannot be
    replayed by a cross-site request."""
    code = _code(render())

    assert "localStorage" not in code


def test_nothing_in_the_page_evaluates_a_string() -> None:
    code = _code(render())

    assert "eval(" not in code
    assert "new Function" not in code


# -- what the server tells the page ------------------------------------------


def test_the_page_is_told_which_states_it_may_offer() -> None:
    """The console renders this list rather than deciding it, so an analyst is
    never shown a control the server will refuse."""
    plane, _ = _plane(_Queue())

    analyst = plane.whoami("Bearer analyst")["may_set"]
    approver = plane.whoami("Bearer approver")["may_set"]

    assert ValidationState.confirmed.value in analyst
    assert ValidationState.risk_accepted.value not in analyst
    assert ValidationState.risk_accepted.value in approver


def test_hiding_a_control_is_a_courtesy_and_the_server_still_refuses() -> None:
    """The point of the previous test is presentation. This is the control."""
    plane, store = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.set_state("Bearer analyst", "F-1", b'{"state": "risk_accepted"}')

    assert exc.value.status == 403
    assert store.get("F-1") is None


def test_a_scanner_is_told_it_may_set_nothing() -> None:
    plane, _ = _plane(_Queue())

    assert plane.whoami("Bearer scanner")["may_set"] == []


# -- the queue ---------------------------------------------------------------


def test_the_queue_carries_each_findings_current_decision() -> None:
    plane, store = _plane(_Queue())
    plane.set_state("Bearer approver", "F-1", b'{"state": "resolved"}')

    rows = plane.list_findings("Bearer analyst")["findings"]

    assert rows[0]["decision"]["state"] == "resolved"
    assert rows[0]["title"] == "SQL injection"


def test_a_finding_nobody_decided_is_null_not_new() -> None:
    """"Nobody has looked at this" and "somebody set it to new" are different
    facts, and defaulting one to the other loses the distinction."""
    plane, _ = _plane(_Queue())

    assert plane.list_findings("Bearer analyst")["findings"][0]["decision"] is None


def test_the_queue_needs_a_credential() -> None:
    plane, _ = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.list_findings(None)

    assert exc.value.status == 401


def test_a_principal_with_no_roles_cannot_read_the_queue() -> None:
    plane, _ = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.list_findings("Bearer stranger")

    assert exc.value.status == 403


def test_a_deployment_with_no_queue_says_so() -> None:
    plane, _ = _plane(None)

    with pytest.raises(Problem) as exc:
        plane.list_findings("Bearer analyst")

    assert exc.value.status == 503


def test_the_public_config_carries_no_secret() -> None:
    """It is unauthenticated, so what it contains is what anyone can read."""
    plane, _ = _plane(_Queue(), client_id="app-1", authorize_url="https://idp/authorize")

    config = plane.public_config()

    assert config["client_id"] == "app-1"
    assert not any(
        key in config for key in ("api_key", "secret", "client_secret", "token")
    )


# -- reading a real run ------------------------------------------------------


def test_the_queue_is_read_from_the_run_and_re_read_each_time(tmp_path: Path) -> None:
    """Re-read rather than cached: a run can be re-executed under an open
    console, and a silently stale queue is worse than one that changes."""
    finding = ScoredFinding(id="f1", repo="acme/app", title="XSS", risk_score=91.0)
    write_manifest(to_rows([finding], "run-1"), tmp_path / "queue.json", "run-1")
    queue = ManifestQueue(tmp_path)

    assert [row["id"] for row in queue.findings()] == ["f1"]

    second = ScoredFinding(id="f2", repo="acme/app", title="SSRF", risk_score=70.0)
    write_manifest(
        to_rows([finding, second], "run-2"), tmp_path / "queue.json", "run-2"
    )

    assert len(queue.findings()) == 2


def test_a_run_with_no_manifest_is_an_empty_queue_not_a_crash(tmp_path: Path) -> None:
    assert ManifestQueue(tmp_path).findings() == []


# -- the development shortcut is fenced --------------------------------------


def _console_args(tmp_path: Path, **extra: object) -> object:
    argv = ["console", str(tmp_path)]
    for key, value in extra.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    return cli._build_parser().parse_args(argv)


def test_a_shared_dev_token_is_refused_off_loopback(tmp_path: Path) -> None:
    """The whole identity model rests on "human" having a referent. A fixed
    string reachable from a network is not one."""
    (tmp_path / "queue.json").write_text('{"findings": []}', encoding="utf-8")
    args = _console_args(tmp_path, dev_token="letmein", host="0.0.0.0")

    assert cli._cmd_console(args, {}) == cli.EXIT_CONFIG  # type: ignore[arg-type]


def test_serving_without_oidc_or_a_dev_token_is_refused(tmp_path: Path) -> None:
    """Without an issuer and audience every token would be accepted on trust."""
    (tmp_path / "queue.json").write_text('{"findings": []}', encoding="utf-8")

    assert cli._cmd_console(_console_args(tmp_path), {}) == cli.EXIT_CONFIG  # type: ignore[arg-type]


def test_the_console_refuses_a_run_with_no_queue(tmp_path: Path) -> None:
    args = _console_args(tmp_path, dev_token="letmein")

    assert cli._cmd_console(args, {}) == cli.EXIT_CONFIG  # type: ignore[arg-type]


# -- detail, history and bulk ------------------------------------------------


def test_the_detail_joins_four_sources_so_the_page_makes_one_request() -> None:
    plane, _ = _plane(_Queue())
    plane.set_state("Bearer analyst", "F-1", b'{"state": "confirmed"}')

    detail = plane.finding_detail("Bearer analyst", "F-1")

    assert detail["finding"]["title"] == "SQL injection"
    assert detail["decision"]["state"] == "confirmed"
    assert detail["history"][0]["state"] == "confirmed"
    assert "chains" in detail and "poc" in detail


def test_the_detail_distinguishes_no_chains_from_no_chain_discovery() -> None:
    """"No chain mentions this finding" and "chain discovery never ran" are
    different facts, and a page told only the first would state the second."""
    plane, _ = _plane(_Queue())

    detail = plane.finding_detail("Bearer analyst", "F-1")

    assert detail["chains_ran"] is False
    assert detail["pocs_ran"] is False


def test_a_detail_request_for_an_unknown_finding_is_404() -> None:
    plane, _ = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.finding_detail("Bearer analyst", "nope")

    assert exc.value.status == 404


def test_history_is_every_decision_not_just_the_current_one() -> None:
    """"Who closed this, and when" is asked about findings that are currently
    open, which an overwriting store cannot answer."""
    plane, _ = _plane(_Queue())
    plane.set_state("Bearer analyst", "F-1", b'{"state": "under_investigation"}')
    plane.set_state("Bearer approver", "F-1", b'{"state": "resolved"}')

    history = plane.decision_history("Bearer analyst", "F-1")["history"]

    assert [item["state"] for item in history] == ["under_investigation", "resolved"]


def test_history_for_a_finding_nobody_decided_is_empty_not_an_error() -> None:
    plane, _ = _plane(_Queue())

    assert plane.decision_history("Bearer analyst", "F-9")["history"] == []


def test_a_bulk_change_reports_each_finding_separately() -> None:
    """A count alone would hide that a machine proposal lost on three of them."""
    plane, _ = _plane(_Queue())

    result = plane.set_states(
        "Bearer approver",
        b'{"state": "resolved", "fingerprints": ["F-1", "F-2", "F-3"]}',
    )

    assert result["total"] == 3
    assert result["applied"] == 3
    assert {row["fingerprint"] for row in result["results"]} == {"F-1", "F-2", "F-3"}


def test_a_bulk_change_is_authorized_once_before_anything_is_written() -> None:
    """A refusal that arrived after some of the work was done would leave the
    caller unable to say which half happened."""
    plane, store = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.set_states(
            "Bearer analyst",
            b'{"state": "risk_accepted", "fingerprints": ["F-1", "F-2"]}',
        )

    assert exc.value.status == 403
    assert store.get("F-1") is None and store.get("F-2") is None


def test_a_bulk_change_deduplicates_its_input() -> None:
    plane, _ = _plane(_Queue())

    result = plane.set_states(
        "Bearer approver",
        b'{"state": "resolved", "fingerprints": ["F-1", "F-1", "F-1"]}',
    )

    assert result["total"] == 1


def test_an_empty_bulk_request_is_refused() -> None:
    plane, _ = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.set_states("Bearer approver", b'{"state": "resolved", "fingerprints": []}')

    assert exc.value.status == 400


def test_a_bulk_request_is_bounded() -> None:
    """A caller should not be able to turn one request into ten thousand."""
    from engagement.api import MAX_BULK

    plane, _ = _plane(_Queue())
    ids = json.dumps([f"F-{n}" for n in range(MAX_BULK + 1)])

    with pytest.raises(Problem) as exc:
        plane.set_states(
            "Bearer approver",
            f'{{"state": "resolved", "fingerprints": {ids}}}'.encode(),
        )

    assert exc.value.status == 413


# -- the run picker ----------------------------------------------------------


def test_the_console_lists_the_runs_it_can_serve() -> None:
    plane, _ = _plane(_Queue())

    runs = plane.list_runs("Bearer analyst")["runs"]

    assert runs[0]["id"] == "acme/run-001"


def test_an_unknown_run_is_404_rather_than_an_empty_queue() -> None:
    """An empty queue for a run that does not exist reads as "this run found
    nothing", which is the confusion the whole package works to avoid."""
    plane, _ = _plane(_Queue())

    with pytest.raises(Problem) as exc:
        plane.list_findings("Bearer analyst", "missing/run")

    assert exc.value.status == 404


def test_a_run_id_cannot_escape_the_workspace(tmp_path: Path) -> None:
    """It arrives over HTTP: `../../etc` is a path traversal wearing a run id.

    The escape target is given a real `queue.json`, so the existence check
    cannot be what refuses it. Only the containment check can — which is the
    point: a traversal that happens to land on a readable file is exactly the
    case a "does it exist" test would wave through.
    """
    workspace = tmp_path / "ws"
    (workspace / "runs" / "acme" / "run-1").mkdir(parents=True)
    (workspace / "runs" / "acme" / "run-1" / "queue.json").write_text(
        '{"findings": []}', encoding="utf-8"
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "queue.json").write_text('{"findings": []}', encoding="utf-8")

    queue = ManifestQueue(workspace / "runs" / "acme" / "run-1")

    # `<ws>/runs/../../outside` — a real directory, with a real queue.json.
    assert (outside / "queue.json").exists()
    with pytest.raises(ValueError):
        queue.select("../../outside")


def test_runs_are_discovered_across_the_workspace(tmp_path: Path) -> None:
    """A run an operator has to restart the console to look at is a run they do
    not look at."""
    for target, run in (("acme", "run-1"), ("acme", "run-2"), ("other", "run-1")):
        directory = tmp_path / "runs" / target / run
        directory.mkdir(parents=True)
        (directory / "queue.json").write_text('{"findings": []}', encoding="utf-8")
    queue = ManifestQueue(tmp_path / "runs" / "acme" / "run-1")

    assert {row["id"] for row in queue.runs()} == {
        "acme/run-1",
        "acme/run-2",
        "other/run-1",
    }


def test_the_run_the_console_was_started_against_is_the_one_it_opens_on(
    tmp_path: Path,
) -> None:
    """Newest-first is the right order and the wrong default: an operator who
    pointed at one run should be shown that run."""
    import os
    import time

    for run in ("run-1", "run-2"):
        directory = tmp_path / "runs" / "acme" / run
        directory.mkdir(parents=True)
        (directory / "queue.json").write_text('{"findings": []}', encoding="utf-8")
    # run-2 is newest, so it sorts first; run-1 is the one asked for.
    newest = tmp_path / "runs" / "acme" / "run-2" / "queue.json"
    os.utime(newest, (time.time() + 60, time.time() + 60))

    rows = ManifestQueue(tmp_path / "runs" / "acme" / "run-1").runs()

    assert rows[0]["id"] == "acme/run-2", "the order should still be newest first"
    assert next(row["id"] for row in rows if row["selected"]) == "acme/run-1"


def test_a_run_without_a_queue_is_omitted_not_listed_as_empty(tmp_path: Path) -> None:
    """It either has not reached export or was not triaged; listing it as a run
    with no findings would be exactly the wrong claim."""
    good = tmp_path / "runs" / "acme" / "done"
    good.mkdir(parents=True)
    (good / "queue.json").write_text('{"findings": []}', encoding="utf-8")
    (tmp_path / "runs" / "acme" / "midway").mkdir(parents=True)

    assert [row["run_id"] for row in ManifestQueue(good).runs()] == ["done"]


# -- headers -----------------------------------------------------------------


def test_the_policy_admits_no_other_origin() -> None:
    policy = SECURITY_HEADERS["Content-Security-Policy"]

    assert "default-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "connect-src 'self'" in policy


def test_a_decision_page_is_never_cached_by_a_browser() -> None:
    assert SECURITY_HEADERS["Cache-Control"] == "no-store"


def test_the_drafter_presence_is_advertised_so_the_page_can_hide_the_button() -> None:
    with_drafter, _ = _plane(_Queue())
    assert with_drafter.public_config()["drafting"] is False

    class _Drafter:
        def draft(self, principal: Principal, fingerprint: str) -> dict[str, Any]:
            return {}

    plane = ControlPlane(
        StaticVerifier(tokens={}), MemoryDecisionStore(), ApiConfig(), MAPPING,
        _Drafter(), _Queue(),
    )
    assert plane.public_config()["drafting"] is True
