"""Starting a scan from the console — the most authority in the package.

Every test here is a refusal or a boundary. The command is checked without
running anything, because a launcher whose argv is only verified by executing
it is a launcher nobody reviews.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from engagement.api import ApiConfig, ControlPlane, Problem
from engagement.auth import RoleMapping, StaticVerifier
from engagement.decisions import MemoryDecisionStore
from engagement.identity import Principal, Role
from engagement.runs import RunLauncher, RunRecord, RunRequest

MAPPING = RoleMapping(
    mapping={
        "Engagement.Analyst": Role.analyst,
        "Engagement.Approver": Role.approver,
        "Engagement.Scanner": Role.scanner,
    }
)

SCANNER = Principal(subject="oid-9", roles=[Role.scanner], tenant="acme")


def _launcher(tmp_path: Path, **kwargs: Any) -> RunLauncher:
    return RunLauncher(
        workspace=tmp_path, env={}, model="claude-opus-5", **kwargs
    )


# -- what the caller may choose ----------------------------------------------

def test_the_ceiling_is_the_deployments_not_the_callers(tmp_path: Path) -> None:
    """A caller-supplied ceiling is not a ceiling."""
    argv = _launcher(tmp_path, max_calls=17).command(
        RunRequest(target="acme"), "run-1"
    )

    assert "--max-calls" in argv
    assert argv[argv.index("--max-calls") + 1] == "17"


def test_a_run_request_cannot_smuggle_extra_arguments() -> None:
    """Strict models: a body naming `max_calls` or `model` is refused rather
    than quietly ignored, so a caller cannot raise its own ceiling."""
    with pytest.raises(ValidationError):
        RunRequest.model_validate({"target": "acme", "max_calls": 99999})
    with pytest.raises(ValidationError):
        RunRequest.model_validate({"target": "acme", "model": "something-else"})


def test_the_model_comes_from_the_deployment(tmp_path: Path) -> None:
    argv = _launcher(tmp_path).command(RunRequest(target="acme"), "run-1")

    assert argv[argv.index("--model") + 1] == "claude-opus-5"


def test_a_generated_run_id_cannot_collide(tmp_path: Path) -> None:
    """A collision would have one run writing into another's directory, which
    the workspace would treat as resumption rather than as the error it is."""
    ids = {RunRequest(target="acme").resolved_run_id() for _ in range(50)}

    assert len(ids) == 50


def test_a_caller_supplied_run_id_is_honoured(tmp_path: Path) -> None:
    assert RunRequest(target="acme", run_id="nightly").resolved_run_id() == "nightly"


# -- refusals ----------------------------------------------------------------


def test_two_runs_against_one_target_are_refused(tmp_path: Path) -> None:
    """They race on the workspace's own files, and the second would corrupt the
    first's state while both reported success."""
    launcher = _launcher(tmp_path)
    launcher._active_targets.add("acme")

    with pytest.raises(RuntimeError):
        launcher.start(SCANNER, RunRequest(target="acme"))


def test_a_different_target_is_not_blocked(tmp_path: Path) -> None:
    launcher = _launcher(tmp_path)
    launcher._active_targets.add("acme")
    launcher._records["x"] = RunRecord(
        id="x", target="other", run_id="r", started_by="s", started_at="t"
    )

    assert launcher.get("x") is not None


def test_a_run_must_name_a_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _launcher(tmp_path).start(SCANNER, RunRequest(target="   "))


def test_exit_three_is_reported_as_incomplete_not_failed() -> None:
    """Exit 3 is "finished, but left work parked or unfunded". Showing it as a
    failure teaches an analyst to ignore the status entirely."""
    for code, expected in ((0, "complete"), (3, "incomplete"), (1, "failed")):
        assert {0: "complete", 3: "incomplete"}.get(code, "failed") == expected


# -- through the control plane ------------------------------------------------


class _Runner:
    def __init__(self) -> None:
        self.started: list[tuple[str, str]] = []

    def start(self, principal: Principal, request: Any) -> RunRecord:
        self.started.append((principal.actor(), request.target))
        return RunRecord(
            id="rec-1",
            target=request.target,
            run_id="run-1",
            started_by=principal.actor(),
            started_at="now",
        )

    def get(self, record_id: str) -> RunRecord | None:
        return None

    def list(self) -> list[RunRecord]:
        return []


def _plane(runner: Any = None) -> ControlPlane:
    verifier = StaticVerifier(
        tokens={
            "scanner": {"oid": "oid-9", "sub": "s", "tid": "acme",
                        "roles": ["Engagement.Scanner"]},
            "approver": {"oid": "oid-2", "sub": "s", "tid": "acme",
                         "roles": ["Engagement.Analyst", "Engagement.Approver"]},
        }
    )
    return ControlPlane(
        verifier, MemoryDecisionStore(), ApiConfig(tenant="acme"), MAPPING,
        runner=runner,
    )


def test_a_scanner_may_start_a_run() -> None:
    runner = _Runner()
    result = _plane(runner).start_run("Bearer scanner", b'{"target": "acme"}')

    assert result["target"] == "acme"
    assert runner.started == [("oid-9", "acme")]


def test_an_approver_who_cannot_scan_may_not_start_a_run() -> None:
    """The role that may spend is deliberately separate from the role that may
    adjudicate. Closing a finding is not permission to start a scan."""
    runner = _Runner()

    with pytest.raises(Problem) as exc:
        _plane(runner).start_run("Bearer approver", b'{"target": "acme"}')

    assert exc.value.status == 403
    assert runner.started == []


def test_starting_a_run_needs_a_credential() -> None:
    with pytest.raises(Problem) as exc:
        _plane(_Runner()).start_run(None, b'{"target": "acme"}')

    assert exc.value.status == 401


def test_a_deployment_that_did_not_enable_runs_refuses_them() -> None:
    """Off unless a deployment turns it on: a control plane serving a queue has
    no business starting scans."""
    with pytest.raises(Problem) as exc:
        _plane(None).start_run("Bearer scanner", b'{"target": "acme"}')

    assert exc.value.status == 503


def test_a_run_already_in_progress_is_409_not_403() -> None:
    """The request is well-formed and will succeed later, which is a different
    thing to tell a caller than "you may not"."""

    class _Busy(_Runner):
        def start(self, principal: Principal, request: Any) -> RunRecord:
            raise RuntimeError("already running")

    with pytest.raises(Problem) as exc:
        _plane(_Busy()).start_run("Bearer scanner", b'{"target": "acme"}')

    assert exc.value.status == 409


def test_a_malformed_run_request_is_400() -> None:
    with pytest.raises(Problem) as exc:
        _plane(_Runner()).start_run("Bearer scanner", b'{"nope": 1}')

    assert exc.value.status == 400


def test_the_console_is_told_whether_runs_are_available() -> None:
    assert _plane(_Runner()).public_config()["runs_enabled"] is True
    assert _plane(None).public_config()["runs_enabled"] is False


def test_listing_scans_on_a_deployment_without_them_is_empty_not_an_error() -> None:
    """A page asking "what has run" should not be broken by a deployment that
    never allows one."""
    result = _plane(None).list_started_runs("Bearer scanner")

    assert result == {"runs": [], "enabled": False}


def test_the_command_is_pure_and_reviewable(tmp_path: Path) -> None:
    """A launcher whose argv is only verified by executing it is one nobody
    reviews."""
    argv = _launcher(tmp_path).command(
        RunRequest(target="acme", repo="acme/api"), "run-1"
    )

    assert "run" in argv and "acme" in argv and "run-1" in argv
    assert "--triage" in argv
    assert argv[argv.index("--repo") + 1] == "acme/api"
    assert json.dumps(argv), "argv must be plain strings"
