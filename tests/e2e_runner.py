"""Drive a real workspace with scripted model answers.

Two entry points on purpose. :func:`drive` is imported by the in-process test;
``python e2e_runner.py <root> <target> <run-id>`` is executed *inside the
built image*, where this repo's test suite does not exist. One file so the two
paths cannot drift into proving different things.

The provider is scripted rather than live: the point is that the driver, the
adapter, the provenance stamping and the workspace's own integrity checks line
up end to end, not that a model can be persuaded to emit JSON. Every answer
still has to survive the real recorders — coverage validation, prompt-hash
binding, evidence re-read from the checkout, agent-id uniqueness — so a scripted
run proves exactly as much about the machinery as a live one.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

#: The target under review. Small enough to reason about, and vulnerable in a
#: way recon will actually route: request input reaching a SQL sink.
FIXTURE_SOURCE = """<?php
$user = $_GET["user"];
$sql = "SELECT * FROM users WHERE name = " . $user;
$r = mysqli_query($conn, $sql);
"""

#: The line the expert cites. Read back from the prompt at dispatch time rather
#: than hard-coded, so a change to the fixture cannot leave the citation
#: pointing at text that is no longer there.
SINK_PATTERN = re.compile(r"^\s*(\$r = mysqli_query.*)$", re.M)


def build_fixture_repo(destination: Path) -> Path:
    """Create the git repository the run will clone."""
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "login.php").write_text(FIXTURE_SOURCE, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(destination)], check=True)
    subprocess.run(["git", "-C", str(destination), "add", "-A"], check=True)
    subprocess.run(
        [
            "git", "-C", str(destination),
            "-c", "user.email=e2e@example.invalid",
            "-c", "user.name=e2e",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )
    return destination


class ScriptedProvider:
    """Answers according to which phase the driver is in.

    Classified by the *system* prompt the driver chose, not by scanning the
    body: the scenario prompt legitimately contains the words "routing unit",
    so matching on the body once made an expert call answer as the router.
    """

    name = "scripted"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def complete(self, request: Any) -> Any:
        from engagement.providers import ModelResponse

        if "scenario-router" in request.system:
            kind, body = "router", self._router()
        elif "triage" in request.system:
            kind, body = "triage", self._triage()
        else:
            kind, body = "expert", self._expert(request.user)
        self.calls.append(kind)
        return ModelResponse(
            deployment=request.deployment, content=body, input_tokens=10, output_tokens=10
        )

    @staticmethod
    def _router() -> str:
        return json.dumps({
            "scenarios": [{
                "id": "S001",
                "recon_item_id": "R001",
                "routing_unit_id": "U001",
                "expert": "injection",
                "target_path": "login.php",
                "proof_question": (
                    "Can an attacker control the SQL query through the user parameter?"
                ),
                "evidence_required": ["source line", "sink line"],
                "security_invariant": (
                    "All SQL must be parameterized; no request-controlled string may "
                    "be concatenated into a query."
                ),
                "proof_obligations": [{
                    "id": "po1",
                    "question": "Does attacker input reach the SQL sink unparameterized?",
                    "evidence_required": "source and sink lines",
                    "central": True,
                }],
            }],
            "coverage_decisions": [],
        })

    @staticmethod
    def _expert(prompt: str) -> str:
        match = SINK_PATTERN.search(prompt)
        snippet = match.group(1).strip() if match else "mysqli_query($conn, $sql);"
        evidence = {
            "path": "login.php", "line": 4, "snippet": snippet,
            "role": "unauthenticated attacker", "note": "sink",
        }
        return json.dumps({
            "status": "verified",
            "summary": "The user parameter is concatenated into a SQL string and executed.",
            "primary_vulnerability_class": "SQL injection",
            "reviewed_files": ["login.php"],
            "evidence": [evidence],
            "proof_obligations": [{
                "id": "po1", "status": "proven_vulnerable",
                "summary": (
                    "Request-controlled input reaches mysqli_query with no "
                    "parameterization."
                ),
                "evidence": [evidence],
            }],
            "findings": [{
                "title": "SQL injection in login handler",
                "severity": "high", "target_path": "login.php", "line": 4,
                "cwe": "CWE-89",
                "summary": "The user query parameter is concatenated into a SQL statement.",
                "evidence": "login.php:4 executes a concatenated query.",
                "impact": "An attacker can read or modify arbitrary rows.",
                "attacker_role": "Unauthenticated remote attacker",
                "preconditions": "The login route is reachable.",
                "recommended_fix": "Use a prepared statement with a bound parameter.",
                "validation_notes": (
                    "Submit a quote in the user parameter and confirm rejection "
                    "after the fix."
                ),
            }],
        })

    @staticmethod
    def _triage() -> str:
        return json.dumps({
            "decision": "accepted",
            "summary": "Confirmed exploitable SQL injection with a complete source-to-sink chain.",
            "final_severity": "critical",
            "severity_rationale": "Unauthenticated and grants arbitrary read of the users table.",
            "confidence": "high",
            "evidence_assessment": "The cited line matches the checkout and establishes the sink.",
            "evidence_gaps": [], "required_changes": [], "reviewed_files": ["login.php"],
        })


def drive(workspace_root: Path, target: str, run_id: str) -> tuple[Any, ScriptedProvider]:
    """Run one engagement to completion against a real workspace."""
    from engagement.budget import Budget, Ledger
    from engagement.contracts import RunRef
    from engagement.driver import Driver, Policy
    from engagement.workspace import CliWorkspace

    provider = ScriptedProvider()
    driver = Driver(
        workspace=CliWorkspace(root=workspace_root),
        provider=provider,
        ledger=Ledger(budget=Budget(max_calls=20)),
        policy=Policy(model="scripted-model", experts=["injection"]),
    )
    return driver.run(RunRef(target=target, run_id=run_id)), provider


def main(argv: list[str]) -> int:
    """Entry point used inside the container, where pytest is absent."""
    if len(argv) != 4:
        print("usage: e2e_runner.py <workspace-root> <target> <run-id>")
        return 2
    report, provider = drive(Path(argv[1]), argv[2], argv[3])
    print(json.dumps({
        "dispatched": provider.calls,
        "phase": report.phase.value,
        "calls": report.model_calls,
        "scenarios_completed": report.scenarios_completed,
        "candidates": len(report.candidates),
        "complete": report.is_complete(),
        "reviewed_fraction": report.reviewed_fraction,
        "sarif": report.sarif_path,
    }))
    return 0 if report.is_complete() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
