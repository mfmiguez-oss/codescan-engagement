"""An in-memory workspace that enforces the checks the real one enforces.

A fake that accepts anything would let the gate pass while the driver quietly
violated the methodology, so this one keeps the three rules that make unattended
operation defensible: an answer must carry the digest of the prompt actually
dispatched, an agent id must never be reused across items, and a scenario must
exist before a result can be recorded against it.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from engagement.contracts import (
    ParkedScenario,
    Phase,
    Priority,
    RenderedPrompt,
    RunRef,
    RunState,
    ScenarioOutcome,
    ScenarioRef,
)
from engagement.workspace import WorkspaceError


class FakeWorkspace:
    def __init__(
        self,
        scenarios: list[ScenarioRef] | None = None,
        candidates_per_scenario: int = 0,
        recon_done: bool = True,
        backlog_done: bool = True,
    ) -> None:
        self.backlog = list(scenarios or [])
        self._candidates_per_scenario = candidates_per_scenario
        self.recon_done = recon_done
        self.backlog_done = backlog_done
        self.finished: dict[str, str] = {}
        self.decisions: dict[str, str] = {}
        self.agent_ids: set[str] = set()
        self.recon_calls = 0
        self.sarif_written = False
        #: status the next recorded scenario result will report
        self.status_for: dict[str, str] = {}
        self.decision_for: dict[str, str] = {}
        self.reject: set[str] = set()
        #: what the model says it lacks, per scenario
        self.missing_for: dict[str, list[str]] = {}
        #: status on the second (expanded) attempt, if different
        self.expanded_status: dict[str, str] = {}
        #: files the jail will resolve; anything else is refused
        self.sources: dict[str, str] = {}
        self.attempts: dict[str, int] = {}
        self.expanded_prompts: list[str] = []
        self.parked_written: list[ParkedScenario] = []
        #: a prior run's queue, for resume
        self.previously_parked: list[ParkedScenario] = []
        #: appended to every rendered prompt, so a test can plant material
        #: the driver must not forward verbatim
        self.prompt_extra = ""

    # -- prompts ------------------------------------------------------------

    def _prompt(self, kind: str, item_id: str) -> RenderedPrompt:
        # CRLF on purpose. The real workspace hashes the file's bytes, so a
        # driver that decoded a prompt and re-encoded it to hash would produce
        # a different digest — the exact defect this fake must be able to catch.
        body = f"# {kind} prompt for {item_id}\r\nreview the material below\r\n"
        raw = (body + self.prompt_extra).encode()
        return RenderedPrompt(text=raw.decode("utf-8"), digest=sha256(raw).hexdigest())

    # -- protocol -----------------------------------------------------------

    def state(self, ref: RunRef) -> RunState:
        if not self.recon_done:
            return RunState(phase=Phase.recon)
        if not self.backlog_done:
            return RunState(phase=Phase.router)
        pending = self.pending_scenarios(ref)
        if pending:
            return RunState(
                phase=Phase.scenarios,
                scenarios_total=len(self.backlog),
                scenarios_pending=len(pending),
            )
        if self.pending_candidates(ref):
            return RunState(
                phase=Phase.triage,
                scenarios_total=len(self.backlog),
                candidates_pending=len(self.pending_candidates(ref)),
            )
        return RunState(phase=Phase.export, scenarios_total=len(self.backlog))

    def run_recon(self, ref: RunRef, experts: list[str]) -> None:
        self.recon_calls += 1
        self.recon_done = True

    def render_router_prompt(self, ref: RunRef) -> RenderedPrompt:
        return self._prompt("router", str(ref))

    def record_backlog(self, ref: RunRef, answer: str) -> None:
        data = json.loads(answer)
        if "scenarios" not in data:
            raise WorkspaceError("router answer has no scenarios array")
        self.backlog_done = True

    def pending_scenarios(self, ref: RunRef) -> list[ScenarioRef]:
        return [item for item in self.backlog if item.scenario_id not in self.finished]

    def render_scenario_prompt(self, ref: RunRef, scenario_id: str) -> RenderedPrompt:
        if all(item.scenario_id != scenario_id for item in self.backlog):
            raise WorkspaceError(f"unknown scenario {scenario_id}")
        return self._prompt("scenario", scenario_id)

    def record_scenario_result(
        self, ref: RunRef, scenario_id: str, answer: str
    ) -> ScenarioOutcome:
        if scenario_id in self.reject:
            raise WorkspaceError(f"integrity check failed for {scenario_id}")
        data = json.loads(answer)
        expected = self._prompt("scenario", scenario_id).digest
        if data.get("scenario_prompt_sha256") != expected:
            raise WorkspaceError(f"scenario_prompt_sha256 mismatch for {scenario_id}")
        agent = str(data.get("subagent_id", ""))
        if not agent:
            raise WorkspaceError("result carries no subagent_id")
        if agent in self.agent_ids:
            raise WorkspaceError(f"subagent_id {agent} already recorded")
        self.agent_ids.add(agent)
        attempt = self.attempts.get(scenario_id, 0) + 1
        self.attempts[scenario_id] = attempt
        if attempt > 1 and scenario_id in self.expanded_status:
            status = self.expanded_status[scenario_id]
        else:
            status = self.status_for.get(scenario_id, "verified")
        if status in {"verified", "rejected", "candidate"}:
            self.finished[scenario_id] = status
        return ScenarioOutcome(
            status=status, missing_context=self.missing_for.get(scenario_id, [])
        )

    def read_source(self, ref: RunRef, path: str) -> str | None:
        """Stands in for the path jail: only declared files resolve."""
        if ".." in path or path.startswith(("/", "\\")):
            return None
        return self.sources.get(path)

    def write_parked(self, ref: RunRef, parked: list[ParkedScenario]) -> Path:
        self.parked_written = list(parked)
        return Path(f"{ref.run_id}-parked.json")

    def read_parked(self, ref: RunRef) -> list[ParkedScenario]:
        return list(self.previously_parked)

    def pending_candidates(self, ref: RunRef) -> list[str]:
        out: list[str] = []
        for scenario_id, status in self.finished.items():
            if status != "verified":
                continue
            for ordinal in range(1, self._candidates_per_scenario + 1):
                candidate = f"{scenario_id}-F{ordinal:03d}"
                if candidate not in self.decisions:
                    out.append(candidate)
        return sorted(out)

    def render_triage_prompt(self, ref: RunRef, candidate_id: str) -> RenderedPrompt:
        return self._prompt("triage", candidate_id)

    def record_triage(self, ref: RunRef, candidate_id: str, answer: str) -> str:
        data = json.loads(answer)
        expected = self._prompt("triage", candidate_id).digest
        if data.get("triage_prompt_sha256") != expected:
            raise WorkspaceError(f"triage_prompt_sha256 mismatch for {candidate_id}")
        agent = str(data.get("triage_agent_id", ""))
        if agent in self.agent_ids:
            raise WorkspaceError(f"triage_agent_id {agent} already recorded")
        self.agent_ids.add(agent)
        decision = self.decision_for.get(candidate_id, "accepted")
        self.decisions[candidate_id] = decision
        return decision

    def emit_sarif(self, ref: RunRef, out: Path | None = None) -> Path:
        self.sarif_written = True
        return out or Path(f"{ref.run_id}.sarif")


def scenarios(*specs: tuple[str, Priority]) -> list[ScenarioRef]:
    return [
        ScenarioRef(scenario_id=sid, expert="injection", priority=priority)
        for sid, priority in specs
    ]
