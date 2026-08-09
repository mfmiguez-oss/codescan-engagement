"""An in-memory workspace that enforces the checks the real one enforces.

A fake that accepts anything would let the gate pass while the driver quietly
violated the methodology, so this one keeps the three rules that make unattended
operation defensible: an answer must carry the digest of the prompt actually
dispatched, an agent id must never be reused across items, and a scenario must
exist before a result can be recorded against it.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from threading import Lock

from engagement.contracts import (
    ParkedScenario,
    Phase,
    Priority,
    RenderedPrompt,
    RoutingPath,
    RoutingUnit,
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
        self.backlog_json: str | None = None
        self.finished: dict[str, str] = {}
        self.decisions: dict[str, str] = {}
        self.agent_ids: set[str] = set()
        self.created_runs: list[str] = []
        self.recon_calls = 0
        self.sarif_written = False
        #: status the next recorded scenario result will report
        self.status_for: dict[str, str] = {}
        self.decision_for: dict[str, str] = {}
        self.reject: set[str] = set()
        #: How many *expanded* answers to refuse before accepting one — the
        #: shape of a real integrity rejection, which is a correctable citation
        #: error rather than a malformed answer. A count rather than a flag
        #: because the behaviour under test is precisely how many corrections
        #: are worth buying: 1 exercises the retry, 2 exercises its bound.
        self.reject_expanded = 0
        #: how many times `reject_once` fired, so a test can prove the retry
        #: happened rather than inferring it from the answer that followed
        self.rejections = 0
        #: what the model says it lacks, per scenario
        self.missing_for: dict[str, list[str]] = {}
        #: status on the second (expanded) attempt, if different
        self.expanded_status: dict[str, str] = {}
        #: files the jail will resolve; anything else is refused
        self.sources: dict[str, str] = {}
        #: Terms a context expansion searched for, so a test can assert that a
        #: "who calls this?" request became a search rather than a re-read.
        self.searches: list[str] = []
        #: Paths a context expansion had to resolve by suffix, so a test can
        #: assert the fallback ran only after the literal read missed.
        self.resolutions: list[str] = []
        self.attempts: dict[str, int] = {}
        self.expanded_prompts: list[str] = []
        self.parked_written: list[ParkedScenario] = []
        #: a prior run's queue, for resume
        self.previously_parked: list[ParkedScenario] = []
        #: appended to every rendered prompt, so a test can plant material
        #: the driver must not forward verbatim
        self.prompt_extra = ""
        #: routing units recon found. Empty leaves the router unchunked, which
        #: is what most tests want; setting it exercises the chunked path.
        self.units: list[str] = []
        #: every router user-prompt the driver dispatched, in order
        self.router_prompts: list[str] = []
        #: cache prefix seen on each router call, in order
        self.router_prefixes: list[str] = []
        #: durable per-chunk router answers, keyed as the real workspace keys
        #: them. Survives across drivers in a test, the way files survive a run.
        self.router_chunks: dict[str, str] = {}
        #: highest number of workspace calls seen in flight at once. Must stay 1
        #: however many scenarios run concurrently — see `_exclusive`.
        self.max_concurrent_workspace_calls = 0
        self._depth = 0
        self._depth_lock = Lock()
        #: expert ids this workspace has files for. The router may use no others.
        self.experts = ["injection", "crypto", "access"]
        #: which path each routing unit belongs to. The coverage gate judges
        #: paths, so chunking keeps them whole; unset means one path per unit.
        self.unit_paths: dict[str, str] = {}
        #: experts recon says a path owes a scenario or an explicit decision.
        self.required_experts: dict[str, list[str]] = {}
        #: experts a mandatory routing unit owes, checked against the unit id.
        self.unit_experts: dict[str, list[str]] = {}

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

    def routing_paths(self, ref: RunRef) -> list[RoutingPath]:
        grouped: dict[str, list[str]] = {}
        for unit in self.units:
            grouped.setdefault(self.unit_paths.get(unit, f"src/{unit}.py"), []).append(
                unit
            )
        return [
            RoutingPath(
                path=path,
                units=[
                    RoutingUnit(
                        unit_id=unit,
                        required_experts=self.unit_experts.get(unit, []),
                        mandatory=bool(self.unit_experts.get(unit)),
                    )
                    for unit in units
                ],
                required_experts=self.required_experts.get(path, []),
            )
            for path, units in grouped.items()
        ]

    def valid_experts(self) -> list[str]:
        return list(self.experts)

    def scenario_errors(self, scenarios: list[object]) -> list[str]:
        # Mirrors the two rules a live run actually tripped: the recorder wants
        # `recon_item_id` to be a non-empty string, and the expert to be one it
        # has a file for rather than a plausible-sounding invention.
        errors = []
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            value = scenario.get("recon_item_id", "")
            if not isinstance(value, str) or not value:
                errors.append(f"scenario {scenario.get('id')}: recon_item_id {value!r}")
            if scenario.get("expert") not in self.experts:
                errors.append(
                    f"scenario {scenario.get('id')}: unknown expert "
                    f"{scenario.get('expert')!r}"
                )
        return errors

    def read_router_chunk(self, ref: RunRef, key: str) -> str | None:
        return self.router_chunks.get(key)

    def write_router_chunk(self, ref: RunRef, key: str, answer: str) -> None:
        self.router_chunks[key] = answer

    def render_router_prompt(self, ref: RunRef) -> RenderedPrompt:
        return self._prompt("router", str(ref))

    def record_backlog(self, ref: RunRef, answer: str) -> None:
        # Kept verbatim so a test can assert what the recorder actually saw:
        # a fenced answer reaching here is what broke a live run.
        self.backlog_json = answer
        data = json.loads(answer)
        if "scenarios" not in data:
            raise WorkspaceError("router answer has no scenarios array")
        self.backlog_done = True

    def pending_scenarios(self, ref: RunRef) -> list[ScenarioRef]:
        return [item for item in self.backlog if item.scenario_id not in self.finished]

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Record whether two workspace calls ever overlapped.

        The real workspace shells out to the OpenHack CLI against one run
        directory, so two at once would interleave appends to its shared trace
        and state files. A concurrent driver must never let that happen, and a
        fake that cannot notice would let the regression through silently.
        """
        with self._depth_lock:
            self._depth += 1
            self.max_concurrent_workspace_calls = max(
                self.max_concurrent_workspace_calls, self._depth
            )
        try:
            time.sleep(0.001)  # widen the window a race would land in
            yield
        finally:
            with self._depth_lock:
                self._depth -= 1

    def render_scenario_prompt(self, ref: RunRef, scenario_id: str) -> RenderedPrompt:
        with self._exclusive():
            if all(item.scenario_id != scenario_id for item in self.backlog):
                raise WorkspaceError(f"unknown scenario {scenario_id}")
            return self._prompt("scenario", scenario_id)

    def record_scenario_result(
        self, ref: RunRef, scenario_id: str, answer: str
    ) -> ScenarioOutcome:
        with self._exclusive():
            return self._record_scenario_result(ref, scenario_id, answer)

    def _record_scenario_result(
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
        if self.reject_expanded > 0 and agent.startswith("expert-expanded"):
            # Only the *expanded* dispatch, because that is the one this models:
            # a mis-cited snippet is an error about source the model was shown,
            # and the expansion is where it is shown any. Gated on the id rather
            # than a call counter so a fake that fired on the first attempt —
            # which reaches a different branch entirely — cannot pass for this.
            #
            # Refused before the id is registered below, which is where the real
            # recorder refuses too: an answer that fails its integrity checks is
            # never persisted, so nothing about it is spent.
            self.reject_expanded -= 1
            self.rejections += 1
            raise WorkspaceError(
                "Scenario result failed integrity checks:\n"
                "- evidence item 4 invalid: evidence snippet does not match "
                "the cited source line"
            )
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

    def resolve_source(
        self, ref: RunRef, paths: Sequence[str], limit: int = 3
    ) -> dict[str, list[str]]:
        """Suffix match over the declared sources, shallowest first.

        Mirrors `CliWorkspace.resolve_source`, including its component-boundary
        rule and case folding — a fake that matched bare substrings would let
        ``api.py`` resolve to ``legacy_api.py`` and no driver test would notice
        the real workspace refusing to.
        """
        self.resolutions.extend(paths)
        out: dict[str, list[str]] = {}
        for request in paths:
            tail = request.strip().replace("\\", "/").strip("/").lower()
            if not tail:
                continue
            hits = [
                path
                for path in self.sources
                if path.lower() == tail or path.lower().endswith("/" + tail)
            ]
            if hits:
                out[request] = sorted(hits, key=lambda p: (p.count("/"), p))[:limit]
        return out

    def search_source(
        self, ref: RunRef, terms: Sequence[str], limit: int = 5
    ) -> list[str]:
        """Literal substring search over the declared sources, shallowest first.

        Mirrors the real workspace rather than improving on it. This once sorted
        every match by depth and truncated afterwards — the behavior
        `CliWorkspace` documents — while `CliWorkspace` truncated first and
        sorted the remainder, so the double was *more correct* than the code it
        stood in for, and every driver test exercised a search production could
        not deliver. A fake may be simpler; it may not be better.
        """
        self.searches.extend(terms)
        hits = [
            path
            for path, body in self.sources.items()
            if any(term in body for term in terms)
        ]
        return sorted(hits, key=lambda path: (path.count("/"), path))[:limit]

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

    def create_run(self, source: RunRef, run_id: str) -> RunRef:
        """A sibling run: the same backlog, nothing finished yet.

        `agent_ids` is deliberately *not* reset — the workspace rejects a
        repeated id, and that rule must hold across passes too, or a second pass
        could reuse the first's context and call itself independent.
        """
        self.created_runs.append(run_id)
        self.finished = {}
        self.decisions = {}
        self.attempts = {}
        return RunRef(target=source.target, run_id=run_id)

    def emit_sarif(self, ref: RunRef, out: Path | None = None) -> Path:
        self.sarif_written = True
        return out or Path(f"{ref.run_id}.sarif")


def scenarios(*specs: tuple[str, Priority]) -> list[ScenarioRef]:
    return [
        ScenarioRef(scenario_id=sid, expert="injection", priority=priority)
        for sid, priority in specs
    ]
