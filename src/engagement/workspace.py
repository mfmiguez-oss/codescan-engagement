"""The workspace port, and the adapter onto an OpenHack checkout.

The driver never sees a command string. It asks a workspace where the run is,
asks for a rendered prompt, and hands back an answer to be recorded — and the
workspace decides whether that answer is admissible.

Keeping that boundary is what preserves the property that makes unattended
operation defensible in the first place: **the integrity checks stay on the
workspace side**. Coverage validation, prompt-hash binding, evidence snippets
re-read from the checkout, and per-item agent-id uniqueness are all enforced by
the recorder, not by the thing driving it. A driver cannot talk its way past
them, and neither can a model.

``CliWorkspace`` shells out to the ``openhack`` CLI because that CLI *is* the
documented contract; the recorders it invokes are the same ones a human would
run. ``record_*`` raising on a rejected answer is therefore a feature, and the
driver treats it as a disposition rather than a crash.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Protocol

from .contracts import (
    ParkedScenario,
    Phase,
    Priority,
    RenderedPrompt,
    RunRef,
    RunState,
    ScenarioOutcome,
    ScenarioRef,
)

#: What a workspace root needs before OpenHack will resolve against it. The
#: package is installed; these are the *data* directories that make a directory
#: a workspace rather than an empty folder.
WORKSPACE_TREES = ("agents", "templates", "config")


def vendored_workspace() -> Path | None:
    """Locate the workspace vendored alongside this package, if present."""
    for candidate in (
        Path(__file__).resolve().parents[2] / "vendor" / "openhack",
        Path(__file__).resolve().parents[3] / "vendor" / "openhack",
    ):
        if (candidate / "agents" / "experts").is_dir():
            return candidate
    return None


def seed_workspace(destination: Path, source: Path | None = None) -> Path:
    """Copy the methodology into a writable workspace root.

    The vendored tree is deliberately *not* usable as a workspace root itself:
    runs would be written inside it, and the drift check would then see run
    artifacts where it expects an untouched mirror. Seeding a copy keeps the
    mirror clean and gives the run somewhere writable to live — which is the
    same thing the container image does at build time.
    """
    origin = source or vendored_workspace()
    if origin is None:
        raise WorkspaceError(
            "no vendored workspace found; pass an OpenHack checkout explicitly"
        )
    destination.mkdir(parents=True, exist_ok=True)
    for tree in WORKSPACE_TREES:
        src = origin / tree
        if not src.is_dir():
            raise WorkspaceError(f"vendored workspace is missing {tree}/")
        shutil.copytree(src, destination / tree, dirs_exist_ok=True)
    (destination / "runs").mkdir(exist_ok=True)
    return destination


def _missing_context(result: dict[str, object]) -> list[str]:
    """The model's own account of what it could not resolve.

    Read from the proof obligations it left unresolved, which the workspace
    already requires to carry a concrete summary rather than a shrug.
    """
    obligations = result.get("proof_obligations")
    statements: list[str] = []
    if isinstance(obligations, list):
        for item in obligations:
            if not isinstance(item, dict) or item.get("status") != "needs_context":
                continue
            summary = str(item.get("summary", "")).strip()
            if summary:
                statements.append(summary)
    if not statements:
        summary = str(result.get("summary", "")).strip()
        if summary:
            statements.append(summary)
    return statements


def _rendered(path: Path) -> RenderedPrompt:
    """Read a rendered prompt and hash the *bytes* the recorder will hash.

    Deliberately not ``read_text`` then re-encode: universal-newline decoding
    rewrites CRLF to LF, so on Windows the re-encoded bytes hash differently
    from the file the recorder reads, and every answer is rejected for a
    mismatch nothing in the driver can see.
    """
    raw = path.read_bytes()
    return RenderedPrompt(text=raw.decode("utf-8"), digest=sha256(raw).hexdigest())


class WorkspaceError(RuntimeError):
    """The workspace refused an answer or could not complete an operation."""


class Workspace(Protocol):
    """Everything the driver needs, and deliberately nothing more."""

    def state(self, ref: RunRef) -> RunState: ...

    def run_recon(self, ref: RunRef, experts: list[str]) -> None: ...

    def render_router_prompt(self, ref: RunRef) -> RenderedPrompt: ...

    def record_backlog(self, ref: RunRef, answer: str) -> None: ...

    def pending_scenarios(self, ref: RunRef) -> list[ScenarioRef]: ...

    def render_scenario_prompt(self, ref: RunRef, scenario_id: str) -> RenderedPrompt: ...

    def record_scenario_result(
        self, ref: RunRef, scenario_id: str, answer: str
    ) -> ScenarioOutcome: ...

    def read_source(self, ref: RunRef, path: str) -> str | None: ...

    def write_parked(self, ref: RunRef, parked: list[ParkedScenario]) -> Path: ...

    def read_parked(self, ref: RunRef) -> list[ParkedScenario]: ...

    def pending_candidates(self, ref: RunRef) -> list[str]: ...

    def render_triage_prompt(self, ref: RunRef, candidate_id: str) -> RenderedPrompt: ...

    def record_triage(self, ref: RunRef, candidate_id: str, answer: str) -> str: ...

    def emit_sarif(self, ref: RunRef, out: Path | None = None) -> Path: ...


class CliWorkspace:
    """Adapter onto a real OpenHack checkout via its CLI.

    ``root`` is the workspace root; it is passed through as ``OPENHACK_ROOT`` so
    the driver can run from anywhere, including a container whose working
    directory is not the checkout.
    """

    def __init__(
        self,
        root: Path,
        command: list[str] | None = None,
        timeout: float = 900.0,
    ) -> None:
        self._root = Path(root)
        # Default to the interpreter running this process rather than a bare
        # PATH lookup for ``openhack``. In a venv or a container with more than
        # one install, a PATH lookup silently resolves to a *different* copy of
        # the workspace tooling than the one this environment installed, and the
        # failure surfaces much later as an unexplained recorder error.
        self._command = command or [sys.executable, "-m", "openhack"]
        self._timeout = timeout

    # -- process plumbing ---------------------------------------------------

    def _run(self, *args: str) -> str:
        env = {**os.environ, "OPENHACK_ROOT": str(self._root)}
        try:
            completed = subprocess.run(
                [*self._command, *args],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env=env,
                check=False,
            )
        except FileNotFoundError as exc:  # pragma: no cover - environment issue
            raise WorkspaceError(
                f"openhack CLI not found: {' '.join(self._command)}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise WorkspaceError(f"openhack {' '.join(args)} timed out") from exc
        if completed.returncode != 0:
            # the last lines carry the recorder's own message; a traceback's
            # opening frames say only that a subprocess was run
            detail = (completed.stderr or completed.stdout or "").strip()
            tail = "\n".join(detail.splitlines()[-12:])
            raise WorkspaceError(f"openhack {args[0]} failed: {tail[:2000]}")
        return completed.stdout

    def _run_dir(self, ref: RunRef) -> Path:
        return self._root / "runs" / ref.target / ref.run_id

    def _write_temp(self, ref: RunRef, name: str, payload: str) -> Path:
        # answers land inside the run folder, so a rejected one is still on disk
        # next to the artifacts it was rejected against
        staging = self._run_dir(ref) / "driver"
        staging.mkdir(parents=True, exist_ok=True)
        path = staging / name
        path.write_text(payload, encoding="utf-8")
        return path

    # -- state --------------------------------------------------------------

    def state(self, ref: RunRef) -> RunState:
        run = self._run_dir(ref)
        if not (run / "run-config.yaml").exists():
            return RunState(phase=Phase.initialize)
        if not (run / "recon-output" / "recon-items.jsonl").exists():
            return RunState(phase=Phase.recon)
        index = run / "scenarios" / "index.jsonl"
        if not index.exists() or not index.read_text(encoding="utf-8").strip():
            return RunState(phase=Phase.router)

        pending_scenarios = self.pending_scenarios(ref)
        total = sum(1 for _ in self._scenario_files(ref))
        if pending_scenarios:
            return RunState(
                phase=Phase.scenarios,
                scenarios_total=total,
                scenarios_pending=len(pending_scenarios),
            )
        pending_candidates = self.pending_candidates(ref)
        if pending_candidates:
            return RunState(
                phase=Phase.triage,
                scenarios_total=total,
                candidates_pending=len(pending_candidates),
            )
        return RunState(phase=Phase.export, scenarios_total=total)

    def _scenario_files(self, ref: RunRef) -> list[Path]:
        backlog = self._run_dir(ref) / "scenarios" / "backlog"
        return sorted(backlog.glob("S*.json")) if backlog.exists() else []

    # -- phases -------------------------------------------------------------

    def run_recon(self, ref: RunRef, experts: list[str]) -> None:
        args = ["run-recon", ref.target, ref.run_id]
        if experts:
            for expert in experts:
                args += ["--expert", expert]
        else:
            args.append("--all-agents")
        self._run(*args)

    def render_router_prompt(self, ref: RunRef) -> RenderedPrompt:
        self._run("create-scenarios", ref.target, ref.run_id)
        prompt = self._run_dir(ref) / "scenarios" / "scenario-router-prompt.md"
        if not prompt.exists():
            raise WorkspaceError("router prompt was not rendered")
        return _rendered(prompt)

    def record_backlog(self, ref: RunRef, answer: str) -> None:
        path = self._write_temp(ref, "router-result.json", answer)
        self._run("record-scenario-backlog", ref.target, ref.run_id, str(path))

    def pending_scenarios(self, ref: RunRef) -> list[ScenarioRef]:
        finished = self._run_dir(ref) / "scenarios" / "finished"
        done = {item.stem for item in finished.glob("S*.json")} if finished.exists() else set()
        pending: list[ScenarioRef] = []
        for path in self._scenario_files(ref):
            if path.stem in done:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise WorkspaceError(f"unreadable scenario {path.name}: {exc}") from exc
            raw_priority = str(data.get("priority", "normal")).lower()
            priority = (
                Priority(raw_priority)
                if raw_priority in {item.value for item in Priority}
                else Priority.normal
            )
            pending.append(
                ScenarioRef(
                    scenario_id=str(data.get("id", path.stem)),
                    expert=str(data.get("expert", "")),
                    priority=priority,
                )
            )
        return pending

    def render_scenario_prompt(self, ref: RunRef, scenario_id: str) -> RenderedPrompt:
        self._run("render-scenario-prompt", ref.target, ref.run_id, scenario_id)
        prompt = self._run_dir(ref) / "scenarios" / "backlog" / f"{scenario_id}.md"
        if not prompt.exists():
            raise WorkspaceError(f"scenario prompt was not rendered for {scenario_id}")
        return _rendered(prompt)

    def record_scenario_result(
        self, ref: RunRef, scenario_id: str, answer: str
    ) -> ScenarioOutcome:
        path = self._write_temp(ref, f"{scenario_id}-result.json", answer)
        self._run("record-scenario-result", ref.target, ref.run_id, scenario_id, str(path))
        finished = self._run_dir(ref) / "scenarios" / "finished" / f"{scenario_id}.json"
        if not finished.exists():
            raise WorkspaceError(f"scenario {scenario_id} was not recorded")
        data = json.loads(finished.read_text(encoding="utf-8"))
        return ScenarioOutcome(
            status=str(data.get("status", "")),
            missing_context=_missing_context(data),
        )

    def read_source(self, ref: RunRef, path: str) -> str | None:
        """Read one file from the checkout, refusing anything outside it.

        The path arrives from model output, so this is a jail rather than a
        convenience: ``..`` segments, absolute paths, and symlinks that escape
        are all resolved and then rejected by the containment check. A refusal
        returns ``None`` and is reported by the caller, never raised — a file
        the model asked for and did not get is a bound on its second attempt,
        not a crash.
        """
        root = (self._run_dir(ref) / "sourcecode").resolve()
        try:
            resolved = (root / path).resolve()
            resolved.relative_to(root)
        except (ValueError, OSError):
            return None
        if not resolved.is_file():
            return None
        try:
            return resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def write_parked(self, ref: RunRef, parked: list[ParkedScenario]) -> Path:
        """Persist the parked queue beside the run it belongs to."""
        out = self._run_dir(ref) / "parked-scenarios.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = [item.model_dump(mode="json") for item in parked]
        out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return out

    def read_parked(self, ref: RunRef) -> list[ParkedScenario]:
        """Load a previous run's parked queue, if it left one.

        A queue that cannot be read back is a report, not a queue: the whole
        reason for persisting it is that a later run — with a wider checkout,
        a larger budget, or simply a better day — can pick the work up.
        """
        path = self._run_dir(ref) / "parked-scenarios.json"
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise WorkspaceError(f"parked queue is unreadable: {exc}") from exc
        if not isinstance(payload, list):
            raise WorkspaceError("parked queue is not a list")
        return [ParkedScenario.model_validate(item) for item in payload]

    def pending_candidates(self, ref: RunRef) -> list[str]:
        run = self._run_dir(ref)
        candidates = run / "finding-candidates"
        decisions = run / "finding-triage" / "decisions"
        if not candidates.exists():
            return []
        decided: set[str] = (
            {item.stem for item in decisions.glob("S*-F*.json")}
            if decisions.exists()
            else set()
        )
        return [
            path.stem
            for path in sorted(candidates.glob("S*-F*.json"))
            if path.stem not in decided
        ]

    def render_triage_prompt(self, ref: RunRef, candidate_id: str) -> RenderedPrompt:
        self._run("render-finding-triage-prompt", ref.target, ref.run_id, candidate_id)
        prompt = self._run_dir(ref) / "finding-triage" / "prompts" / f"{candidate_id}.md"
        if not prompt.exists():
            raise WorkspaceError(f"triage prompt was not rendered for {candidate_id}")
        return _rendered(prompt)

    def record_triage(self, ref: RunRef, candidate_id: str, answer: str) -> str:
        path = self._write_temp(ref, f"{candidate_id}-triage.json", answer)
        self._run("record-finding-triage", ref.target, ref.run_id, candidate_id, str(path))
        decision = (
            self._run_dir(ref) / "finding-triage" / "decisions" / f"{candidate_id}.json"
        )
        if not decision.exists():
            raise WorkspaceError(f"triage for {candidate_id} was not recorded")
        data = json.loads(decision.read_text(encoding="utf-8"))
        return str(data.get("decision", ""))

    def emit_sarif(self, ref: RunRef, out: Path | None = None) -> Path:
        args = ["emit-sarif", ref.target, ref.run_id]
        if out is not None:
            args += ["--out", str(out)]
        self._run(*args)
        return out or (self._run_dir(ref) / "findings.sarif")
