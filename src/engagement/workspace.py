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
import re
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol, Sequence

from .contracts import (
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


#: Extensions a caller search will open. A checkout holds binaries, images and
#: minified bundles that cannot contain a readable call site and would cost a
#: full read each to prove it.
#:
#: ``.env`` is deliberately absent. It was listed here beside ``.cfg`` and
#: ``.ini`` and never matched anything — ``Path(".env").suffix`` is ``""``,
#: because a leading dot makes the whole name a stem — and the right resolution
#: of that was to drop it rather than reach for ``path.name``. A dotenv file
#: holds credentials, not call sites, and whatever a search finds here is read
#: verbatim into a prompt sent to the model provider.
_SEARCHABLE_SUFFIXES = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".go", ".php",
        ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".kt", ".scala", ".swift",
        ".html", ".jinja", ".j2", ".erb", ".yaml", ".yml", ".json", ".toml",
        ".cfg", ".ini", ".sh", ".sql",
    }
)

#: Files above this are generated, vendored, or data — never the hand-written
#: call site a reviewer is asking for, and reading them is most of the cost.
_MAX_SEARCH_BYTES = 2_000_000

#: A Python traceback line naming the exception that ended it, e.g.
#: ``ValueError: result S001 does not match scenario-result-schema.json:``.
_EXCEPTION_LINE = re.compile(r"^\w[\w.]*(Error|Exception)\b\s*:")


def _complaint(detail: str) -> str:
    """The recorder's own message, lifted out of the traceback around it.

    The CLI reports a refusal by raising, so what arrives here is a traceback
    whose *last* lines carry the reason and whose opening frames say only that a
    subprocess was run. Callers then abbreviate for a parked reason or a report
    line, and abbreviating keeps the front — so the useful half was exactly the
    half being thrown away: a live run parked two scenarios with a reason that
    said `File "cli.py", line 327, in main` and nothing about why.

    Leading with the exception line is what makes the first 200 characters worth
    reading, and it keeps the detail lines beneath it — a schema refusal lists
    one line per offending field, and those are the actionable part.
    """
    lines = detail.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        if _EXCEPTION_LINE.match(lines[index].strip()):
            return "\n".join(lines[index:])[:2000]
    # No recognisable exception line: the tail is still the best guess, since
    # whatever the process last said is closer to why it stopped than its first
    # words were.
    return "\n".join(lines[-12:])[:2000]


def missing_context(result: dict[str, object]) -> list[str]:
    """The model's own account of what it could not resolve.

    Three sources, most direct first, because a model states this gap wherever
    the prompt gave it room and the fact is the same one either way:

    1. A top-level ``missing_context`` list. The workspace's schema does not
       define this field, but a model told to return "the smallest missing
       facts" sometimes emits it anyway, and a live DSVW run did.
    2. The summaries of proof obligations left ``needs_context``, which the
       workspace *does* require to carry a concrete summary rather than a shrug.
       This is the usual source.
    3. The overall summary, as a last resort.

    Reading only (1) is what this used to do, and it meant a live run parked
    three scenarios as "no gap stated to act on" while every one of them
    explained in its obligations exactly which callers it needed.
    """
    declared = result.get("missing_context")
    if isinstance(declared, list):
        stated = [str(item).strip() for item in declared if str(item).strip()]
        if stated:
            return stated

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


#: Fields the backlog recorder requires on every scenario before it will even
#: reach the schema. Mirrored here so a chunk carrying an incomplete scenario is
#: re-asked for one call, rather than failing the merge after the whole phase.
_REQUIRED_SCENARIO_FIELDS = frozenset({
    "id",
    "recon_item_id",
    "expert",
    "target_path",
    "proof_question",
    "evidence_required",
    "security_invariant",
    "proof_obligations",
})


class WorkspaceError(RuntimeError):
    """The workspace refused an answer or could not complete an operation."""


class Workspace(Protocol):
    """Everything the driver needs, and deliberately nothing more."""

    def state(self, ref: RunRef) -> RunState: ...

    def run_recon(self, ref: RunRef, experts: list[str]) -> None: ...

    def routing_paths(self, ref: RunRef) -> list[RoutingPath]: ...

    def scenario_errors(self, scenarios: list[Any]) -> list[str]: ...

    def valid_experts(self) -> list[str]: ...

    def read_router_chunk(self, ref: RunRef, key: str) -> str | None: ...

    def write_router_chunk(self, ref: RunRef, key: str, answer: str) -> None: ...

    def render_router_prompt(self, ref: RunRef) -> RenderedPrompt: ...

    def record_backlog(self, ref: RunRef, answer: str) -> None: ...

    def pending_scenarios(self, ref: RunRef) -> list[ScenarioRef]: ...

    def render_scenario_prompt(self, ref: RunRef, scenario_id: str) -> RenderedPrompt: ...

    def record_scenario_result(
        self, ref: RunRef, scenario_id: str, answer: str
    ) -> ScenarioOutcome: ...

    def read_source(self, ref: RunRef, path: str) -> str | None: ...

    def search_source(
        self, ref: RunRef, terms: Sequence[str], limit: int = 5
    ) -> list[str]: ...

    def write_parked(self, ref: RunRef, parked: list[ParkedScenario]) -> Path: ...

    def read_parked(self, ref: RunRef) -> list[ParkedScenario]: ...

    def pending_candidates(self, ref: RunRef) -> list[str]: ...

    def render_triage_prompt(self, ref: RunRef, candidate_id: str) -> RenderedPrompt: ...

    def record_triage(self, ref: RunRef, candidate_id: str, answer: str) -> str: ...

    def emit_sarif(self, ref: RunRef, out: Path | None = None) -> Path: ...

    def create_run(self, source: RunRef, run_id: str) -> RunRef: ...


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
        env = {
            **os.environ,
            "OPENHACK_ROOT": str(self._root),
            # UTF-8 mode, because the CLI writes prompt and result files with
            # `write_text` and no explicit encoding. On Windows that resolves to
            # cp1252, which cannot represent most of what a security review
            # writes down — a live run died on `≥` in a scenario after the
            # router phase had completed. The subprocess is where the writes
            # happen, so this is where the default has to be corrected; it is
            # not something the caller can fix by encoding its own input.
            "PYTHONUTF8": "1",
        }
        try:
            completed = subprocess.run(
                [*self._command, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
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
            detail = (completed.stderr or completed.stdout or "").strip()
            raise WorkspaceError(f"openhack {args[0]} failed: {_complaint(detail)}")
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

    def routing_paths(self, ref: RunRef) -> list[RoutingPath]:
        """Routing units grouped by the path they belong to, in recon's order.

        Grouped rather than flat because **the coverage gate judges paths**, not
        units: every path with an input and a sink needs a scenario or a
        path-level decision, and every path/expert requirement needs one too. A
        split that cut a path across two assignments would leave neither able to
        speak for it, and the merged backlog would be refused for a path that
        every chunk thought the other one owned. A live run was rejected with
        430 such errors.
        """
        grouped: dict[str, list[RoutingUnit]] = {}
        for path, unit in self._routing_units(ref):
            grouped.setdefault(path, []).append(unit)
        required = self._required_experts(ref)
        return [
            RoutingPath(
                path=path,
                units=units,
                required_experts=sorted(required.get(path, ())),
            )
            for path, units in grouped.items()
        ]

    def _required_experts(self, ref: RunRef) -> dict[str, set[str]]:
        """Path/expert pairs recon says the backlog must account for.

        Read from the same `coverage-gaps.json` the recorder's coverage gate
        reads, so an assignment can state exactly what will be asked of it
        rather than leaving the router to infer it from the raw material.
        """
        gaps = self._run_dir(ref) / "recon-output" / "coverage-gaps.json"
        if not gaps.exists():
            return {}
        try:
            data = json.loads(gaps.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - recon writes this
            return {}
        required: dict[str, set[str]] = {}
        for entry in data.get("routing_requirements", []):
            if not isinstance(entry, dict):
                continue
            path = str(entry.get("path", "")).strip()
            expert = str(entry.get("expert", "")).strip()
            if path and expert:
                required.setdefault(path, set()).add(expert)
        return required

    def _routing_units(self, ref: RunRef) -> list[tuple[str, RoutingUnit]]:
        """Every routing unit id with its path, in the order recon emitted them.

        Read rather than derived: the router prompt names these ids and the
        backlog recorder validates against them, so the driver has to split the
        work on the *same* list both ends already agree on. An empty list is a
        legitimate answer — a target with no routing units routes in one call —
        and is not the same as the file being missing, which is a broken run.
        """
        path = self._run_dir(ref) / "recon-output" / "routing-units.jsonl"
        if not path.exists():
            raise WorkspaceError(
                "routing-units.jsonl is missing; run recon before routing"
            )
        units: list[tuple[str, RoutingUnit]] = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise WorkspaceError(
                    f"unreadable routing unit on line {number}: {exc}"
                ) from exc
            unit_id = str(data.get("unit_id", "")).strip()
            if not unit_id:
                continue
            experts = data.get("required_experts")
            units.append((
                str(data.get("path", "")).strip(),
                RoutingUnit(
                    unit_id=unit_id,
                    required_experts=[str(e) for e in experts]
                    if isinstance(experts, list)
                    else [],
                    # The two the gate treats as obligations; anything else is
                    # a suggestion recon offers and the router may decline.
                    mandatory=data.get("coverage") in {"mandatory", "mandatory_path"},
                ),
            ))
        return units

    def scenario_errors(self, scenarios: list[Any]) -> list[str]:
        """Which scenarios the backlog recorder would refuse, and why.

        The recorder's *own* schema, asked earlier. The router is dozens of
        calls and one merged answer, so a single malformed scenario otherwise
        discards the whole phase at its last step — a live run lost 51 calls to
        one `recon_item_id: []` among 776 good ones. Checking per chunk turns
        that into one re-ask.

        This does not relax the recorder's check; it is the same check, run
        sooner. If the schema cannot be read the answer goes forward unjudged,
        because the recorder is still the authority and inventing a local
        opinion of admissibility is exactly what this must not do.

        The schema file is read from the workspace root rather than through
        OpenHack's own loader: that loader resolves the root from
        ``OPENHACK_ROOT``, which this adapter sets only in the *subprocess*
        environment, so importing it in-process would fail wherever the driver
        happens to be running. Reading the file directly also keeps this
        thread-safe, which matters now that scenarios dispatch concurrently.
        """
        errors: list[str] = []
        experts = set(self.valid_experts())
        validator = self._scenario_validator()
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                errors.append("scenario is not an object")
                continue
            name = scenario.get("id")
            missing = _REQUIRED_SCENARIO_FIELDS - set(scenario)
            if missing:
                errors.append(f"scenario {name} missing: {sorted(missing)}")
            if validator is not None:
                for error in validator.iter_errors(scenario):
                    path = "$" + "".join(f".{part}" for part in error.path)
                    errors.append(f"scenario {name}: {path}: {error.message}")
            expert = scenario.get("expert")
            if experts and expert not in experts:
                errors.append(f"scenario {name}: unknown expert {expert!r}")
            obligations = scenario.get("proof_obligations")
            if isinstance(obligations, list):
                ids = [
                    o.get("id") for o in obligations if isinstance(o, dict)
                ]
                if len(ids) != len(set(ids)):
                    errors.append(f"scenario {name}: duplicate proof obligation ids")
        return errors

    def valid_experts(self) -> list[str]:
        """Expert ids this workspace actually has, from the same files the
        recorder reads. Empty when the directory is absent, which leaves the
        judgement to the recorder rather than inventing one."""
        directory = self._root / "agents" / "experts"
        if not directory.is_dir():
            return []
        return sorted(path.stem for path in directory.glob("*.md"))

    def _scenario_validator(self) -> Any:
        schema_path = self._root / "config" / "scenario-schema.json"
        if not schema_path.exists():
            return None
        try:
            from jsonschema import (  # type: ignore[import-untyped]
                Draft202012Validator,
            )

            return Draft202012Validator(
                json.loads(schema_path.read_text(encoding="utf-8"))
            )
        except (ImportError, json.JSONDecodeError, OSError):  # pragma: no cover
            return None

    def _router_chunk_path(self, ref: RunRef, key: str) -> Path:
        return self._run_dir(ref) / "scenarios" / "router-chunks" / f"{key}.json"

    def read_router_chunk(self, ref: RunRef, key: str) -> str | None:
        """A chunk answer a previous attempt already paid for, if there is one.

        Router answers are durable because the phase is long: a run that dies on
        its fortieth call would otherwise discard thirty-nine paid-for answers
        and start again. Stored per chunk rather than per run so the unit of
        loss is one call.
        """
        path = self._router_chunk_path(ref, key)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    def write_router_chunk(self, ref: RunRef, key: str, answer: str) -> None:
        path = self._router_chunk_path(ref, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(answer, encoding="utf-8")

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
                    target_path=str(data.get("target_path", "")),
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
            missing_context=missing_context(data),
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

    def search_source(
        self, ref: RunRef, terms: Sequence[str], limit: int = 5
    ) -> list[str]:
        """Files in the checkout mentioning any of ``terms``, shallowest first.

        This answers the "who calls this?" half of a context expansion, which no
        amount of path resolution can: a reviewer that asks for the callers of a
        function has named a symbol, not a file, and the file it wants is
        precisely the one it could not name.

        Every term is matched in **one** walk. Per-term walks re-read the whole
        checkout once each, and the caller holds a lock across the call, so the
        cost of asking about four functions was four scans that no other worker
        could interleave with.

        Bounded and read-only, like every other checkout access here. A term
        arrives from model output, so it is matched as a literal — never
        compiled as a pattern, which would hand untrusted text control over the
        search itself. Symlinks are resolved and then contained, the same jail
        `read_source` applies and for the same reason: a checkout is a clone of
        the repository under review, and a link committed into it points
        wherever its author chose — including at the host's own files.

        Ordering by depth is a cheap proxy for relevance: an application's
        routes sit nearer the root than its vendored dependencies. The **walk**
        is ordered by depth, rather than the matches being re-ordered after the
        fact, because sorting a list that has already been cut sorts the wrong
        list — the walk yields paths alphabetically, so stopping at ``limit``
        first keeps whichever matches sort early and drops the shallow ones the
        ordering exists to surface.
        """
        root = (self._run_dir(ref) / "sourcecode").resolve()
        needles = [term.strip() for term in terms if term.strip()]
        if not needles or not root.is_dir():
            return []

        def by_depth(path: Path) -> tuple[int, str]:
            relative = path.relative_to(root)
            return len(relative.parts), relative.as_posix()

        found: list[str] = []
        for path in sorted(root.rglob("*"), key=by_depth):
            if len(found) >= limit:
                break
            if path.suffix.lower() not in _SEARCHABLE_SUFFIXES:
                continue
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
                if not resolved.is_file():
                    continue
                if resolved.stat().st_size > _MAX_SEARCH_BYTES:
                    continue
                content = resolved.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                continue
            if not any(needle in content for needle in needles):
                continue
            # the lexical path, not the resolved one: it is what the caller
            # hands back to `read_source`, which resolves and contains it again
            found.append(path.relative_to(root).as_posix())
        return found

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

    def create_run(self, source: RunRef, run_id: str) -> RunRef:
        """Create a sibling run against the same target, for a second pass.

        The target's git URL and branch are read from the first run's own
        ``run-config.yaml`` rather than taken as arguments: a second pass that
        reviewed a *different* checkout would produce findings that cannot be
        compared with the first, and the corroboration count would be measuring
        two different things.
        """
        config = self._run_dir(source) / "run-config.yaml"
        if not config.exists():
            raise WorkspaceError(
                f"cannot create a second run: {config} is missing, so the target "
                "the first pass reviewed cannot be identified"
            )
        settings: dict[str, str] = {}
        for line in config.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(":")
            if _ and key.strip() in {"git_url", "branch"}:
                settings[key.strip()] = value.strip().strip("\"'")
        git_url = settings.get("git_url", "")
        if not git_url:
            raise WorkspaceError(f"cannot create a second run: no git_url in {config}")

        args = ["init-run", source.target, git_url, "--run-id", run_id]
        if settings.get("branch"):
            args += ["--branch", settings["branch"]]
        self._run(*args)
        return RunRef(target=source.target, run_id=run_id)

    def emit_sarif(self, ref: RunRef, out: Path | None = None) -> Path:
        args = ["emit-sarif", ref.target, ref.run_id]
        if out is not None:
            args += ["--out", str(out)]
        self._run(*args)
        return out or (self._run_dir(ref) / "findings.sarif")
