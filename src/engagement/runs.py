"""Starting a scan from the console, and knowing what happened to it.

This is the surface with the most authority in the package. Every other route
reads a file or records a judgement; this one **reads a repository and spends
money**, on behalf of someone who clicked a button. Four decisions follow from
that, and each is a refusal rather than a safeguard bolted on afterwards.

**Off unless a deployment turns it on.** A control plane serving a queue has no
business starting scans, and defaulting to "available" would mean every
deployment that only wanted the read surface got the spending one too.
`engagement console --allow-runs` is the whole switch; without it the route
answers 503 and the console does not render the control.

**`scanner`, not `analyst`.** The role that may spend already exists and is
deliberately separate from the role that may adjudicate. An analyst who can
close findings still cannot start a run, because those are different
authorities and the estate has said so since `identity.py` was written.

**Its own ceiling, per request.** The launched run gets a budget set by the
deployment, not by the caller. A caller-supplied ceiling is not a ceiling.

**One at a time, per target.** Two concurrent runs against one target race on
the workspace's own files, and the second would corrupt the first's state while
both reported success. The claim is held in this process for the same reason
the rate limiter lives here: it bounds one process honestly rather than
pretending to bound a fleet.

The run itself executes in a subprocess — the same CLI an operator would type,
with the same arguments. Not an in-process call: a scan is long, and a failure
inside one should not be able to take the control plane down with it.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from .contracts import StrictModel
from .identity import Principal

#: How long a finished record is kept so the console can show the outcome.
#: Long enough for someone to come back after lunch, short enough that a
#: long-lived process does not accumulate them without bound.
RETAIN_SECONDS = 6 * 60 * 60


class RunRequest(StrictModel):
    """What the caller may choose. Deliberately small.

    Everything that costs money — the budget, the model, whether advisory
    stages run — is the deployment's to set. The caller names a target and a
    repository, which is the part only they know.
    """

    target: str
    run_id: str = ""
    repo: str = ""

    def resolved_run_id(self) -> str:
        """A run id the caller did not choose, unless they did.

        Generated ids carry the date and a short random suffix so two runs
        started in the same minute cannot collide — a collision would have one
        run writing into another's directory, which the workspace would treat
        as resumption rather than as the error it is.
        """
        if self.run_id.strip():
            return self.run_id.strip()
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return f"web-{stamp}-{uuid.uuid4().hex[:6]}"


class RunRecord(StrictModel):
    """What a launched run is doing, or did."""

    id: str
    target: str
    run_id: str
    started_by: str
    started_at: str
    status: str = "running"
    exit_code: int | None = None
    #: The last few lines the CLI wrote. Bounded, and never the whole log: the
    #: console shows progress, and a run's own artifacts are where its output
    #: actually lives.
    tail: list[str] = []
    finished_at: str | None = None

    @property
    def finished(self) -> bool:
        return self.status != "running"


#: Lines of CLI output kept per run.
MAX_TAIL = 40


class RunLauncher:
    """Starts runs as subprocesses and tracks them.

    Injected into the control plane as a protocol, so the HTTP surface never
    learns what a subprocess is and the gate never starts one.
    """

    def __init__(
        self,
        workspace: Path,
        env: Mapping[str, str],
        model: str,
        max_calls: int = 200,
        extra_args: list[str] | None = None,
    ) -> None:
        self._workspace = Path(workspace)
        self._env = dict(env)
        self._model = model
        self._max_calls = max_calls
        self._extra = list(extra_args or [])
        self._records: dict[str, RunRecord] = {}
        self._active_targets: set[str] = set()
        self._lock = Lock()

    # -- the command --------------------------------------------------------

    def command(self, request: RunRequest, run_id: str) -> list[str]:
        """The exact command that would run. Pure, so it is testable offline
        and reviewable without starting anything."""
        argv = [
            sys.executable,
            "-c",
            "from engagement.cli import main; import sys; sys.exit(main())",
            "run",
            request.target,
            run_id,
            "--workspace",
            str(self._workspace),
            "--model",
            self._model,
            "--max-calls",
            str(self._max_calls),
            "--triage",
        ]
        if request.repo.strip():
            argv += ["--repo", request.repo.strip()]
        return argv + self._extra

    # -- launching ----------------------------------------------------------

    def start(self, principal: Principal, request: RunRequest) -> RunRecord:
        """Begin a run, or refuse because one is already going for this target."""
        target = request.target.strip()
        if not target:
            raise ValueError("a run must name a target")
        run_id = request.resolved_run_id()

        with self._lock:
            self._reap()
            if target in self._active_targets:
                raise RuntimeError(
                    f"a run against {target} is already in progress; two runs "
                    "against one target race on the workspace's own files"
                )
            self._active_targets.add(target)
            record = RunRecord(
                id=uuid.uuid4().hex[:12],
                target=target,
                run_id=run_id,
                started_by=principal.actor(),
                started_at=datetime.now(UTC).isoformat(),
            )
            self._records[record.id] = record

        thread = threading.Thread(
            target=self._execute, args=(record.id, request, run_id), daemon=True
        )
        thread.start()
        return record

    def _execute(self, record_id: str, request: RunRequest, run_id: str) -> None:
        argv = self.command(request, run_id)
        try:
            process = subprocess.run(  # noqa: S603 - argv is built here, never from input
                argv,
                capture_output=True,
                text=True,
                env=self._env,
                timeout=6 * 60 * 60,
            )
            code = process.returncode
            output = (process.stdout or "") + (process.stderr or "")
        except subprocess.TimeoutExpired:
            code, output = 124, "the run exceeded its wall-clock limit and was stopped"
        except Exception as exc:  # noqa: BLE001 - a launch failure is a run outcome
            code, output = 1, f"could not start the run: {type(exc).__name__}"

        with self._lock:
            record = self._records.get(record_id)
            if record is not None:
                record.exit_code = code
                # Exit 3 is "finished, but left work parked or unfunded". It is
                # not a failure and must not be shown as one, or an operator
                # learns to ignore the status entirely.
                record.status = {0: "complete", 3: "incomplete"}.get(code, "failed")
                record.tail = output.strip().splitlines()[-MAX_TAIL:]
                record.finished_at = datetime.now(UTC).isoformat()
            self._active_targets.discard(request.target.strip())

    # -- reading ------------------------------------------------------------

    def get(self, record_id: str) -> RunRecord | None:
        with self._lock:
            return self._records.get(record_id)

    def list(self) -> list[RunRecord]:
        """Newest first, so the console shows what just happened."""
        with self._lock:
            self._reap()
            return sorted(
                self._records.values(), key=lambda r: r.started_at, reverse=True
            )

    def _reap(self) -> None:
        """Drop finished records past the retention window.

        Called under the lock from both readers and the writer, so a long-lived
        console does not accumulate records for the life of the process.
        """
        if len(self._records) < 200:
            return
        cutoff = datetime.now(UTC).timestamp() - RETAIN_SECONDS
        for key, record in list(self._records.items()):
            if not record.finished or not record.finished_at:
                continue
            if datetime.fromisoformat(record.finished_at).timestamp() < cutoff:
                self._records.pop(key, None)
