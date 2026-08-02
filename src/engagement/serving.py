"""Wiring the console to a run on disk.

:mod:`engagement.api` defines what the HTTP surface needs — a queue to show and
a drafter to call — as protocols, so it never learns where runs live. This is
the other half: the two small adapters that read a real run directory, and the
assembly that puts a serveable application together from them.

Kept apart from ``api`` on purpose. The handlers are pure functions over
injected collaborators and are tested without a socket or a filesystem; the
moment they knew about paths, that would stop being true.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .analysis import draft_requested
from .audit import AuditLog, FileSink
from .budget import Budget, Ledger
from .dispatch import Dispatcher
from .export import read_manifest
from .identity import Principal
from .providers import ModelProvider


class ManifestQueue:
    """The ranked queue, read from a run's ``queue.json`` on every request.

    Re-read rather than cached in memory because a run can be re-executed
    underneath a console that is still open, and an analyst working from a
    silently stale queue is worse off than one who sees it change. The file is
    small and this is a single-analyst surface; correctness is worth the read.

    Given a workspace root it also *discovers* runs, so one console can serve
    every run in a workspace rather than being pinned to whichever directory it
    was started against. A run the operator has to restart the console to look
    at is a run they do not look at.
    """

    def __init__(self, run_dir: Path, workspace: Path | None = None) -> None:
        self._run_dir = Path(run_dir)
        self._workspace = Path(workspace) if workspace else _workspace_of(self._run_dir)
        self._selected = self._run_dir

    def runs(self) -> list[dict[str, Any]]:
        """Every run in the workspace that produced a queue, newest first.

        A run with no `queue.json` is omitted rather than listed as empty: it
        either has not reached export or was not triaged, and showing it as a
        run with no findings would be the exact confusion the whole package
        works to avoid.
        """
        found: list[dict[str, Any]] = []
        root = self._workspace / "runs"
        if not root.is_dir():
            return self._only_selected()
        for manifest in sorted(root.glob("*/*/queue.json")):
            run_dir = manifest.parent
            found.append(
                {
                    "id": f"{run_dir.parent.name}/{run_dir.name}",
                    "target": run_dir.parent.name,
                    "run_id": run_dir.name,
                    "findings": _count(manifest),
                    "modified": manifest.stat().st_mtime,
                    "has_threat_model": (run_dir / "threat-model.md").exists(),
                }
            )
        if not found:
            return self._only_selected()
        # The run the console was started against is marked, and the page
        # opens on it. Newest-first is the right *order*, but defaulting to it
        # would show an operator who pointed at one run a different one.
        selected = f"{self._run_dir.parent.name}/{self._run_dir.name}"
        for row in found:
            row["selected"] = row["id"] == selected
        return sorted(found, key=lambda row: row["modified"], reverse=True)

    def _only_selected(self) -> list[dict[str, Any]]:
        manifest = self._run_dir / "queue.json"
        if not manifest.exists():
            return []
        return [
            {
                "id": f"{self._run_dir.parent.name}/{self._run_dir.name}",
                "target": self._run_dir.parent.name,
                "run_id": self._run_dir.name,
                "findings": _count(manifest),
                "modified": manifest.stat().st_mtime,
                "has_threat_model": (self._run_dir / "threat-model.md").exists(),
                "selected": True,
            }
        ]

    def select(self, run: str | None) -> Path:
        """Resolve a `target/run-id` to a directory inside the workspace.

        Resolved and then checked against the workspace root, because the value
        arrives over HTTP: `../../etc` is a path traversal wearing a run id, and
        joining it without checking would let a caller read any `queue.json` on
        the host.
        """
        if not run:
            return self._run_dir
        candidate = (self._workspace / "runs" / run).resolve()
        root = (self._workspace / "runs").resolve()
        if not candidate.is_relative_to(root):
            raise ValueError("run id escapes the workspace")
        if not (candidate / "queue.json").exists():
            raise ValueError("no such run")
        return candidate

    def findings(self, run: str | None = None) -> list[dict[str, Any]]:
        run_dir = self.select(run)
        path = run_dir / "queue.json"
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for finding in read_manifest(path):
            data = finding.model_dump(mode="json")
            data["base_score"] = finding.base_score
            data["total_adjust"] = finding.total_adjust
            rows.append(data)
        return rows

    def detail(self, fingerprint: str, run: str | None = None) -> dict[str, Any]:
        """Everything this run knows about one finding.

        Assembled here rather than in the page because it spans three files.
        Absent pieces come back as `null` and empty lists, and the console says
        which — "no chain mentions this finding" and "chain discovery never ran"
        are different facts and the page is told which one it has.
        """
        run_dir = self.select(run)
        finding = next(
            (row for row in self.findings(run) if row.get("id") == fingerprint), None
        )
        chains = _read_json(run_dir / "chains.json")
        pocs = _read_json(run_dir / "pocs.json")
        return {
            "finding": finding,
            "chains": [
                chain
                for chain in (chains if isinstance(chains, list) else [])
                if isinstance(chain, dict)
                and fingerprint in (chain.get("finding_ids") or [])
            ],
            "chains_ran": chains is not None,
            "poc": next(
                (
                    poc
                    for poc in (pocs if isinstance(pocs, list) else [])
                    if isinstance(poc, dict) and poc.get("finding_id") == fingerprint
                ),
                None,
            ),
            "pocs_ran": pocs is not None,
        }


def _workspace_of(run_dir: Path) -> Path:
    """`<workspace>/runs/<target>/<run-id>` back to `<workspace>`."""
    parents = run_dir.resolve().parents
    return parents[2] if len(parents) >= 3 else run_dir.resolve()


def _count(manifest: Path) -> int:
    payload = _read_json(manifest)
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        return len(payload["findings"])
    return 0


def _read_json(path: Path) -> Any:
    """Contents, or ``None`` when the file is absent or unreadable.

    ``None`` means "this stage did not run or left nothing", which the caller
    reports as such. An unreadable artifact must not become an empty one — that
    is how "we could not tell" turns into "there is nothing".
    """
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class RunPocDrafter:
    """Drafts a PoC against a run's own queue, on an analyst's request.

    Each request gets a **fresh ledger**, deliberately. The run's ledger bounds
    what the unattended run was authorised to spend and is long since closed;
    reusing it would either let a console spend a finished run's headroom or
    refuse forever once that run had used it. What bounds this path is a
    per-request ceiling, which is the honest shape: a person asked, a person's
    request is bounded.
    """

    def __init__(
        self,
        run_dir: Path,
        provider: ModelProvider,
        deployment: str,
        max_calls: int = 4,
        audit: AuditLog | None = None,
    ) -> None:
        self._run_dir = Path(run_dir)
        self._provider = provider
        self._deployment = deployment
        self._max_calls = max_calls
        self._audit = audit or AuditLog(FileSink(self._run_dir / "audit.jsonl"))

    def draft(self, principal: Principal, fingerprint: str) -> dict[str, Any]:
        findings = read_manifest(self._run_dir / "queue.json")
        self._audit.record(
            "poc_requested",
            actor=principal.actor(),
            findings=1,
            deployment=self._deployment,
        )
        dispatcher = Dispatcher(
            self._provider,
            Ledger(budget=Budget(max_calls=self._max_calls)),
            self._audit,
        )
        summary = draft_requested(
            findings, dispatcher, self._deployment, [fingerprint]
        )
        self._audit.record(
            "poc_request_finished",
            actor=principal.actor(),
            drafted=len(summary.drafted),
            undrafted=len(summary.pocs_undrafted),
            calls=summary.model_calls,
        )
        drafted = summary.drafted
        return {
            "finding_id": fingerprint,
            "drafted": bool(drafted),
            # The draft itself is returned rather than only written, so an
            # analyst sees the answer to the question they asked. Preconditions
            # first: they are what decides whether the path is really open.
            "poc": drafted[0].model_dump(mode="json") if drafted else None,
            "warnings": summary.warnings,
            "calls": summary.model_calls,
        }
