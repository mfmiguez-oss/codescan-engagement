"""The authenticated write path.

This is where the estate's oldest invariant finally has everything it needs: a
machine proposal never overwrites a human decision, a terminal state is never
silently re-opened, and — new here — the "human" in that sentence is a verified
principal rather than a string the writer chose.

One function, :func:`resolve_write`, holds the overwrite rule, and every store
routes through it. Re-expressing the rule per backend is how backends drift,
and a rule about authority that two backends disagree about is not a rule.

Authorization and resolution are separate steps on purpose. Authorization asks
"may this principal set this state at all?" and is answered by
:mod:`engagement.identity` before anything is read. Resolution asks "does this
write win against what is already recorded?" and is answered here. A caller
that skips the first can still not smuggle a machine actor past the second.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Protocol

from pydantic import Field

from .contracts import StrictModel
from .identity import (
    MACHINE_STATES,
    TERMINAL_STATES,
    Action,
    Principal,
    ValidationState,
    authorize,
)


class DecisionError(RuntimeError):
    """The write was structurally invalid."""


class Decision(StrictModel):
    """One recorded judgement about one finding."""

    fingerprint: str
    state: ValidationState
    #: The verified principal's subject. Never a display name, which changes.
    actor: str
    actor_display: str = ""
    tenant: str = ""
    note: str | None = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    #: True when written by an unattended run rather than a person.
    machine: bool = False

    @classmethod
    def by(
        cls,
        principal: Principal,
        fingerprint: str,
        state: ValidationState,
        note: str | None = None,
    ) -> Decision:
        return cls(
            fingerprint=fingerprint,
            state=state,
            actor=principal.actor(),
            actor_display=principal.display,
            tenant=principal.tenant,
            note=note,
            machine=principal.is_machine,
        )


def resolve_write(existing: Decision | None, incoming: Decision) -> Decision:
    """Decide which record survives. The single home of the overwrite rule.

    - A human decision is never overwritten by a machine proposal.
    - A terminal state is never re-opened by a machine proposal.
    - A machine proposal may only set non-terminal machine states.
    - A human may set anything they are authorized to set, including
      overriding another human — that is a judgement call the audit trail
      records rather than one this function second-guesses.
    """
    if incoming.machine:
        if incoming.state not in MACHINE_STATES:
            raise DecisionError(
                f"machine proposals may only set "
                f"{sorted(item.value for item in MACHINE_STATES)}, "
                f"not {incoming.state.value!r}"
            )
        if existing is not None and not existing.machine:
            return existing
        if existing is not None and existing.state in TERMINAL_STATES:
            return existing
    return incoming


class DecisionStore(Protocol):
    def get(self, fingerprint: str) -> Decision | None: ...

    def put(self, incoming: Decision) -> Decision: ...

    def all(self) -> list[Decision]: ...


class _BaseStore:
    """Shared write path. Subclasses supply storage, never the rule."""

    def __init__(self) -> None:
        self._lock = Lock()

    def put(self, incoming: Decision) -> Decision:
        """Apply the overwrite rule and persist whatever survived.

        Read and write happen under one lock so two concurrent writers cannot
        both read the same prior state and both decide they win.
        """
        with self._lock:
            existing = self.get(incoming.fingerprint)
            resolved = resolve_write(existing, incoming)
            if resolved is not existing:
                self._write(resolved)
            return resolved

    def get(self, fingerprint: str) -> Decision | None:  # pragma: no cover
        raise NotImplementedError

    def _write(self, decision: Decision) -> None:  # pragma: no cover
        raise NotImplementedError


class MemoryDecisionStore(_BaseStore):
    def __init__(self) -> None:
        super().__init__()
        self._records: dict[str, Decision] = {}

    def get(self, fingerprint: str) -> Decision | None:
        return self._records.get(fingerprint)

    def _write(self, decision: Decision) -> None:
        self._records[decision.fingerprint] = decision

    def all(self) -> list[Decision]:
        return list(self._records.values())


class JsonlDecisionStore(_BaseStore):
    """Append-only decision log; current state is the last line per finding.

    Append-only rather than update-in-place because the history is the point:
    "who closed this, and when" is a question an auditor asks about a finding
    that is currently open, and an overwriting store cannot answer it.
    """

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = Path(path)

    def _read_all(self) -> Iterator[Decision]:
        if not self._path.exists():
            return iter(())

        def rows() -> Iterator[Decision]:
            with self._path.open("r", encoding="utf-8") as handle:
                for number, line in enumerate(handle, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        yield Decision.model_validate_json(stripped)
                    except ValueError as exc:
                        # a corrupt line is an error, not a skip: silently
                        # dropping one loses a decision, which is the one thing
                        # this file exists to never do
                        raise DecisionError(
                            f"{self._path}:{number}: unreadable decision: {exc}"
                        ) from exc

        return rows()

    def get(self, fingerprint: str) -> Decision | None:
        latest: Decision | None = None
        for decision in self._read_all():
            if decision.fingerprint == fingerprint:
                latest = decision
        return latest

    def _write(self, decision: Decision) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(decision.model_dump_json() + "\n")

    def all(self) -> list[Decision]:
        latest: dict[str, Decision] = {}
        for decision in self._read_all():
            latest[decision.fingerprint] = decision
        return list(latest.values())

    def history(self, fingerprint: str) -> list[Decision]:
        """Every decision ever recorded for one finding, oldest first."""
        return [d for d in self._read_all() if d.fingerprint == fingerprint]


def record_decision(
    principal: Principal,
    store: DecisionStore,
    fingerprint: str,
    state: ValidationState,
    note: str | None = None,
    tenant: str | None = None,
) -> Decision:
    """Authorize, then write. The only supported way to change a state.

    Authorization runs *before* the store is touched, so an unauthorized
    attempt leaves no trace in the decision log beyond whatever the caller
    chooses to log about the refusal.
    """
    authorize(principal, Action.set_state, state, tenant=tenant)
    return store.put(Decision.by(principal, fingerprint, state, note))
