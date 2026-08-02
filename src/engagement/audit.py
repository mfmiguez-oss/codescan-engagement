"""Append-only record of what a run actually did.

An unattended run makes decisions and spends money with nobody watching, so the
only answer to "what did the 02:00 job send, to which model, and what did it
cost" is whatever it wrote down. Counting calls in memory is not that: the
ledger knows there were seven, and cannot say what any of them were.

Two rules, both borrowed from the rest of the estate because they are right:

- **The file sink is authoritative.** A write failure here is a real error, not
  a warning — a run that cannot record what it is doing should stop doing it.
- **Nothing sensitive is recorded.** Events carry prompt *digests*, token
  counts, and redaction *counts*; never prompt text, never model output, never
  a redacted value. The audit trail must be safe to ship to a log platform
  that the source under review is not.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import Field

from .contracts import StrictModel

#: Values an event detail may carry. Deliberately excludes nested structures,
#: which is how prompt text ends up in a log by accident.
Detail = str | int | float | bool | None


class AuditEvent(StrictModel):
    kind: str
    detail: dict[str, Detail] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class FileSink:
    """Authoritative append-only sink. A write failure here is a real error."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def emit(self, event: AuditEvent) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")


class MemorySink:
    """For the gate, and for a caller that wants events without a file."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class NullSink:
    """Records nothing. Explicit, so an unaudited run is a visible choice."""

    def emit(self, event: AuditEvent) -> None:
        return None


class AuditLog:
    """Records to one authoritative sink."""

    def __init__(self, sink: AuditSink | None = None) -> None:
        self._sink = sink or NullSink()

    def record(self, kind: str, **detail: Detail) -> AuditEvent:
        event = AuditEvent(kind=kind, detail=dict(detail))
        self._sink.emit(event)
        return event

    def dispatch(
        self,
        phase: str,
        deployment: str,
        prompt_digest: str,
        input_tokens: int,
        output_tokens: int,
        redactions: int,
        calls_so_far: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> AuditEvent:
        """One model call. The digest identifies the prompt without carrying it.

        Cache counts sit beside the token counts rather than folded into them:
        what a call cost and what it would have cost uncached are different
        questions, and a trail that recorded only a total could answer neither
        after the fact.
        """
        return self.record(
            "model_call",
            phase=phase,
            deployment=deployment,
            prompt_sha256=prompt_digest,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            redactions=redactions,
            calls_so_far=calls_so_far,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
        )


def default_audit_path(workspace: Path, target: str, run_id: str) -> Path:
    """Where a run's trail lives: beside the run it describes.

    Next to the parked queue and the SARIF export rather than in a central log
    directory, so archiving a run folder archives the evidence of what produced
    it — and copying one somewhere else cannot leave its trail behind.
    """
    return workspace / "runs" / target / run_id / "audit.jsonl"


def read_events(path: Path) -> list[AuditEvent]:
    """Read an audit file back. A malformed line is an error, not a skip."""
    events: list[AuditEvent] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                events.append(AuditEvent.model_validate_json(stripped))
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: unreadable audit event: {exc}") from exc
    return events
