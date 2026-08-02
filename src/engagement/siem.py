"""Shipping the audit trail to a SIEM.

The audit file already answers "what did the 02:00 job do" for anyone holding
it. A SIEM is where that question actually gets asked — alongside every other
system's trail, by people who will never open a run folder — so the trail has to
leave the host in a shape a correlation engine can index.

Two formats, because between them they cover essentially every deployed SIEM:

``ecs``
    Elastic Common Schema as JSON lines. Elastic ingests it natively; Splunk,
    Sentinel, Chronicle and OpenSearch all take JSON and map fields.
``cef``
    ArcSight Common Event Format, one line per event. The lingua franca for
    QRadar, ArcSight and the syslog collectors in front of most others.

The security property that governs this module is **narrowing, never widening**.
The audit trail is deliberately safe to ship: it carries prompt *digests*, token
counts and redaction *counts*, and never prompt text, model output or a redacted
value. An exporter that enriched events on the way out — by reading the run
folder, or by attaching the source a finding came from — would break that
guarantee at exactly the moment the data leaves the trust boundary, and it would
break it into a system with broad read access and long retention.

So this module is a pure function of the audit file. It adds nothing that was
not already in an event, and `tests/test_siem.py` holds it to that by asserting
every exported field traces back to one. Detail keys are additionally
allow-listed on the way out: a future event kind that starts carrying something
sensitive fails the allow-list rather than silently shipping it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from .audit import AuditEvent, Detail, read_events

FORMATS = ("ecs", "cef", "jsonl")

#: Vendor and product as they appear in CEF headers and ECS `observer` fields.
VENDOR = "codescan"
PRODUCT = "engagement"
VERSION = "0.1.0"

#: Detail keys allowed out of the process, per event kind. An unlisted key is
#: dropped and counted, never shipped: the allow-list is what keeps a future
#: event that starts carrying prompt text from quietly reaching a log platform.
#: Nothing here is free text supplied by a model.
ALLOWED_DETAILS: dict[str, frozenset[str]] = {
    "model_call": frozenset(
        {
            "phase",
            "deployment",
            "prompt_sha256",
            "input_tokens",
            "output_tokens",
            "redactions",
            "calls_so_far",
            "cache_read_tokens",
            "cache_write_tokens",
        }
    ),
    "run_started": frozenset({"target", "run_id"}),
    "resume_started": frozenset({"target", "run_id"}),
    "run_finished": frozenset(
        {
            "phase",
            "calls",
            "completed",
            "parked",
            "unfunded",
            "redactions",
            "reviewed_fraction",
            "complete",
        }
    ),
    "lifecycle_assessed": frozenset(
        {"eol", "eos", "deprecated", "unknown", "supported", "adjusted", "feed_loaded"}
    ),
    "analysis_finished": frozenset(
        {"chains", "pocs_drafted", "pocs_undrafted", "chains_unanalysed", "calls"}
    ),
}

#: Fallback for an event kind nobody has classified yet. Empty on purpose —
#: an unknown event still ships, with its identity and timestamp, and none of
#: its payload. Failing closed is the only safe default at a trust boundary.
_NO_DETAILS: frozenset[str] = frozenset()

#: ECS event categorisation, and the severity a SIEM should rank it at (0-100).
#: An unattended scanner's interesting events are the ones that mean work was
#: *not* done, so those carry the weight — a clean finish is informational.
_CLASSIFICATION: dict[str, tuple[str, str, int]] = {
    "model_call": ("process", "info", 21),
    "run_started": ("process", "start", 21),
    "resume_started": ("process", "start", 21),
    "run_finished": ("process", "end", 21),
    "lifecycle_assessed": ("vulnerability", "info", 47),
    "analysis_finished": ("vulnerability", "info", 21),
}


def _classify(event: AuditEvent) -> tuple[str, str, int]:
    return _CLASSIFICATION.get(event.kind, ("process", "info", 21))


def _severity_for(event: AuditEvent) -> int:
    """Raise the severity of an event that reports incomplete work.

    A run that finished having reviewed 40% of its backlog is the event an
    operator most needs to see, and it is indistinguishable from a clean finish
    unless the exporter says so. The signal is already in the event; this only
    makes it legible to a rule that ranks on severity.
    """
    _, _, base = _classify(event)
    if event.kind == "run_finished" and event.detail.get("complete") is False:
        return 73
    return base


def _allowed(event: AuditEvent) -> tuple[dict[str, Detail], list[str]]:
    """Split an event's detail into what may ship and what may not."""
    permitted = ALLOWED_DETAILS.get(event.kind, _NO_DETAILS)
    kept = {key: value for key, value in event.detail.items() if key in permitted}
    dropped = sorted(key for key in event.detail if key not in permitted)
    return kept, dropped


def to_ecs(event: AuditEvent, run: str = "") -> dict[str, object]:
    """One audit event as an ECS document."""
    category, kind, _ = _classify(event)
    detail, dropped = _allowed(event)
    document: dict[str, object] = {
        "@timestamp": event.timestamp,
        "event": {
            "kind": "event",
            "category": [category],
            "type": [kind],
            "action": event.kind,
            "module": PRODUCT,
            "dataset": f"{PRODUCT}.audit",
            "severity": _severity_for(event),
            "provider": VENDOR,
        },
        "observer": {"vendor": VENDOR, "product": PRODUCT, "version": VERSION},
        "labels": {str(key): value for key, value in detail.items()},
    }
    if run:
        document["trace"] = {"id": run}
    if dropped:
        # the omission is itself reportable: a consumer must be able to tell a
        # narrowed event from a complete one
        document["engagement"] = {"dropped_fields": dropped}
    return document


def _cef_escape(value: object, header: bool = False) -> str:
    text = str(value)
    text = text.replace("\\", "\\\\")
    if header:
        return text.replace("|", "\\|").replace("\n", " ")
    return text.replace("=", "\\=").replace("\n", " ")


def to_cef(event: AuditEvent, run: str = "") -> str:
    """One audit event as a CEF line.

    CEF severity is 0-10 while ECS is 0-100, so the same number is rescaled
    rather than reused — shipping a 73 into a field whose maximum is 10 would
    saturate every event at critical.
    """
    severity = min(10, max(0, round(_severity_for(event) / 10)))
    extension: list[str] = [f"rt={_cef_escape(event.timestamp)}"]
    if run:
        extension.append(f"cs1Label=runId cs1={_cef_escape(run)}")
    detail, dropped = _allowed(event)
    for key, value in detail.items():
        rendered = "true" if value is True else "false" if value is False else value
        extension.append(f"{_cef_escape(key)}={_cef_escape(rendered)}")
    if dropped:
        extension.append(f"droppedFields={_cef_escape(','.join(dropped))}")
    header = "|".join(
        _cef_escape(part, header=True)
        for part in ("CEF:0", VENDOR, PRODUCT, VERSION, event.kind, event.kind, severity)
    )
    return f"{header}|{' '.join(extension)}"


def render(events: Sequence[AuditEvent], fmt: str = "ecs", run: str = "") -> str:
    """Render a whole trail in one of the supported formats."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown SIEM format {fmt!r}; expected one of: {', '.join(FORMATS)}")
    if fmt == "cef":
        return "\n".join(to_cef(event, run) for event in events)
    if fmt == "jsonl":
        # the trail as written, for a collector that already understands it
        return "\n".join(event.model_dump_json() for event in events)
    return "\n".join(json.dumps(to_ecs(event, run), sort_keys=True) for event in events)


def export(
    audit_path: Path, out: Path, fmt: str = "ecs", run: str = ""
) -> tuple[Path, int]:
    """Convert an audit file into a SIEM-ready one. Returns the path and count."""
    events = read_events(Path(audit_path))
    body = render(events, fmt, run)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"{body}\n" if body else "", encoding="utf-8")
    return out, len(events)


def summarize(events: Iterable[AuditEvent]) -> dict[str, int]:
    """Event counts by kind — what a shipper prints so a scheduler can assert it."""
    tally: dict[str, int] = {}
    for event in events:
        tally[event.kind] = tally.get(event.kind, 0) + 1
    return tally


def stamp() -> str:
    """Export time, for a filename that will not collide across runs."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
