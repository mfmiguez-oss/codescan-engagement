"""The queue as a file someone works from.

A ranked list is the pipeline's output; a *worklist* is what an analyst needs,
and the difference is four columns:

**Where it was detected.** Path and line, plus the repository — a finding
without a location is a claim the reader has to go and re-find.

**What detected it.** Which scanner, which engine, which stage. Two independent
sources agreeing is a stronger signal than one asserting twice, and an analyst
who cannot see the provenance cannot weigh it. ``corroboration`` counts the
distinct sources; ``detected_by`` names them.

**No duplicates.** One row per real issue. Rows are merged on the finding's own
identity, and the merge is *reported* — a row that absorbed three others says so
in ``merged_count``, so nothing disappears without a trace.

**Whether it moved.** A queue is read against the last one. ``severity_delta``
and ``score_delta`` say whether this finding got worse, got better, or is new
since the previous run, and ``movement_reason`` says what moved it — lifecycle
state, exploit intelligence, or a rescan finding more corroboration. Without
that column an analyst re-reads a hundred unchanged rows to find the three that
changed.

Formula injection is neutralised: a cell that would execute in a spreadsheet is
data here too. The queue contains attacker-influenced text by construction, and
a CSV is opened in Excel far more often than it is parsed.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from pydantic import Field

from .contracts import ScoredFinding, StrictModel

#: Ordered as an analyst reads: what and where first, then why it ranks there,
#: then what changed, then the identity you quote in a ticket.
COLUMNS = [
    "rank",
    "finding_id",
    "title",
    "severity",
    "risk_score",
    "repo",
    "path",
    "line",
    "component",
    "version",
    "ecosystem",
    "detected_by",
    "corroboration",
    "merged_count",
    "lifecycle",
    "lifecycle_adjust",
    "base_score",
    "kev",
    "epss",
    "severity_delta",
    "score_delta",
    "movement_reason",
    "first_seen_run",
    "evidence",
]

#: A leading character a spreadsheet would treat as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    """Position on the severity ladder; -1 for anything unrecognised."""
    try:
        return _SEVERITY_ORDER.index(severity.strip().lower())
    except ValueError:
        return -1


def neutralize(value: str) -> str:
    """Make a cell inert in a spreadsheet without changing what it says."""
    return f"'{value}" if value.startswith(_FORMULA_PREFIXES) else value


class Baseline(StrictModel):
    """What the previous run said, keyed by finding identity.

    Only the fields movement is computed from — a baseline that carried whole
    findings would be a second copy of the queue, and would drift from it.
    """

    run_id: str = ""
    severities: dict[str, str] = Field(default_factory=dict)
    scores: dict[str, float] = Field(default_factory=dict)
    first_seen: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_findings(
        cls, findings: list[ScoredFinding], run_id: str, previous: Baseline | None = None
    ) -> Baseline:
        """Snapshot this run, carrying each finding's original first-seen run."""
        carried = previous.first_seen if previous else {}
        return cls(
            run_id=run_id,
            severities={f.id: f.severity for f in findings},
            scores={f.id: f.risk_score for f in findings},
            first_seen={f.id: carried.get(f.id, run_id) for f in findings},
        )

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path

    @classmethod
    def read(cls, path: Path) -> Baseline | None:
        """Load a previous run's baseline. A missing one is not an error.

        A malformed one is also not an error, deliberately: the baseline only
        drives a *comparison* column, and refusing to export a queue because
        last week's file is corrupt would withhold the findings over a
        nice-to-have. The caller reports it instead.
        """
        try:
            return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None


class Row(StrictModel):
    """One line of the worklist: a finding, merged, with its movement."""

    finding: ScoredFinding
    detected_by: list[str] = Field(default_factory=list)
    merged_count: int = 0
    line: int | None = None
    severity_delta: str = "new"
    score_delta: float = 0.0
    movement_reason: str = ""
    first_seen_run: str = ""

    @property
    def corroboration(self) -> int:
        """Distinct sources that reported this. One source twice is still one."""
        distinct = {source.strip().lower() for source in self.detected_by if source.strip()}
        return max(1, len(distinct))


def _merge_key(finding: ScoredFinding) -> str:
    """What makes two rows the same issue.

    The finding's own id when it has one — the backbone already minted it from
    weakness class plus location, which is the right identity. Falling back to
    the tuple keeps rows from an inventory-only source (which carry no id from
    a scanner) from colliding under an empty key.
    """
    if finding.id:
        return finding.id
    return "|".join(
        [
            finding.repo.strip().lower(),
            finding.title.strip().lower(),
            finding.path.strip().lower(),
            finding.component.strip().lower(),
        ]
    )


def dedupe(findings: list[ScoredFinding], sources: dict[str, list[str]] | None = None) -> list[Row]:
    """One row per real issue, keeping the worst score and every source.

    Merging keeps the *highest* score rather than the first or the last: two
    sources disagreeing about severity is not a reason to report the milder
    reading, and the corroboration count tells the analyst the disagreement
    exists.
    """
    provenance = sources or {}
    rows: dict[str, Row] = {}
    for finding in findings:
        key = _merge_key(finding)
        detected = list(provenance.get(finding.id, [])) or ["engagement"]
        existing = rows.get(key)
        if existing is None:
            rows[key] = Row(finding=finding, detected_by=detected)
            continue
        existing.merged_count += 1
        for source in detected:
            if source not in existing.detected_by:
                existing.detected_by.append(source)
        if finding.risk_score > existing.finding.risk_score:
            # keep the worse reading; the merge count records that it was contested
            preserved = existing.detected_by
            merged = existing.merged_count
            rows[key] = Row(finding=finding, detected_by=preserved, merged_count=merged)
    return list(rows.values())


def apply_movement(rows: list[Row], baseline: Baseline | None, run_id: str) -> None:
    """Fill in what changed since the previous run, and why.

    With no baseline every row reads ``unknown`` rather than ``new``: a first
    run has not established that anything is new, and labelling a whole queue
    "new" would train an analyst to ignore the column exactly when it starts
    being meaningful.
    """
    for row in rows:
        finding = row.finding
        if baseline is None:
            row.severity_delta = "unknown"
            row.movement_reason = "no previous run to compare against"
            row.first_seen_run = run_id
            continue

        row.first_seen_run = baseline.first_seen.get(finding.id, run_id)
        was_severity = baseline.severities.get(finding.id)
        if was_severity is None:
            row.severity_delta = "new"
            row.movement_reason = "not present in the previous run"
            continue

        was_score = baseline.scores.get(finding.id, 0.0)
        row.score_delta = round(finding.risk_score - was_score, 1)
        now, before = severity_rank(finding.severity), severity_rank(was_severity)
        if now > before:
            row.severity_delta = f"increased ({was_severity} -> {finding.severity})"
        elif now < before:
            row.severity_delta = f"decreased ({was_severity} -> {finding.severity})"
        elif row.score_delta > 0:
            row.severity_delta = "score increased"
        elif row.score_delta < 0:
            row.severity_delta = "score decreased"
        else:
            row.severity_delta = "unchanged"
        row.movement_reason = _why(row, was_score)


def _why(row: Row, was_score: float) -> str:
    """Attribute the movement to something an analyst can act on."""
    if row.score_delta == 0 and row.severity_delta == "unchanged":
        return ""
    reasons: list[str] = []
    if row.finding.lifecycle_adjust:
        reasons.append(
            f"lifecycle: component is {row.finding.lifecycle} "
            f"(+{row.finding.lifecycle_adjust:.0f})"
        )
    if row.finding.kev:
        reasons.append("listed in CISA KEV")
    if row.corroboration > 1:
        reasons.append(f"corroborated by {row.corroboration} sources")
    if not reasons:
        reasons.append(f"score moved {was_score:.1f} -> {row.finding.risk_score:.1f}")
    return "; ".join(reasons)


def to_rows(
    findings: list[ScoredFinding],
    run_id: str,
    baseline: Baseline | None = None,
    sources: dict[str, list[str]] | None = None,
) -> list[Row]:
    """Dedupe, rank, and annotate movement — the whole worklist in one call."""
    rows = dedupe(findings, sources)
    rows.sort(key=lambda row: (-row.finding.risk_score, row.finding.id))
    apply_movement(rows, baseline, run_id)
    return rows


def flatten(row: Row, rank: int) -> dict[str, str]:
    finding = row.finding
    values = {
        "rank": str(rank),
        "finding_id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "risk_score": f"{finding.risk_score:.1f}",
        "repo": finding.repo,
        "path": finding.path,
        "line": "" if row.line is None else str(row.line),
        "component": finding.component,
        "version": finding.version,
        "ecosystem": finding.ecosystem,
        "detected_by": "|".join(row.detected_by),
        "corroboration": str(row.corroboration),
        "merged_count": str(row.merged_count),
        "lifecycle": finding.lifecycle,
        "lifecycle_adjust": f"{finding.lifecycle_adjust:.1f}",
        "base_score": f"{finding.base_score:.1f}",
        "kev": str(finding.kev).lower(),
        "epss": "" if finding.epss is None else f"{finding.epss:.3f}",
        "severity_delta": row.severity_delta,
        "score_delta": f"{row.score_delta:+.1f}" if row.score_delta else "0.0",
        "movement_reason": row.movement_reason,
        "first_seen_run": row.first_seen_run,
        "evidence": finding.evidence.replace("\n", " ")[:1000],
    }
    return {key: neutralize(value) for key, value in values.items()}


def write_csv(rows: list[Row], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for rank, row in enumerate(rows, start=1):
            writer.writerow(flatten(row, rank))
    return path


def write_queue(
    findings: list[ScoredFinding],
    out_dir: Path,
    run_id: str,
    baseline_path: Path | None = None,
    sources: dict[str, list[str]] | None = None,
) -> tuple[Path, list[Row], list[str]]:
    """Write the worklist and roll the baseline forward for the next run."""
    warnings: list[str] = []
    previous: Baseline | None = None
    if baseline_path is not None:
        if Path(baseline_path).exists():
            previous = Baseline.read(Path(baseline_path))
            if previous is None:
                warnings.append(
                    f"movement: the baseline at {baseline_path} was unreadable; this "
                    "queue reports no movement rather than comparing against it"
                )
        else:
            warnings.append(
                "movement: no previous run to compare against — severity movement "
                "is reported as unknown, which is not the same as unchanged"
            )

    rows = to_rows(findings, run_id, previous, sources)
    csv_path = write_csv(rows, Path(out_dir) / "queue.csv")

    if baseline_path is not None:
        Baseline.from_findings([row.finding for row in rows], run_id, previous).write(
            Path(baseline_path)
        )
    return csv_path, rows, warnings


def movement_summary(rows: list[Row]) -> dict[str, int]:
    """Counts an operator reads before opening the file."""
    tally = {"increased": 0, "decreased": 0, "new": 0, "unchanged": 0}
    for row in rows:
        if row.severity_delta.startswith("increased") or row.severity_delta == "score increased":
            tally["increased"] += 1
        elif row.severity_delta.startswith("decreased") or row.severity_delta == "score decreased":
            tally["decreased"] += 1
        elif row.severity_delta == "new":
            tally["new"] += 1
        else:
            tally["unchanged"] += 1
    return tally


def write_manifest(rows: list[Row], path: Path, run_id: str) -> Path:
    """A machine-readable sidecar carrying what the CSV flattens."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "count": len(rows),
        "movement": movement_summary(rows),
        "findings": [
            {
                **row.finding.model_dump(),
                "detected_by": row.detected_by,
                "corroboration": row.corroboration,
                "merged_count": row.merged_count,
                "severity_delta": row.severity_delta,
                "score_delta": row.score_delta,
                "movement_reason": row.movement_reason,
                "first_seen_run": row.first_seen_run,
            }
            for row in rows
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
