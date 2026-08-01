"""The deterministic triage backbone: ingest, dedup, enrich, score, rank.

Ported from `triagekit` rather than depended on. The dependency was a private
git reference, which meant the whole second half of this pipeline — lifecycle,
chains, PoC drafts, the worklist — sat behind credentials and a network fetch at
install time, and degraded to a *warning* when it was missing. A run that could
not score looked exactly like a run that found nothing worth scoring.

Porting was the right trade because of what was actually used. The backbone is
~450 lines of deterministic, offline arithmetic; the package it came from is
~2,900, and the remainder is a second LLM gateway, a second CLI, a second audit
log and a second state store — all things this package already has. Vendoring
would have imported a competing implementation of half of itself. That is the
asymmetry with the OpenHack workspace, which is vendored precisely because it
*complements* the driver rather than duplicating it.

**Fingerprinting and the weakness table are ported verbatim, deliberately.** A
fingerprint is a finding's identity: every analyst decision, every validation
state, and every baseline comparison is keyed on it. A port that hashed even
slightly differently would silently orphan all of them at the moment of the
switch — every finding would read as new, and every prior decision would stop
matching the finding it was made about. `tests/test_backbone_conformance.py`
holds this to the original byte-for-byte whenever `triagekit` happens to be
installed, the same way the vendored workspace is held to its upstream.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field

from .contracts import StrictModel


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


#: Points a severity contributes before weighting. Not linear: the gap between
#: high and critical is deliberately smaller than the gap between low and
#: medium, because the bottom of the ladder is where over-reporting lives.
SEVERITY_VALUE: dict[Severity, float] = {
    Severity.info: 10.0,
    Severity.low: 30.0,
    Severity.medium: 55.0,
    Severity.high: 80.0,
    Severity.critical: 100.0,
}

_SEVERITY_ORDER = [
    Severity.info,
    Severity.low,
    Severity.medium,
    Severity.high,
    Severity.critical,
]


class Location(StrictModel):
    path: str
    line: int | None = None


class Component(StrictModel):
    name: str
    version: str | None = None
    ecosystem: str | None = None


class Adjustment(StrictModel):
    reason: str
    delta: float


class ScoreBreakdown(StrictModel):
    """Every weighted dimension, the weights, every adjustment, and the floor.

    ``base_score + adjustments`` must reconcile exactly to ``final_score``
    unless ``kev_floor_applied`` records that the floor, not the blend, set it.
    A composite score that cannot be taken apart is a number an analyst has to
    take on faith, and the first thing challenged when it disagrees with them.
    """

    values: dict[str, float]
    weights: dict[str, float]
    base_score: float
    adjustments: list[Adjustment] = Field(default_factory=list)
    kev_floor_applied: bool = False
    floor: float | None = None
    final_score: float

    def reconciles(self) -> bool:
        blended = self.base_score + sum(a.delta for a in self.adjustments)
        blended = max(0.0, min(100.0, blended))
        if self.kev_floor_applied:
            return self.floor is not None and self.final_score == self.floor > blended
        return abs(self.final_score - blended) < 1e-9


class Finding(StrictModel):
    """A single weakness, source-agnostic once ingested."""

    fingerprint: str
    repo: str
    title: str
    severity: Severity
    weakness_id: str | None = None
    vuln_id: str | None = None
    component: Component | None = None
    location: Location | None = None
    scanners: list[str] = Field(default_factory=list)
    corroboration: int = 1
    raw_detection_count: int = 1
    evidence: str = ""
    kev: bool = False
    epss: float | None = None
    exposure: float = 0.0
    chaining: float = 0.0
    ai_exploitability: float | None = None
    ai_rationale: str | None = None
    risk_score: float | None = None
    breakdown: ScoreBreakdown | None = None


class FingerprintError(ValueError):
    """A finding lacks the keys its identity requires."""


class ScoreError(RuntimeError):
    """A score failed to reconcile with its own breakdown."""


# ---------------------------------------------------------------------------
# Identity. Ported verbatim — see the module docstring.
# ---------------------------------------------------------------------------

_CWE_RE = re.compile(r"^(?:cwe-?)?0*(\d+)$", re.IGNORECASE)
_LABEL_SEPARATORS = re.compile(r"[\s_-]+")

#: Labels scanners return instead of a CWE id, mapped to the id they
#: unambiguously mean. Deliberately conservative: merging is irreversible in the
#: queue, so a *wrong* mapping hides a genuinely distinct finding — which makes
#: an over-eager synonym table a suppression surface of its own. Labels whose
#: CWE correspondence is arguable (broken access control, insecure cookie,
#: timing bypass) are left alone to stay distinct; they still benefit from
#: separator normalisation below.
_WEAKNESS_SYNONYMS: dict[str, str] = {
    "XSS": "CWE-79",
    "CROSS_SITE_SCRIPTING": "CWE-79",
    "REFLECTED_XSS": "CWE-79",
    "STORED_XSS": "CWE-79",
    "SQLI": "CWE-89",
    "SQL_INJECTION": "CWE-89",
    "COMMAND_INJECTION": "CWE-78",
    "OS_COMMAND_INJECTION": "CWE-78",
    "CODE_INJECTION": "CWE-94",
    "PATH_TRAVERSAL": "CWE-22",
    "DIRECTORY_TRAVERSAL": "CWE-22",
    "FILE_INCLUSION": "CWE-98",
    "LFI": "CWE-98",
    "RFI": "CWE-98",
    "HARDCODED_CREDENTIALS": "CWE-798",
    "HARDCODED_CREDENTIAL": "CWE-798",
    "HARDCODED_PASSWORD": "CWE-798",
    "CSRF": "CWE-352",
    "CROSS_SITE_REQUEST_FORGERY": "CWE-352",
    "INSECURE_DESERIALIZATION": "CWE-502",
    "SESSION_FIXATION": "CWE-384",
    "OPEN_REDIRECT": "CWE-601",
    "UNVALIDATED_REDIRECT": "CWE-601",
    "WEAK_PASSWORD_HASHING": "CWE-916",
    "INSECURE_CRYPTOGRAPHY": "CWE-327",
    "WEAK_SESSION_ID": "CWE-330",
    "INFORMATION_DISCLOSURE": "CWE-200",
    "NO_BRUTE_FORCE_PROTECTION": "CWE-307",
    "INSUFFICIENT_BRUTE_FORCE_PROTECTION": "CWE-307",
}


def canonical_weakness(weakness: str) -> str:
    """Canonicalise weakness ids so spelling variants hash identically.

    Three layers: a numeric or ``CWE-nn`` id becomes ``CWE-<int>``; a known
    label becomes the CWE id it means; anything else keeps its own identity with
    separators and case normalised, so ``PATH-TRAVERSAL`` and ``path_traversal``
    cannot split one finding into two.
    """
    raw = weakness.strip()
    match = _CWE_RE.match(raw)
    if match:
        return f"CWE-{int(match.group(1))}"
    label = _LABEL_SEPARATORS.sub("_", raw.upper()).strip("_")
    return _WEAKNESS_SYNONYMS.get(label, label)


def normalize_path(path: str) -> str:
    """Normalise separators, leading ``./`` and case before hashing."""
    normalised = path.strip().replace("\\", "/").lower()
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised.lstrip("/")


def normalize_component(component: Component) -> str:
    ecosystem = (component.ecosystem or "").strip().lower()
    return f"{ecosystem}:{component.name.strip().lower()}"


def compute_fingerprint(
    repo: str,
    *,
    vuln_id: str | None = None,
    component: Component | None = None,
    weakness_id: str | None = None,
    path: str | None = None,
) -> str:
    """Mint a finding's identity locally.

    Dependency findings key on vulnerability id + normalised component + repo;
    the manifest path is excluded because scanners disagree about which manifest
    to blame. Code findings key on weakness class + normalised path + repo;
    excluding the path there would collapse every instance of a weakness class
    into one finding, which is silent suppression.
    """
    repo_key = repo.strip().lower()
    if component is not None:
        if not vuln_id:
            raise FingerprintError("a dependency finding needs a vulnerability id")
        key = (
            f"dep|{repo_key}|{vuln_id.strip().upper()}|{normalize_component(component)}"
        )
    else:
        if not weakness_id or not path:
            raise FingerprintError("a code finding needs a weakness id and a path")
        key = f"code|{repo_key}|{canonical_weakness(weakness_id)}|{normalize_path(path)}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def clamp_score(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a number into range. Not-a-number becomes the floor."""
    if value != value:  # NaN
        return lo
    return max(lo, min(hi, float(value)))


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


class IngestError(StrictModel):
    source: str
    entry: str
    message: str


class IngestReport(StrictModel):
    """Findings plus what was left out.

    A dropped entry is a suppression surface, so it is carried alongside the
    results rather than logged and forgotten.
    """

    findings: list[Finding] = Field(default_factory=list)
    errors: list[IngestError] = Field(default_factory=list)


_SARIF_LEVEL_TO_SEVERITY = {
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.low,
    "none": Severity.info,
}


def parse_sarif(path: Path, repo: str) -> IngestReport:
    """Code findings: SARIF ``runs[].results[]`` with ruleId as weakness id.

    Defensive per entry: a malformed result costs that result, not the run — but
    the cost is *reported*, never silent.
    """
    report = IngestReport()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    runs = data.get("runs")
    if not isinstance(runs, list):
        report.errors.append(
            IngestError(source=Path(path).name, entry="<root>", message="no 'runs'")
        )
        return report

    for run_index, run in enumerate(runs):
        tool = "sarif"
        try:
            tool = str(run["tool"]["driver"]["name"]).lower()
        except Exception:  # noqa: BLE001 - a nameless tool is not a broken run
            pass
        for result_index, result in enumerate(run.get("results") or []):
            entry = f"runs[{run_index}].results[{result_index}]"
            try:
                rule_id = str(result["ruleId"])
                physical: dict[str, Any] = result["locations"][0]["physicalLocation"]
                file_path = str(physical["artifactLocation"]["uri"])
                line = physical.get("region", {}).get("startLine")
                report.findings.append(
                    Finding(
                        fingerprint=compute_fingerprint(
                            repo, weakness_id=rule_id, path=file_path
                        ),
                        repo=repo,
                        title=str(result.get("message", {}).get("text") or rule_id),
                        severity=_SARIF_LEVEL_TO_SEVERITY.get(
                            str(result.get("level", "warning")), Severity.medium
                        ),
                        weakness_id=rule_id,
                        location=Location(path=file_path, line=int(line) if line else None),
                        scanners=[tool],
                        evidence=str(result.get("message", {}).get("text") or ""),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one bad result, reported
                report.errors.append(
                    IngestError(source=Path(path).name, entry=entry, message=str(exc))
                )
    return report


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def _max_severity(left: Severity, right: Severity) -> Severity:
    return left if _SEVERITY_ORDER.index(left) >= _SEVERITY_ORDER.index(right) else right


def merge_pair(base: Finding, other: Finding) -> Finding:
    """Merge two reports of the same issue, keeping the worse claim."""
    scanners = list(dict.fromkeys([*base.scanners, *other.scanners]))
    return base.model_copy(
        update={
            "scanners": scanners,
            "corroboration": len(scanners),
            "raw_detection_count": base.raw_detection_count + other.raw_detection_count,
            "severity": _max_severity(base.severity, other.severity),
            "evidence": base.evidence or other.evidence,
            "weakness_id": base.weakness_id or other.weakness_id,
            "location": base.location or other.location,
        }
    )


def dedup(findings: list[Finding]) -> list[Finding]:
    """One finding per fingerprint.

    Corroboration across scanners is signal, not a duplicate to discard: the
    merged finding records how many independent sources reported it and keeps
    the highest severity any of them claimed.
    """
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.fingerprint)
        merged[finding.fingerprint] = (
            finding if existing is None else merge_pair(existing, finding)
        )
    return list(merged.values())


# ---------------------------------------------------------------------------
# Enrich
# ---------------------------------------------------------------------------


class EnrichmentError(FileNotFoundError):
    """A feed the caller asked for was missing or unreadable."""


def load_kev(path: Path) -> set[str]:
    """KEV membership for scoring.

    Delegates the shape-handling to :func:`engagement.feeds.load_kev` rather
    than re-implementing it: this used to parse CISA's catalogue a second time,
    and two readers of one format drift. Use ``feeds.load_kev`` directly when
    the caller also needs the catalogue's age — which the ingest stage does,
    because a stale catalogue silently scores exploited CVEs as un-exploited.
    """
    from .feeds import FeedError
    from .feeds import load_kev as load_catalogue

    if not Path(path).exists():
        raise EnrichmentError(
            f"KEV catalogue not found at {path}; supply one, run "
            "'engagement fetch-kev', or omit --feeds explicitly"
        )
    try:
        return load_catalogue(Path(path)).ids
    except FeedError as exc:
        raise EnrichmentError(str(exc)) from exc


def load_epss(path: Path) -> dict[str, float]:
    """EPSS probabilities: CSV with ``cve,epss`` columns."""
    path = Path(path)
    if not path.exists():
        raise EnrichmentError(
            f"EPSS file not found at {path}; supply one or omit --feeds explicitly"
        )
    scores: dict[str, float] = {}
    with path.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            scores[str(row["cve"]).upper()] = float(row["epss"])
    return scores


def enrich(findings: list[Finding], kev: set[str], epss: dict[str, float]) -> list[Finding]:
    """Attach exploit intelligence. A finding with no vuln id gets neither."""
    enriched: list[Finding] = []
    for finding in findings:
        vuln = (finding.vuln_id or "").upper()
        enriched.append(
            finding.model_copy(
                update={
                    "kev": vuln in kev if vuln else False,
                    "epss": epss.get(vuln) if vuln else None,
                }
            )
        )
    return enriched


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, float] = {
    "severity": 0.30,
    "exploitability": 0.35,
    "exposure": 0.20,
    "chaining": 0.15,
}

#: A finding CISA lists as actively exploited cannot rank below this, whatever
#: the blend says. Known exploitation is a fact about the world, not a weighted
#: opinion about one.
KEV_FLOOR = 85.0


def _exploitability_value(finding: Finding) -> float:
    """AI judgement blended with EPSS when both are present; either alone
    otherwise; the severity value as a conservative proxy when neither is."""
    ai = finding.ai_exploitability
    epss = None if finding.epss is None else finding.epss * 100.0
    if ai is not None and epss is not None:
        return 0.6 * ai + 0.4 * epss
    if ai is not None:
        return ai
    if epss is not None:
        return epss
    return SEVERITY_VALUE[finding.severity]


def dimension_values(finding: Finding) -> dict[str, float]:
    return {
        "severity": SEVERITY_VALUE[finding.severity],
        "exploitability": clamp_score(_exploitability_value(finding)),
        "exposure": clamp_score(finding.exposure),
        "chaining": clamp_score(finding.chaining),
    }


def score_finding(finding: Finding, adjustments: list[Adjustment] | None = None) -> Finding:
    """The weighted composite, with the KEV floor and a reconciling breakdown."""
    adjustments = adjustments or []
    values = dimension_values(finding)
    total_weight = sum(WEIGHTS.values())
    base = sum(values[dim] * weight for dim, weight in WEIGHTS.items()) / total_weight
    blended = clamp_score(base + sum(a.delta for a in adjustments))

    kev_floor_applied = finding.kev and blended < KEV_FLOOR
    final = KEV_FLOOR if kev_floor_applied else blended

    breakdown = ScoreBreakdown(
        values=values,
        weights=dict(WEIGHTS),
        base_score=base,
        adjustments=list(adjustments),
        kev_floor_applied=kev_floor_applied,
        floor=KEV_FLOOR if kev_floor_applied else None,
        final_score=final,
    )
    if not breakdown.reconciles():
        # An explicit raise rather than the original's `assert`: assertions are
        # stripped under `python -O`, and a score that silently stops reconciling
        # is precisely the failure the breakdown exists to make impossible.
        raise ScoreError(
            f"score {final} does not reconcile with its breakdown for {finding.fingerprint}"
        )
    return finding.model_copy(update={"risk_score": final, "breakdown": breakdown})


def rank(findings: list[Finding]) -> list[Finding]:
    """Highest risk first, with the fingerprint as a stable tie-break.

    The tie-break is not cosmetic: without it two findings on the same score
    swap places between identical runs, and every diff of the queue is noise.
    """
    return sorted(findings, key=lambda f: (-(f.risk_score or 0.0), f.fingerprint))
