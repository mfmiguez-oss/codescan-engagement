"""The two score dimensions that were structurally zero.

The scorer weights four dimensions — severity 30%, exploitability 35%, exposure
20%, chaining 15% — but nothing populated the last two, so 35% of the weight was
always zero. That is not a cosmetic gap. It pulled every blended score down,
which meant the KEV floor decided the ranking of every exploited finding rather
than the blend, and it made two genuinely different findings score identically:
one reachable from an unauthenticated endpoint and one buried behind three
internal hops.

Both are filled from evidence this pipeline already produces, not from a model:

**Exposure** comes from OpenHack's recon, which walks the source for *request
boundaries* — route registrations, webhook handlers, SAML/OIDC callbacks, upload
endpoints — and records each with a path and a boundary type. A finding in a
file that is a request boundary is externally reachable; one that is not is not.
That is a fact recon already established, and it was being thrown away.

**Chaining** comes from the chain discovery stage, which was already producing
exactly the signal the dimension was named for and had nowhere to put it. A
finding that is a link in a plausible attack chain is worth more than the same
finding standing alone.

Both are applied as **recorded, reversible adjustments** in the same shape as
the lifecycle bump: the delta sits beside the score rather than being folded
into it, so the backbone's own number is always recoverable by subtraction. An
adjustment you cannot undo is an assertion, not an explanation.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from .contracts import Chain, ScoredFinding, StrictModel

# ---------------------------------------------------------------------------
# Exposure, from recon's request boundaries
# ---------------------------------------------------------------------------

#: Exposure points by boundary type, 0-100. Ordered by how much an attacker has
#: to have already achieved before the boundary is reachable: an unauthenticated
#: callback that a third party can invoke ranks above a logout handler that
#: needs a session first.
BOUNDARY_EXPOSURE: dict[str, float] = {
    "saml_acs": 100.0,  # unauthenticated, parses attacker-supplied XML
    "oidc_callback": 95.0,
    "oauth_callback": 95.0,
    "webhook": 90.0,  # invoked by a third party by design
    "upload": 85.0,
    "auth_start": 80.0,
    "saml_auth": 80.0,
    "oauth_token": 75.0,
    "callback": 70.0,
    "auth_check": 65.0,
    "request_boundary": 60.0,
    "logout": 40.0,  # needs a session to reach
}

#: A finding in a file that holds no boundary. Not zero: reachability is a
#: spectrum and recon only sees boundaries it recognised, so "no boundary found
#: in this file" is weaker evidence than "this file is unreachable".
NO_BOUNDARY_EXPOSURE = 15.0

#: Points a chain membership adds, and the ceiling. Small on purpose: chaining
#: changes how *bad* a finding is in combination, not whether it is real, and a
#: modifier that can outrank the evidence is a modifier that hides it.
CHAIN_POINTS = 6.0
MAX_CHAIN_ADJUST = 18.0


class ExposureMap(StrictModel):
    """Request boundaries recon found, keyed by the path that holds them."""

    by_path: dict[str, float] = Field(default_factory=dict)
    types_by_path: dict[str, str] = Field(default_factory=dict)
    boundaries: int = 0
    source: str = ""
    warnings: list[str] = Field(default_factory=list)

    @property
    def loaded(self) -> bool:
        return self.boundaries > 0

    def score_for(self, path: str) -> tuple[float, str]:
        """Exposure for a finding's path, and the boundary type that decided it."""
        key = _normalise(path)
        if not key:
            return NO_BOUNDARY_EXPOSURE, ""
        if key in self.by_path:
            return self.by_path[key], self.types_by_path.get(key, "")
        return NO_BOUNDARY_EXPOSURE, ""


def _normalise(path: str) -> str:
    return path.strip().replace("\\", "/").lstrip("./").lower()


def load_boundaries(recon_items: Path) -> ExposureMap:
    """Read recon's item stream and keep the request boundaries.

    A missing recon file is not an error: exposure is an enrichment, and a queue
    without it is still a correct queue. It is *reported*, because a run scored
    with every finding at the no-boundary baseline ranks differently from one
    where reachability was actually assessed.
    """
    mapping = ExposureMap(source=str(recon_items))
    path = Path(recon_items)
    if not path.exists():
        mapping.warnings.append(
            f"exposure: no recon items at {path} — every finding scores at the "
            "no-boundary baseline, so reachability did not contribute to ranking"
        )
        return mapping

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            mapping.warnings.append(f"exposure: {path.name}:{number} is not JSON; skipped")
            continue
        if not isinstance(item, dict) or item.get("type") != "request-boundary":
            continue
        item_path = _normalise(str(item.get("path", "")))
        if not item_path:
            continue
        boundary_type = str(item.get("boundary_type") or "request_boundary")
        score = BOUNDARY_EXPOSURE.get(boundary_type, BOUNDARY_EXPOSURE["request_boundary"])
        mapping.boundaries += 1
        # Several boundaries can share a file; the most exposed one decides,
        # because reachability is a floor, not an average.
        if score >= mapping.by_path.get(item_path, -1.0):
            mapping.by_path[item_path] = score
            mapping.types_by_path[item_path] = boundary_type
    return mapping


class SignalReport(StrictModel):
    """What the two dimensions contributed, and to how many findings."""

    exposure_applied: int = 0
    chaining_applied: int = 0
    boundaries: int = 0
    exposed_findings: int = 0
    warnings: list[str] = Field(default_factory=list)


def apply_exposure(findings: list[ScoredFinding], mapping: ExposureMap) -> SignalReport:
    """Record each finding's reachability and adjust its score by it.

    The adjustment is relative to the no-boundary baseline, so a finding on an
    unreachable path is not *penalised* — it simply gains nothing, while one on
    an unauthenticated callback gains the difference. Scoring the baseline as a
    penalty would push everything down and change nothing about the order.
    """
    report = SignalReport(boundaries=mapping.boundaries, warnings=list(mapping.warnings))
    if not mapping.loaded:
        return report

    weight = 0.20  # the scorer's own weight for this dimension
    for finding in findings:
        score, boundary_type = mapping.score_for(finding.path)
        finding.exposure = score
        finding.exposure_boundary = boundary_type
        delta = round((score - NO_BOUNDARY_EXPOSURE) * weight, 1)
        if delta:
            finding.exposure_adjust = delta
            finding.risk_score = min(100.0, finding.risk_score + delta)
            report.exposure_applied += 1
            report.exposed_findings += 1
    return report


def apply_chaining(
    findings: list[ScoredFinding], chains: list[Chain], report: SignalReport | None = None
) -> SignalReport:
    """Feed chain membership back into the score it was always meant to inform.

    Counted per chain rather than flat: a finding that appears in three distinct
    chains is a hub, and a hub is where a responder should start. Capped, so a
    model that returns many overlapping chains cannot inflate one finding past
    the evidence for it.
    """
    report = report or SignalReport()
    if not chains:
        return report

    membership: dict[str, int] = {}
    for chain in chains:
        for finding_id in set(chain.finding_ids):
            membership[finding_id] = membership.get(finding_id, 0) + 1

    for finding in findings:
        count = membership.get(finding.id, 0)
        if not count:
            continue
        finding.chain_count = count
        finding.chaining = min(100.0, count * 100.0 / 3.0)
        delta = min(MAX_CHAIN_ADJUST, count * CHAIN_POINTS)
        finding.chaining_adjust = delta
        finding.risk_score = min(100.0, finding.risk_score + delta)
        report.chaining_applied += 1
    return report
