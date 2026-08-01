"""The ported backbone, held to the original it was ported from.

Two layers, deliberately:

**Always-on properties** — fingerprint stability, score reconciliation, the KEV
floor, deterministic ranking. These are the invariants the estate depends on and
they hold whether or not `triagekit` is installed.

**Conformance** — the same inputs must produce the same fingerprints and the
same scores as `triagekit` itself. Skipped when the original is not installed,
exactly as `test_vendor.py` skips its upstream-drift check when no OpenHack
checkout sits beside the repo. A fingerprint is a finding's *identity*: every
analyst decision, validation state and baseline comparison is keyed on it, so a
port that hashed differently would orphan all of them silently — every finding
would read as new and every prior decision would stop matching.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engagement.backbone import (
    KEV_FLOOR,
    WEIGHTS,
    Adjustment,
    Component,
    Finding,
    ScoreError,
    Severity,
    canonical_weakness,
    compute_fingerprint,
    dedup,
    enrich,
    load_kev,
    normalize_path,
    parse_sarif,
    rank,
    score_finding,
)

try:  # pragma: no cover - depends on the environment
    import triagekit.contracts as _tk_contracts
    import triagekit.scoring as _tk_scoring

    HAVE_ORIGINAL = True
except ImportError:  # pragma: no cover
    HAVE_ORIGINAL = False

needs_original = pytest.mark.skipif(
    not HAVE_ORIGINAL, reason="triagekit is not installed; conformance not checkable here"
)

#: Inputs chosen to exercise every branch of the identity path: a plain CWE id,
#: a numeric one, a label with each separator style, an unknown label, and a
#: dependency finding.
_IDENTITY_CASES = [
    ("acme/app", {"weakness_id": "CWE-79", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "79", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "cwe-079", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "XSS", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "cross site scripting", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "PATH-TRAVERSAL", "path": "./src/b.py"}),
    ("acme/app", {"weakness_id": "path_traversal", "path": "src\\b.py"}),
    ("ACME/App", {"weakness_id": "some_novel_label", "path": "/src/c.py"}),
]


def _finding(**kwargs: object) -> Finding:
    base: dict[str, object] = {
        "fingerprint": "fp",
        "repo": "acme/app",
        "title": "a finding",
        "severity": Severity.medium,
    }
    base.update(kwargs)
    return Finding(**base)  # type: ignore[arg-type]


# -- identity ----------------------------------------------------------------


def test_spelling_variants_of_one_weakness_hash_identically() -> None:
    """Otherwise one weakness splits into several findings in the queue."""
    plain = compute_fingerprint("acme/app", weakness_id="CWE-79", path="src/a.py")
    for label in ("79", "cwe-079", "XSS", "cross_site_scripting", "Cross Site Scripting"):
        assert compute_fingerprint("acme/app", weakness_id=label, path="src/a.py") == plain


def test_path_separator_and_case_do_not_split_a_finding() -> None:
    windows = compute_fingerprint("acme/app", weakness_id="CWE-89", path="src\\Db.py")
    posix = compute_fingerprint("acme/app", weakness_id="CWE-89", path="./src/db.py")

    assert windows == posix


def test_the_same_weakness_in_two_files_stays_two_findings() -> None:
    """Collapsing them would be silent suppression."""
    first = compute_fingerprint("acme/app", weakness_id="CWE-89", path="src/a.py")
    second = compute_fingerprint("acme/app", weakness_id="CWE-89", path="src/b.py")

    assert first != second


def test_an_unmappable_label_keeps_its_own_identity() -> None:
    """An over-eager synonym table hides genuinely distinct findings."""
    assert canonical_weakness("broken access control") == "BROKEN_ACCESS_CONTROL"
    assert canonical_weakness("insecure cookie") == "INSECURE_COOKIE"


def test_a_dependency_finding_needs_a_vulnerability_id() -> None:
    from engagement.backbone import FingerprintError

    with pytest.raises(FingerprintError):
        compute_fingerprint("acme/app", component=Component(name="lodash"))


def test_a_dependency_fingerprint_ignores_the_manifest_path() -> None:
    """Scanners disagree about which manifest to blame."""
    component = Component(name="lodash", ecosystem="npm")
    assert compute_fingerprint(
        "acme/app", vuln_id="CVE-2020-8203", component=component
    ) == compute_fingerprint("acme/app", vuln_id="cve-2020-8203", component=component)


# -- scoring -----------------------------------------------------------------


def test_the_score_always_reconciles_with_its_breakdown() -> None:
    scored = score_finding(_finding(severity=Severity.high, epss=0.4))

    assert scored.breakdown is not None
    assert scored.breakdown.reconciles()


def test_an_adjustment_moves_the_score_and_is_recorded() -> None:
    scored = score_finding(_finding(), [Adjustment(reason="prior", delta=-7.5)])

    assert scored.breakdown is not None
    assert scored.breakdown.adjustments[0].delta == -7.5
    assert scored.breakdown.reconciles()


def test_a_kev_finding_cannot_rank_below_the_floor() -> None:
    scored = score_finding(_finding(severity=Severity.low, kev=True))

    assert scored.risk_score == KEV_FLOOR
    assert scored.breakdown is not None and scored.breakdown.kev_floor_applied


def test_the_floor_does_not_lower_a_score_already_above_it() -> None:
    scored = score_finding(
        _finding(
            severity=Severity.critical,
            kev=True,
            ai_exploitability=100.0,
            exposure=100.0,
            chaining=100.0,
        )
    )

    assert scored.risk_score is not None and scored.risk_score > KEV_FLOOR
    assert scored.breakdown is not None and not scored.breakdown.kev_floor_applied


def test_an_unpopulated_dimension_drags_the_blend_toward_the_floor() -> None:
    """Worth knowing rather than discovering later: this driver never sets
    ``exposure`` or ``chaining``, so 35% of the weight is structurally zero and
    a KEV finding is floored at 85 almost regardless of the rest. The floor is
    doing the ranking, not the blend."""
    scored = score_finding(_finding(severity=Severity.critical, kev=True, ai_exploitability=99.0))

    assert scored.breakdown is not None
    assert scored.breakdown.base_score < KEV_FLOOR
    assert scored.breakdown.kev_floor_applied


def test_a_broken_breakdown_raises_rather_than_asserting() -> None:
    """`assert` is stripped under -O; a score that stops reconciling must not be."""
    import engagement.backbone as backbone

    original = backbone.ScoreBreakdown.reconciles
    backbone.ScoreBreakdown.reconciles = lambda self: False  # type: ignore[method-assign]
    try:
        with pytest.raises(ScoreError):
            score_finding(_finding())
    finally:
        backbone.ScoreBreakdown.reconciles = original  # type: ignore[method-assign]


def test_the_weights_sum_to_one() -> None:
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


def test_ranking_is_stable_for_equal_scores() -> None:
    """Without a tie-break, every diff of the queue is noise."""
    findings = [
        score_finding(_finding(fingerprint=fp, severity=Severity.medium))
        for fp in ("ccc", "aaa", "bbb")
    ]
    assert [f.fingerprint for f in rank(findings)] == ["aaa", "bbb", "ccc"]
    assert [f.fingerprint for f in rank(list(reversed(findings)))] == ["aaa", "bbb", "ccc"]


# -- dedup and enrich --------------------------------------------------------


def test_dedup_counts_corroborating_scanners_and_keeps_the_worst_severity() -> None:
    merged = dedup(
        [
            _finding(fingerprint="fp", severity=Severity.low, scanners=["semgrep"]),
            _finding(fingerprint="fp", severity=Severity.critical, scanners=["openhack"]),
        ]
    )

    assert len(merged) == 1
    assert merged[0].severity is Severity.critical
    assert merged[0].corroboration == 2
    assert merged[0].raw_detection_count == 2


def test_enrichment_marks_kev_membership() -> None:
    enriched = enrich([_finding(vuln_id="CVE-2021-44228")], {"CVE-2021-44228"}, {})

    assert enriched[0].kev


def test_a_finding_with_no_vulnerability_id_gets_no_intelligence() -> None:
    enriched = enrich([_finding()], {"CVE-2021-44228"}, {"CVE-2021-44228": 0.9})

    assert not enriched[0].kev and enriched[0].epss is None


def test_the_fetch_kev_cache_is_readable_by_the_scorer(tmp_path: Path) -> None:
    """Closes the loop: `engagement fetch-kev` writes what enrichment reads."""
    from engagement.feeds import parse_kev, write_kev

    cache = write_kev(parse_kev(["CVE-2021-44228"]), tmp_path / "kev.json")

    assert load_kev(cache) == {"CVE-2021-44228"}


def test_every_kev_shape_this_estate_produces_is_readable(tmp_path: Path) -> None:
    for name, payload in (
        ("list.json", ["CVE-2021-44228"]),
        ("cisa.json", {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}),
        ("cache.json", {"vulnerability_ids": ["CVE-2021-44228"]}),
    ):
        path = tmp_path / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert load_kev(path) == {"CVE-2021-44228"}, name


# -- ingest ------------------------------------------------------------------


def test_a_malformed_sarif_result_costs_that_result_and_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "findings.sarif"
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "OpenHack"}},
                        "results": [
                            {
                                "ruleId": "CWE-89",
                                "level": "error",
                                "message": {"text": "SQLi"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/db.py"},
                                            "region": {"startLine": 42},
                                        }
                                    }
                                ],
                            },
                            {"ruleId": "CWE-79"},  # no locations
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    report = parse_sarif(path, "acme/app")

    assert len(report.findings) == 1
    assert report.findings[0].location is not None
    assert report.findings[0].location.line == 42
    assert report.findings[0].scanners == ["openhack"]
    assert len(report.errors) == 1, "the dropped result must be reported, not silent"


def test_a_sarif_without_runs_is_reported_not_crashed(tmp_path: Path) -> None:
    path = tmp_path / "empty.sarif"
    path.write_text("{}", encoding="utf-8")
    report = parse_sarif(path, "acme/app")

    assert report.findings == []
    assert report.errors and report.errors[0].message == "no 'runs'"


# -- conformance with the original -------------------------------------------


@needs_original
def test_fingerprints_are_identical_to_the_original() -> None:
    """Identity must survive the port, or every decision is orphaned."""
    for repo, kwargs in _IDENTITY_CASES:
        ours = compute_fingerprint(repo, **kwargs)  # type: ignore[arg-type]
        theirs = _tk_contracts.compute_fingerprint(repo, **kwargs)
        assert ours == theirs, f"{repo} {kwargs}"


@needs_original
def test_dependency_fingerprints_are_identical_to_the_original() -> None:
    ours = compute_fingerprint(
        "acme/app", vuln_id="CVE-2020-8203", component=Component(name="lodash", ecosystem="npm")
    )
    theirs = _tk_contracts.compute_fingerprint(
        "acme/app",
        vuln_id="CVE-2020-8203",
        component=_tk_contracts.Component(name="lodash", ecosystem="npm"),
    )

    assert ours == theirs


@needs_original
def test_the_weakness_table_matches_the_original() -> None:
    """A divergent synonym merges findings the original keeps distinct."""
    labels = [
        "XSS", "SQLI", "COMMAND_INJECTION", "PATH_TRAVERSAL", "LFI", "CSRF",
        "INSECURE_DESERIALIZATION", "OPEN_REDIRECT", "WEAK_SESSION_ID",
        "broken access control", "some novel label", "CWE-1234", "42",
    ]
    for label in labels:
        assert canonical_weakness(label) == _tk_contracts.canonical_weakness(label), label


@needs_original
def test_scores_are_identical_to_the_original() -> None:
    cases = [
        {"severity": "low"},
        {"severity": "critical"},
        {"severity": "medium", "epss": 0.75},
        {"severity": "high", "ai_exploitability": 90.0},
        {"severity": "high", "ai_exploitability": 90.0, "epss": 0.2},
        {"severity": "low", "kev": True},
        {"severity": "critical", "kev": True, "ai_exploitability": 99.0},
        {"severity": "medium", "exposure": 60.0, "chaining": 40.0},
    ]
    for case in cases:
        ours = score_finding(_finding(**case))
        theirs = _tk_scoring.score_finding(
            _tk_contracts.Finding(
                fingerprint="fp", repo="acme/app", title="a finding", **case
            )
        )
        assert ours.risk_score == theirs.risk_score, case


@needs_original
def test_the_weights_and_floor_match_the_original() -> None:
    assert WEIGHTS == _tk_scoring.WEIGHTS
    assert KEV_FLOOR == _tk_scoring.KEV_FLOOR


@needs_original
def test_path_normalisation_matches_the_original() -> None:
    for path in ("src/a.py", "./src/a.py", "src\\A.py", "/src/a.py", "././x.py"):
        assert normalize_path(path) == _tk_contracts.normalize_path(path), path
