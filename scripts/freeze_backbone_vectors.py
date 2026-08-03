"""Freeze the identity and scoring vectors the ported backbone must reproduce.

`src/engagement/backbone.py` is a port of `triagekit`, and the thing that must
survive a port is *identity*: every analyst decision, validation state and
baseline comparison is keyed on a finding's fingerprint, so a port that hashed
differently would orphan all of them silently — every finding would read as new
and every prior decision would stop matching the finding it was made about.

`tests/test_backbone_conformance.py` checked that against the original by
importing it. The original is a private repo that is not a dependency, so it was
never installed — not in CI, not in the development venv — and the six
conformance tests skipped every single run since they were written. A drift
check that has never executed is not a check; it is a comment that costs a test
id. Same failure as vendoring without a manifest.

So the comparison is frozen instead. This script runs *once per deliberate
backbone change*, against a `triagekit` checkout, and writes the answers to
`tests/data/backbone_vectors.json`. The conformance tests then read that file
and run offline, always, everywhere — the same move the vendor manifest makes
for the workspace, and for the same reason.

Usage:

    python scripts/freeze_backbone_vectors.py --from ../codescan-triage

Omit ``--from`` when `triagekit` is importable already. Committing the result is
the deliberate act: a diff in this file is a change to what a finding *is*, and
should be read as carefully as a migration.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "data" / "backbone_vectors.json"

#: Inputs chosen to exercise every branch of the identity path: a plain CWE id,
#: a bare number, a zero-padded one, a label in each separator style, a label
#: with no mapping at all, and both path separators with and without a leading
#: ``./`` or ``/``. A vector set that only covers the easy spellings freezes the
#: half of the function that was never going to drift.
IDENTITY_CASES: list[tuple[str, dict[str, str]]] = [
    ("acme/app", {"weakness_id": "CWE-79", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "79", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "cwe-079", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "XSS", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "cross site scripting", "path": "src/a.py"}),
    ("acme/app", {"weakness_id": "PATH-TRAVERSAL", "path": "./src/b.py"}),
    ("acme/app", {"weakness_id": "path_traversal", "path": "src\\b.py"}),
    ("ACME/App", {"weakness_id": "some_novel_label", "path": "/src/c.py"}),
]

#: Dependency identity. The manifest path is deliberately absent from the key,
#: so these vectors also pin the *shape* of the component normalisation.
DEPENDENCY_CASES: list[dict[str, Any]] = [
    {
        "repo": "acme/app",
        "vuln_id": "CVE-2020-8203",
        "component": {"name": "lodash", "ecosystem": "npm"},
    },
    {
        "repo": "acme/app",
        "vuln_id": "cve-2020-8203",
        "component": {"name": "lodash", "ecosystem": "npm"},
    },
    {
        "repo": "acme/app",
        "vuln_id": "CVE-2021-44228",
        "component": {"name": "log4j-core", "ecosystem": "maven", "version": "2.14.1"},
    },
]

#: Labels whose canonical form is the merge decision itself. A divergent synonym
#: merges findings the original keeps distinct, or splits ones it merges — both
#: are silent.
WEAKNESS_LABELS = [
    "XSS", "SQLI", "COMMAND_INJECTION", "PATH_TRAVERSAL", "LFI", "CSRF",
    "INSECURE_DESERIALIZATION", "OPEN_REDIRECT", "WEAK_SESSION_ID",
    "broken access control", "insecure cookie", "some novel label",
    "CWE-1234", "42", "cwe-079", "Cross Site Scripting",
]

PATHS = ["src/a.py", "./src/a.py", "src\\A.py", "/src/a.py", "././x.py", "a/../b.py"]

#: Score cases, one per branch of the blend: each severity alone, each dimension
#: alone, the KEV floor biting, and the floor declining to lower a score already
#: above it.
SCORE_CASES: list[dict[str, Any]] = [
    {"severity": "info"},
    {"severity": "low"},
    {"severity": "medium"},
    {"severity": "high"},
    {"severity": "critical"},
    {"severity": "medium", "epss": 0.75},
    {"severity": "high", "ai_exploitability": 90.0},
    {"severity": "high", "ai_exploitability": 90.0, "epss": 0.2},
    {"severity": "low", "kev": True},
    {"severity": "critical", "kev": True, "ai_exploitability": 99.0},
    {"severity": "medium", "exposure": 60.0, "chaining": 40.0},
    {"severity": "critical", "exposure": 100.0, "chaining": 100.0, "ai_exploitability": 100.0},
]


def _source_commit(checkout: Path | None) -> dict[str, Any]:
    """Where the vectors came from, and whether that answer is reproducible."""
    if checkout is None:
        return {"source_repo": None, "source_commit": None, "source_dirty": []}
    try:
        commit = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(checkout), "status", "--porcelain"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return {"source_repo": checkout.name, "source_commit": None, "source_dirty": []}
    dirty = sorted(line[3:].strip() for line in status.splitlines() if line.strip())
    return {"source_repo": checkout.name, "source_commit": commit, "source_dirty": dirty}


def freeze(checkout: Path | None) -> dict[str, Any]:
    if checkout is not None:
        sys.path.insert(0, str(checkout / "src"))
    import triagekit.contracts as contracts
    import triagekit.scoring as scoring

    fingerprints = [
        {"repo": repo, "kwargs": kwargs, "digest": contracts.compute_fingerprint(repo, **kwargs)}
        for repo, kwargs in IDENTITY_CASES
    ]
    dependencies = []
    for case in DEPENDENCY_CASES:
        component = contracts.Component(**case["component"])
        dependencies.append(
            {
                **case,
                "digest": contracts.compute_fingerprint(
                    case["repo"], vuln_id=case["vuln_id"], component=component
                ),
            }
        )
    scores = []
    for case in SCORE_CASES:
        scored = scoring.score_finding(
            contracts.Finding(fingerprint="fp", repo="acme/app", title="a finding", **case)
        )
        scores.append({"case": case, "risk_score": scored.risk_score})

    return {
        **_source_commit(checkout),
        "frozen_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "weights": dict(scoring.WEIGHTS),
        "kev_floor": scoring.KEV_FLOOR,
        "fingerprints": fingerprints,
        "dependency_fingerprints": dependencies,
        "weakness_table": {
            label: contracts.canonical_weakness(label) for label in WEAKNESS_LABELS
        },
        "path_normalisation": {path: contracts.normalize_path(path) for path in PATHS},
        "scores": scores,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from", dest="source", type=Path,
        help="A codescan-triage checkout to import `triagekit` from.",
    )
    args = parser.parse_args()
    checkout = args.source.resolve() if args.source else None
    if checkout is not None and not (checkout / "src" / "triagekit").is_dir():
        print(f"no triagekit package under {checkout / 'src'}", file=sys.stderr)
        return 2
    try:
        vectors = freeze(checkout)
    except ImportError as exc:
        print(f"could not import triagekit: {exc}", file=sys.stderr)
        print("pass --from <codescan-triage checkout>", file=sys.stderr)
        return 2

    VECTORS.parent.mkdir(parents=True, exist_ok=True)
    VECTORS.write_text(json.dumps(vectors, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    commit = vectors["source_commit"]
    print(f"froze {len(vectors['fingerprints']) + len(vectors['dependency_fingerprints'])} "
          f"identity and {len(vectors['scores'])} score vector(s)")
    print(f"  -> {VECTORS.relative_to(ROOT)} from {commit[:12] if commit else 'an install'}")
    if vectors["source_dirty"]:
        print(
            f"warning: the source tree had {len(vectors['source_dirty'])} uncommitted "
            f"change(s), so these vectors are NOT reproducible from "
            f"{commit[:12] if commit else 'it'}.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
