"""Break the code, confirm a named test notices, restore it.

A test that has never failed is a claim, not a check. This script makes each
invariant test earn its name: it applies a targeted mutation that violates the
property, runs the one test that exists to catch it, and asserts the test fails.
A mutation that survives means the property is unguarded whatever the suite says.

Run it after the gate:

    python scripts/mutation_check.py

Each entry is (module, original, mutant, test). The original must match exactly
once — a stale anchor is reported as a setup failure rather than passing quietly,
because a mutation that never applied is a check that never ran.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "engagement"

Mutation = tuple[str, str, str, str]

MUTATIONS: list[Mutation] = [
    (
        "analysis.py",
        "        if candidate in permitted and candidate not in seen:",
        "        if candidate not in seen:",
        "tests/test_analysis.py::test_a_chain_may_only_reference_findings_from_its_own_request",
    ),
    (
        "analysis.py",
        "            if len(ids) < self._min:",
        "            if False:",
        "tests/test_analysis.py::test_a_chain_narrowed_below_two_findings_is_dropped_as_fabricated",
    ),
    (
        "analysis.py",
        "            if finding_id not in allowed or finding_id in seen:",
        "            if finding_id in seen:",
        "tests/test_analysis.py::test_a_poc_is_drafted_only_against_a_finding_in_its_request",
    ),
    (
        "analysis.py",
        '_TAGS = re.compile(r"[<>]")',
        '_TAGS = re.compile(r"(?!x)x")',
        "tests/test_analysis.py::test_model_prose_cannot_carry_markup_into_the_pack",
    ),
    (
        "lifecycle.py",
        "            report.unknown_components.append(f\"{ecosystem or '?'}:{name}\")\n"
        "            report.assessments.append(\n"
        "                Assessment(\n"
        "                    component=name,\n"
        "                    ecosystem=ecosystem,\n"
        "                    version=version,\n"
        "                    state=LifecycleState.unknown,\n"
        "                )\n"
        "            )\n"
        "            continue",
        "            report.assessments.append(\n"
        "                Assessment(\n"
        "                    component=name,\n"
        "                    ecosystem=ecosystem,\n"
        "                    version=version,\n"
        "                    state=LifecycleState.supported,\n"
        "                )\n"
        "            )\n"
        "            continue",
        "tests/test_lifecycle.py::test_a_component_the_feed_does_not_cover_is_unknown_not_supported",
    ),
    (
        "lifecycle.py",
        "        if self.eol is not None and as_of >= self.eol:\n"
        "            return LifecycleState.eol\n"
        "        if self.eos is not None and as_of >= self.eos:\n"
        "            return LifecycleState.eos",
        "        if self.eos is not None and as_of >= self.eos:\n"
        "            return LifecycleState.eol\n"
        "        if self.eol is not None and as_of >= self.eol:\n"
        "            return LifecycleState.eos",
        "tests/test_lifecycle.py"
        "::test_a_version_past_support_but_not_eol_is_end_of_support_not_end_of_life",
    ),
    (
        "lifecycle.py",
        "            finding.lifecycle_adjust = delta\n"
        "            finding.risk_score = min(100.0, finding.risk_score + delta)",
        "            finding.risk_score = min(100.0, finding.risk_score + delta)",
        "tests/test_lifecycle.py::test_the_adjustment_can_always_be_undone",
    ),
    (
        "siem.py",
        "    kept = {key: value for key, value in event.detail.items() if key in permitted}",
        "    kept = dict(event.detail)",
        "tests/test_siem.py::test_a_detail_key_outside_the_allowlist_is_dropped_and_reported",
    ),
    (
        "siem.py",
        '    if event.kind == "run_finished" and event.detail.get("complete") is False:\n'
        "        return 73",
        "    if False:\n        return 73",
        "tests/test_siem.py"
        "::test_an_incomplete_run_is_exported_at_a_higher_severity_than_a_clean_one",
    ),
    (
        # Pointed at the *alias* test, not the catalogue one: the catalogue is a
        # second line of defence, so breaking the prefix check still leaves
        # catalogued ids correct. Only an alias outside the catalogue — the
        # common real case, since operators name their own deployments —
        # actually depends on this branch.
        "models.py",
        "    if any(lowered.startswith(prefix) for prefix in _SAMPLING_REMOVED):\n"
        "        return False",
        "    if False:\n        return False",
        "tests/test_models.py::test_a_prefix_match_catches_an_alias_not_in_the_catalogue",
    ),
    (
        "models.py",
        '_ID_PREFIXES: tuple[str, ...] = ("us.", "eu.", "apac.", "anthropic.")',
        '_ID_PREFIXES: tuple[str, ...] = ()',
        "tests/test_models.py::test_a_platform_prefix_does_not_defeat_the_family_match",
    ),
    (
        "export.py",
        "        if finding.risk_score > existing.finding.risk_score:",
        "        if False:",
        "tests/test_export.py::test_a_merge_keeps_the_worse_reading",
    ),
    (
        "export.py",
        '            row.severity_delta = "unknown"',
        '            row.severity_delta = "new"',
        "tests/test_export.py::test_a_first_run_reports_unknown_movement_not_new",
    ),
    (
        "export.py",
        '    return f"\'{value}" if value.startswith(_FORMULA_PREFIXES) else value',
        "    return value",
        "tests/test_export.py::test_a_hostile_title_cannot_execute_in_a_spreadsheet",
    ),
    (
        "feeds.py",
        "        return max(0, ((as_of or datetime.now(UTC).date()) - released).days)",
        "        return 0",
        "tests/test_feeds.py::test_a_stale_catalogue_is_detectable",
    ),
]


def _run(test: str) -> bool:
    """True when the test failed — which is what a caught mutation looks like."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test, "-q", "--no-header", "-x"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode != 0


def main() -> int:
    failures: list[str] = []
    for module, original, mutant, test in MUTATIONS:
        path = SRC / module
        source = path.read_text(encoding="utf-8")
        name = test.rsplit("::", 1)[-1]
        if source.count(original) != 1:
            failures.append(f"SETUP  {module}: anchor for {name} matched {source.count(original)}x")
            continue
        path.write_text(source.replace(original, mutant, 1), encoding="utf-8")
        try:
            caught = _run(test)
        finally:
            path.write_text(source, encoding="utf-8")
        print(f"{'caught  ' if caught else 'SURVIVED'} {name}")
        if not caught:
            failures.append(f"SURVIVED {module}: {test}")

    if failures:
        print("\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print(f"\nall {len(MUTATIONS)} mutations were caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
