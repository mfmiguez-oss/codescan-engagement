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
    (
        # Identity: a fingerprint that stops canonicalising splits one weakness
        # into several findings and orphans every decision keyed on the old id.
        "backbone.py",
        "    label = _LABEL_SEPARATORS.sub(\"_\", raw.upper()).strip(\"_\")\n"
        "    return _WEAKNESS_SYNONYMS.get(label, label)",
        "    return raw",
        "tests/test_backbone_conformance.py"
        "::test_spelling_variants_of_one_weakness_hash_identically",
    ),
    (
        "backbone.py",
        '    normalised = path.strip().replace("\\\\", "/").lower()',
        "    normalised = path",
        "tests/test_backbone_conformance.py"
        "::test_path_separator_and_case_do_not_split_a_finding",
    ),
    (
        # The floor is what makes known exploitation outrank a weighted opinion.
        "backbone.py",
        "    kev_floor_applied = finding.kev and blended < KEV_FLOOR",
        "    kev_floor_applied = False",
        "tests/test_backbone_conformance.py::test_a_kev_finding_cannot_rank_below_the_floor",
    ),
    (
        "backbone.py",
        "    return sorted(findings, key=lambda f: (-(f.risk_score or 0.0), f.fingerprint))",
        "    return sorted(findings, key=lambda f: -(f.risk_score or 0.0))",
        "tests/test_backbone_conformance.py::test_ranking_is_stable_for_equal_scores",
    ),
    (
        # Two same-vendor passes miss the same things, so their agreement is not
        # evidence — a corroboration count built on it would mislead.
        "models.py",
        "    if not allow_single:\n        raise SingleVendorError(message)",
        "    if False:\n        raise SingleVendorError(message)",
        "tests/test_two_pass.py::test_two_passes_on_one_vendor_are_refused",
    ),
    (
        "contracts.py",
        "        return self.lifecycle_adjust + self.exposure_adjust + self.chaining_adjust",
        "        return self.lifecycle_adjust",
        "tests/test_signals.py::test_both_adjustments_together_stay_reversible",
    ),
    (
        "signals.py",
        "        if score >= mapping.by_path.get(item_path, -1.0):",
        "        if item_path not in mapping.by_path:",
        "tests/test_signals.py::test_the_most_exposed_boundary_in_a_file_decides",
    ),
    (
        "signals.py",
        "        delta = min(MAX_CHAIN_ADJUST, count * CHAIN_POINTS)",
        "        delta = count * CHAIN_POINTS",
        "tests/test_signals.py::test_the_chaining_adjustment_is_capped",
    ),
    (
        # A vault that silently falls back to the environment means rotating
        # the secret changes nothing, and nothing about it looks wrong.
        "secrets.py",
        "        value = self._from_vault(ref) if ref.uses_vault "
        'else self._env.get(ref.env_var, "")',
        '        value = self._env.get(ref.env_var, "")',
        "tests/test_secrets.py::test_a_configured_vault_never_falls_back_to_the_environment",
    ),
    (
        "egress.py",
        '    vault = (env.get("ENGAGEMENT_KEY_VAULT") or "").strip()\n    if vault:',
        '    vault = (env.get("ENGAGEMENT_KEY_VAULT") or "").strip()\n    if False:',
        "tests/test_secrets.py::test_the_vault_host_is_on_the_egress_allowlist",
    ),
    (
        # The network boundary. An allowlist that fails open is not one.
        "egress.py",
        "        if self.enforce:\n            raise EgressBlocked(message)",
        "        if False:\n            raise EgressBlocked(message)",
        "tests/test_egress.py::test_an_unconfigured_host_is_refused",
    ),
    (
        "egress.py",
        "        if host and host in self.allowed:\n            return",
        "        if host:\n            return",
        "tests/test_egress.py::test_nothing_observed_can_widen_the_allowlist",
    ),
    (
        # Sampling is the only evidence an unattended queue's decisions are any
        # good; without it there is merely no evidence they are bad.
        "governance.py",
        "    return value < rate",
        "    return False",
        "tests/test_governance.py::test_selection_is_uniform_at_the_configured_rate",
    ),
    (
        "governance.py",
        "        is_shadow = bool(model and model in shadow)",
        "        is_shadow = False",
        "tests/test_governance.py::test_a_shadowed_models_decisions_do_not_count",
    ),
    (
        # A second pass skipped for budget must not leave a queue that reads as
        # corroborated. Silence here is the failure mode, not the exception.
        "driver.py",
        "        if not self._ledger.can_afford():\n"
        "            report.warnings.append(\n"
        '                "detection: the budget was exhausted by the first pass, so the "',
        "        if False:\n"
        "            report.warnings.append(\n"
        '                "detection: the budget was exhausted by the first pass, so the "',
        "tests/test_two_pass.py"
        "::test_a_budget_exhausted_by_the_first_pass_reports_no_corroboration",
    ),
    (
        "driver.py",
        '        second_policy = self._policy.model_copy(\n'
        '            update={"expert_model": second_model, "second_expert_model": ""}\n'
        "        )",
        '        second_policy = self._policy.model_copy(\n'
        '            update={"second_expert_model": ""}\n'
        "        )",
        "tests/test_two_pass.py::test_the_second_pass_uses_the_second_vendors_model",
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
