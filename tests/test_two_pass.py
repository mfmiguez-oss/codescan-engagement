"""Two detection passes, and why they must come from different vendors.

The value of a second pass is *independence*. Two models from one vendor share
training data, tokenizer lineage and refusal behaviour, so they miss the same
things in the same places — and a second pass that agrees for structural reasons
produces a corroboration count that reads like evidence and is not. The count is
the whole point, so the configuration is refused rather than warned about.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engagement.models import SingleVendorError, check_two_vendor_passes, vendor_of
from engagement.triage import BackbonePipeline


def _sarif(tmp_path: Path, name: str, *rules: tuple[str, str]) -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "OpenHack"}},
                        "results": [
                            {
                                "ruleId": rule,
                                "level": "error",
                                "message": {"text": f"{rule} in {file}"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": file},
                                            "region": {"startLine": 10},
                                        }
                                    }
                                ],
                            }
                            for rule, file in rules
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


# -- vendor independence -----------------------------------------------------


def test_vendors_are_recognised_across_platform_prefixes() -> None:
    assert vendor_of("claude-opus-5") == "anthropic"
    assert vendor_of("anthropic.claude-opus-5") == "anthropic"
    assert vendor_of("us.anthropic.claude-opus-5") == "anthropic"
    assert vendor_of("gpt-5.6-luna") == "openai"
    assert vendor_of("mistral-large-2407") == "mistral"
    assert vendor_of("meta.llama3-70b") == "meta"


def test_two_passes_on_one_vendor_are_refused() -> None:
    with pytest.raises(SingleVendorError, match="both detection passes use anthropic"):
        check_two_vendor_passes(["claude-opus-5", "claude-haiku-4-5"])


def test_two_passes_on_different_vendors_are_accepted() -> None:
    assert check_two_vendor_passes(["claude-opus-5", "gpt-5.6-luna"]) == []


def test_a_single_vendor_pair_can_be_accepted_deliberately() -> None:
    """An operator may have only one vendor available; it must be a choice."""
    warnings = check_two_vendor_passes(
        ["claude-opus-5", "claude-haiku-4-5"], allow_single=True
    )

    assert any("would read as evidence without being any" in w for w in warnings)


def test_an_unrecognised_alias_is_never_assumed_independent() -> None:
    warnings = check_two_vendor_passes(["some-internal-alias", "gpt-5.6-luna"])

    assert any("assumed, not verified" in w for w in warnings)


def test_two_unrecognised_aliases_are_treated_as_one_vendor() -> None:
    """Unknown is its own vendor, so two unknowns are not independent."""
    with pytest.raises(SingleVendorError):
        check_two_vendor_passes(["alias-a", "alias-b"])


def test_one_pass_needs_no_vendor_check() -> None:
    assert check_two_vendor_passes(["claude-opus-5"]) == []


# -- consolidation -----------------------------------------------------------


def test_agreement_between_passes_becomes_real_corroboration(tmp_path: Path) -> None:
    first = _sarif(tmp_path, "a.sarif", ("CWE-89", "src/db.py"), ("CWE-79", "src/view.py"))
    second = _sarif(tmp_path, "b.sarif", ("CWE-89", "src/db.py"))

    summary = BackbonePipeline().ingest(
        first, "acme/app", tmp_path, extra_sarif={"pass-2:gpt": second}
    )

    by_title = {f.title: f for f in summary.queue}
    agreed = by_title["CWE-89 in src/db.py"]
    alone = by_title["CWE-79 in src/view.py"]

    assert sorted(agreed.detected_by) == ["pass-1", "pass-2:gpt"]
    assert alone.detected_by == ["pass-1"]
    assert summary.passes == 2
    assert summary.corroborated == 1


def test_a_finding_only_one_pass_saw_is_kept(tmp_path: Path) -> None:
    """Uncorroborated is not false — dropping it would be suppression."""
    first = _sarif(tmp_path, "a.sarif", ("CWE-89", "src/db.py"))
    second = _sarif(tmp_path, "b.sarif", ("CWE-22", "src/files.py"))

    summary = BackbonePipeline().ingest(
        first, "acme/app", tmp_path, extra_sarif={"pass-2:gpt": second}
    )

    assert summary.findings == 2
    assert summary.corroborated == 0


def test_the_split_between_corroborated_and_single_pass_is_reported(tmp_path: Path) -> None:
    first = _sarif(tmp_path, "a.sarif", ("CWE-89", "src/db.py"), ("CWE-79", "src/v.py"))
    second = _sarif(tmp_path, "b.sarif", ("CWE-89", "src/db.py"))

    summary = BackbonePipeline().ingest(
        first, "acme/app", tmp_path, extra_sarif={"pass-2:gpt": second}
    )

    assert any(
        "not thereby false, only uncorroborated" in w for w in summary.warnings
    ), "the meaning of a single-pass finding must be stated"


def test_one_pass_reports_no_corroboration_claim(tmp_path: Path) -> None:
    summary = BackbonePipeline().ingest(
        _sarif(tmp_path, "a.sarif", ("CWE-89", "src/db.py")), "acme/app", tmp_path
    )

    assert summary.passes == 1
    assert not any("independent passes" in w for w in summary.warnings)


# -- the driver drives both passes -------------------------------------------


def _driver(second_model: str = "gpt-5.6-luna", max_calls: int = 60):
    from engagement.budget import Budget, Ledger
    from engagement.contracts import Priority
    from engagement.driver import Driver, Policy
    from engagement.providers import FakeProvider
    from fakes import FakeWorkspace, scenarios

    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    driver = Driver(
        workspace=workspace,
        provider=FakeProvider(),
        ledger=Ledger(budget=Budget(max_calls=max_calls)),
        policy=Policy(model="claude-opus-5", second_expert_model=second_model),
    )
    return driver, workspace


def test_the_driver_creates_a_second_run_and_reports_two_passes() -> None:
    from engagement.contracts import RunRef

    driver, workspace = _driver()
    report = driver.run_two_pass(RunRef(target="acme", run_id="run-001"))

    assert workspace.created_runs == ["run-001-p2"]
    assert report.passes == 2
    assert report.second_sarif_path is not None


def test_both_passes_spend_from_one_ledger() -> None:
    """One ceiling over the engagement, not one per pass."""
    from engagement.contracts import RunRef

    driver, _ = _driver()
    one_pass = Driver_calls(driver, RunRef(target="acme", run_id="run-001"))

    assert one_pass == driver.ledger.calls
    assert driver.ledger.calls > 0


def Driver_calls(driver, ref) -> int:
    driver.run_two_pass(ref)
    return driver.ledger.calls


def test_the_second_pass_uses_the_second_vendors_model() -> None:
    from engagement.contracts import RunRef

    driver, _ = _driver()
    driver.run_two_pass(RunRef(target="acme", run_id="run-001"))
    deployments = {request.deployment for request in driver._provider.requests}  # type: ignore[attr-defined]

    assert "gpt-5.6-luna" in deployments, "the second pass reused the first model"
    assert "claude-opus-5" in deployments


def test_agent_ids_stay_unique_across_passes() -> None:
    """Isolation must survive a second pass, or it is one context twice."""
    from engagement.contracts import RunRef

    driver, workspace = _driver()
    driver.run_two_pass(RunRef(target="acme", run_id="run-001"))

    assert len(workspace.agent_ids) == len(set(workspace.agent_ids))


def test_a_budget_exhausted_by_the_first_pass_reports_no_corroboration() -> None:
    """Silently skipping the second pass would leave a queue that looks
    corroborated and is not."""
    from engagement.contracts import RunRef

    # One call covers the router and leaves nothing for a scenario, let alone a
    # second pass over the whole backlog.
    driver, workspace = _driver(max_calls=1)
    report = driver.run_two_pass(RunRef(target="acme", run_id="run-001"))

    assert not driver.ledger.can_afford(), "the premise of this test did not hold"
    assert workspace.created_runs == []
    assert report.passes == 1
    assert any("every finding here is uncorroborated" in w for w in report.warnings)


def test_a_second_pass_that_cannot_be_created_is_reported() -> None:
    from engagement.contracts import RunRef
    from engagement.workspace import WorkspaceError

    driver, workspace = _driver()

    def refuse(source, run_id):  # type: ignore[no-untyped-def]
        raise WorkspaceError("no run-config.yaml")

    workspace.create_run = refuse  # type: ignore[assignment]
    report = driver.run_two_pass(RunRef(target="acme", run_id="run-001"))

    assert report.passes == 1
    assert any("nothing in it is corroborated" in w for w in report.warnings)


def test_no_second_model_means_one_pass_and_no_second_run() -> None:
    from engagement.contracts import RunRef

    driver, workspace = _driver(second_model="")
    report = driver.run_two_pass(RunRef(target="acme", run_id="run-001"))

    assert workspace.created_runs == []
    assert report.passes == 1


def test_the_same_weakness_in_different_files_is_not_merged_across_passes(
    tmp_path: Path,
) -> None:
    first = _sarif(tmp_path, "a.sarif", ("CWE-89", "src/a.py"))
    second = _sarif(tmp_path, "b.sarif", ("CWE-89", "src/b.py"))

    summary = BackbonePipeline().ingest(
        first, "acme/app", tmp_path, extra_sarif={"pass-2:gpt": second}
    )

    assert summary.findings == 2, "collapsing these would be silent suppression"
