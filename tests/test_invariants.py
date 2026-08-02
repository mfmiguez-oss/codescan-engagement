"""One invariant per mitigated risk, plus the meta-test that keeps the
register and the code from drifting apart.

A conformance document is worth exactly as much as the checking behind it. The
meta-test is what stops this one becoming a description of intentions: a row
cannot claim "mitigated" unless it names a test that exists.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
THREATMODEL = ROOT / "docs" / "THREATMODEL.md"
OUTPUTS = ROOT / "docs" / "OUTPUTS.md"
FRAMEWORKS = ROOT / "docs" / "SECURITY_FRAMEWORKS.md"
TESTS_DIR = Path(__file__).parent
SRC_DIR = ROOT / "src" / "engagement"

_ROW = re.compile(r"^\|\s*(R\d+)\s*\|(.+)\|\s*(mitigated|open)\s*\|\s*([^|]+)\|\s*$")


def _rows() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in THREATMODEL.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line.strip())
        if match:
            rows.append((match.group(1), match.group(3), match.group(4).strip()))
    return rows


def _all_test_source() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(TESTS_DIR.glob("test_*.py"))
    )


def test_the_register_parses_and_is_not_empty() -> None:
    rows = _rows()
    assert len(rows) >= 20, "the risk register went missing or unparseable"
    assert any(status == "open" for _, status, _ in rows), (
        "a register with no open rows has stopped being honest"
    )


def test_every_mitigated_risk_names_an_invariant_test_that_exists() -> None:
    """The meta-test: a 'mitigated' row with nothing behind it fails here, so
    the register cannot take credit the code does not back."""
    source = _all_test_source()
    missing: list[str] = []
    for risk_id, status, test_name in _rows():
        if status != "mitigated":
            continue
        if test_name in {"", "—", "-"}:
            missing.append(f"{risk_id}: no invariant test named")
        elif f"def {test_name}(" not in source:
            missing.append(f"{risk_id}: names '{test_name}', which does not exist")
    assert not missing, "; ".join(missing)


def test_every_open_risk_declines_to_name_a_test() -> None:
    """An open row with a test beside it is a mitigated row that forgot to say
    so — or a claim dressed as a gap."""
    wrong = [
        risk_id
        for risk_id, status, test_name in _rows()
        if status == "open" and test_name not in {"", "—", "-"}
    ]
    assert not wrong, f"open rows naming a test: {wrong}"


def test_every_per_output_threat_names_a_test_that_exists() -> None:
    """OUTPUTS.md is organised by artifact rather than by risk, so the
    register's meta-test does not reach it. It gets its own, for the same
    reason: a control named in a document and nowhere else is a description of
    an intention.

    An em dash is allowed where the control is structural — "the page has no
    write path" cannot be tested by asserting the absence of code that was
    never written.
    """
    source = _all_test_source()
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", OUTPUTS.read_text(encoding="utf-8")))
    assert named, "OUTPUTS.md names no tests at all"
    missing = sorted(name for name in named if f"def {name}(" not in source)
    assert not missing, f"per-output rows naming tests that do not exist: {missing}"


def test_every_output_of_the_pipeline_has_a_threat_model() -> None:
    """The failure this catches: a new artifact ships and nobody asks what it
    could mislead a reader into believing."""
    headings = "\n".join(
        line
        for line in OUTPUTS.read_text(encoding="utf-8").splitlines()
        if line.startswith("### ")
    )
    missing = [
        artifact
        for artifact in (
            "findings.sarif",
            "queue.csv",
            "queue.json",
            "chains.json",
            "pocs.md",
            "audit.jsonl",
            "decisions.jsonl",
            "report.html",
            "threat-model.md",
            "SIEM export",
            "cached prompt prefix",
        )
        if artifact not in headings
    ]
    assert not missing, f"outputs this package produces with no threat model: {missing}"


def test_every_per_output_diagram_renders_in_the_document() -> None:
    """"Readable directly in the md file" is the requirement: a diagram that
    needs a build step or an external renderer is a diagram nobody looks at."""
    text = OUTPUTS.read_text(encoding="utf-8")

    opened = text.count("```mermaid")
    closed = text.count("```")
    assert opened >= 9, f"only {opened} diagrams in OUTPUTS.md"
    assert closed == opened * 2, "an unbalanced fence would swallow the rest of the file"
    assert "![" not in text, "an image reference is not readable in the file itself"


def test_the_outputs_document_lists_every_artifact_a_run_writes() -> None:
    """The map at the top and the sections below it must not drift: a file in
    one and not the other is an output nobody can look up."""
    text = OUTPUTS.read_text(encoding="utf-8")
    for artifact in ("threat-model.md", "queue.csv", "report.html", "decisions.jsonl"):
        assert f"`{artifact}`" in text, f"{artifact} is missing from OUTPUTS.md"


def test_the_frameworks_document_is_dated() -> None:
    """Category names and technique ids move between revisions. An undated
    conformance claim is a claim about an unknown version."""
    text = FRAMEWORKS.read_text(encoding="utf-8")
    assert re.search(r"Assessed 20\d\d-\d\d-\d\d", text), (
        "SECURITY_FRAMEWORKS.md must record the date it was assessed"
    )


def test_the_frameworks_document_takes_no_unbacked_credit() -> None:
    """Every 'Enforced' verdict has to name a test, for the same reason the
    register does."""
    source = _all_test_source()
    text = FRAMEWORKS.read_text(encoding="utf-8")
    missing: list[str] = []
    for line in text.splitlines():
        if "| Enforced |" not in line:
            continue
        named = re.findall(r"`(test_[a-z0-9_]+)`", line)
        if not named:
            missing.append(line.strip()[:70])
            continue
        for name in named:
            if f"def {name}(" not in source:
                missing.append(f"{name} does not exist")
    assert not missing, f"Enforced rows without a real test: {missing[:4]}"


# -- invariants the register names ------------------------------------------


def test_no_dynamic_execution_primitives_in_source() -> None:
    """Model output is data. Nothing in this package can turn it into code."""
    offenders: list[str] = []
    pattern = re.compile(r"\beval\(|\bexec\(|shell\s*=\s*True|os\.system\(")
    for path in sorted(SRC_DIR.rglob("*.py")):
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if pattern.search(line):
                offenders.append(f"{path.name}:{number}")
    assert not offenders, f"dynamic execution primitives: {offenders}"


def test_the_claim_store_uses_no_string_interpolated_sql() -> None:
    """Every statement is parameterised; a repo name is data, not syntax."""
    source = (SRC_DIR / "claims.py").read_text(encoding="utf-8")
    interpolated = re.findall(
        r"""(?:execute|executemany)\(\s*f["']""", source
    )
    assert not interpolated, "f-string SQL in the claim store"
    assert '%(worker)s' in source, "the claim query should bind parameters by name"
