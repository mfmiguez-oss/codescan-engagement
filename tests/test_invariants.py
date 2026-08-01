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
