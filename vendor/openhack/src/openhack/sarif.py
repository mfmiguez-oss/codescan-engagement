"""SARIF 2.1.0 emitter for triage-accepted findings.

Only findings that completed the durable chain are emitted: a result must have
been recorded through ``finding-triage/decisions/`` with an accepting decision.
Candidates, rejected findings, and Semgrep recon hints are never exported —
SARIF is a report format here, not a queue dump, and the run's own admission
rule is the only gate that decides what counts as a finding.

The structured source is the triage decision, not ``findings/*.md``:
``record_triage`` stores the merged, schema-validated finding inside the
decision, so the emitter reads recorded data rather than re-parsing prose it
would have to guess the structure of.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]

from .log import emit
from .models import Expert, Finding, FindingCandidate, FindingTriage, ScenarioResult
from .paths import run_path
from .registry import load_experts
from .triage import ACCEPTING_DECISIONS

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)
TOOL_NAME = "openhack"
DEFAULT_OUTPUT = "findings.sarif"

#: openhack severity -> (SARIF level, GitHub ``security-severity`` score).
#:
#: SARIF defines only four levels, so **critical and high both map to
#: ``error``** — the distinction cannot survive in ``level`` alone. It is
#: preserved twice over in properties: exactly, as ``openhack_severity``, and
#: numerically, as the ``security-severity`` score consumers rank by. A
#: consumer reading only ``level`` sees a deliberate, documented flattening
#: rather than a silent one.
_SEVERITY: dict[str, tuple[str, str]] = {
    "critical": ("error", "9.5"),
    "high": ("error", "7.5"),
    "medium": ("warning", "5.0"),
    "low": ("note", "3.0"),
    "informational": ("none", "0.0"),
    "unknown": ("none", "0.0"),
}

_CWE_RE = re.compile(r"^(?:cwe[-_ ]?)?(\d+)$", re.IGNORECASE)
_UNSET = {"", "not specified.", "none", "n/a"}


def _is_set(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in _UNSET


def _normalize_cwe(value: Any) -> str | None:
    """``89`` / ``cwe-89`` / ``CWE_89`` -> ``CWE-89``; anything else is None."""
    if not _is_set(value):
        return None
    match = _CWE_RE.match(str(value).strip())
    return f"CWE-{int(match.group(1))}" if match else None


def _finding_cwes(finding: Finding) -> list[str]:
    """Every CWE the finding names itself, in order, de-duplicated."""
    raw = cast(dict[str, Any], finding)
    candidates: list[Any] = []
    for key in ("cwe", "cwe_id", "cwes", "cwe_ids"):
        value = raw.get(key)
        if isinstance(value, list):
            candidates.extend(value)
        elif value is not None:
            candidates.append(value)
    out: list[str] = []
    for item in candidates:
        cwe = _normalize_cwe(item)
        if cwe and cwe not in out:
            out.append(cwe)
    return out


def _rule_id(finding: Finding, expert: str) -> str:
    """The CWE the finding names, else the expert family that owns it.

    A specific CWE is the more useful key for a downstream triage pipeline, but
    it is only used when the finding actually carries one. The expert id is the
    stable fallback: it comes from a fixed registry, so it does not drift when
    a model rewords a vulnerability class between runs — and a rule id that
    drifts splits one issue into two across rescans.
    """
    cwes = _finding_cwes(finding)
    return cwes[0] if cwes else (expert or "finding")


def _relative_uri(value: Any) -> str | None:
    """Normalise a recorded path into a source-relative SARIF artifact URI."""
    if not _is_set(value):
        return None
    text = str(value).strip().replace("\\", "/").lstrip("/")
    if text.startswith("sourcecode/"):
        text = text[len("sourcecode/") :]
    return text or None


def _line(value: Any) -> int | None:
    try:
        line = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return line if line >= 1 else None


def _physical_location(uri: str, line: int | None, snippet: Any = None) -> dict[str, Any]:
    location: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    region: dict[str, Any] = {}
    if line is not None:
        region["startLine"] = line
    if _is_set(snippet):
        region["snippet"] = {"text": str(snippet).strip()}
    if region:
        location["region"] = region
    return {"physicalLocation": location}


def _evidence_items(result: ScenarioResult) -> list[dict[str, Any]]:
    """Scenario evidence, already validated line-by-line against the checkout."""
    items = result.get("evidence") or []
    return [dict(item) for item in items if isinstance(item, dict)]


def _locations(
    finding: Finding, result: ScenarioResult
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The finding's primary location, plus every other cited source line.

    Preference order for the primary: the finding's own target path (enriched
    with a matching evidence snippet when one cites the same file), then the
    first evidence item. Every remaining evidence item becomes a related
    location, so no recorded citation is dropped on the way out.

    A snippet is only ever attached to the line it was recorded against. Taking
    the line from the finding and the text from whichever evidence item happened
    to cite the same file would render a snippet that is not what stands at that
    line — a citation that looks verified and is not.
    """
    evidence = _evidence_items(result)
    target = _relative_uri(finding.get("target_path")) or _relative_uri(
        finding.get("affected_path")
    )

    primary: dict[str, Any] | None = None
    consumed = -1
    if target:
        line = _line(finding.get("line"))
        snippet = None
        same_path = [
            (index, item)
            for index, item in enumerate(evidence)
            if _relative_uri(item.get("path")) == target
        ]
        for index, item in same_path:
            if line is None or _line(item.get("line")) == line:
                line = line or _line(item.get("line"))
                snippet = item.get("snippet")
                consumed = index
                break
        primary = _physical_location(target, line, snippet)
    elif evidence:
        item = evidence[0]
        uri = _relative_uri(item.get("path"))
        if uri:
            primary = _physical_location(uri, _line(item.get("line")), item.get("snippet"))
            consumed = 0

    related: list[dict[str, Any]] = []
    for index, item in enumerate(evidence):
        if index == consumed:
            continue
        uri = _relative_uri(item.get("path"))
        if not uri:
            continue
        location = _physical_location(uri, _line(item.get("line")), item.get("snippet"))
        label = item.get("note") if _is_set(item.get("note")) else item.get("role")
        if _is_set(label):
            location["message"] = {"text": str(label)}
        related.append(location)

    return ([primary] if primary else []), related


def _message(finding: Finding) -> str:
    """The finding's technical summary — one paragraph, nothing more.

    Consumers render ``message.text`` as the alert headline, and several derive
    a title from it verbatim, so impact and remediation stay in properties
    rather than being concatenated here into something that reads badly as a
    title and duplicates what the full report already carries.
    """
    summary = str(finding.get("summary", "")).strip()
    return summary or str(finding.get("title", "Finding")).strip() or "Finding"


def _finding_properties(
    candidate_id: str,
    candidate: FindingCandidate,
    decision: FindingTriage,
    finding: Finding,
    severity: str,
) -> dict[str, Any]:
    """Everything SARIF's own fields cannot carry, kept rather than dropped."""
    properties: dict[str, Any] = {
        "candidate_id": candidate_id,
        "scenario_id": candidate.get("scenario_id", ""),
        "expert": candidate.get("expert", ""),
        "openhack_severity": severity,
        "security-severity": _SEVERITY.get(severity, _SEVERITY["unknown"])[1],
        "triage_decision": decision.get("decision", ""),
        "confidence": decision.get("confidence", ""),
        "review_mode": decision.get("review_mode", ""),
        "triage_agent_id": decision.get("triage_agent_id", ""),
    }
    optional = {
        "vulnerability_class": candidate.get("primary_vulnerability_class"),
        "severity_rationale": decision.get("severity_rationale"),
        "triage_summary": decision.get("summary"),
        "attacker_role": finding.get("attacker_role"),
        "preconditions": finding.get("preconditions"),
        "recommended_fix": finding.get("recommended_fix"),
        "impact": finding.get("impact"),
    }
    for key, value in optional.items():
        if _is_set(value):
            properties[key] = str(value).strip()
    cwes = _finding_cwes(finding)
    if cwes:
        properties["cwe"] = cwes
    return {key: value for key, value in properties.items() if value != ""}


def _expert_index() -> dict[str, Expert]:
    return {str(expert.get("id", "")): expert for expert in load_experts()}


def _rule(rule_id: str, expert_id: str, experts: dict[str, Expert]) -> dict[str, Any]:
    """A rule descriptor, enriched from the owning expert's manifest."""
    expert = experts.get(expert_id, cast(Expert, {}))
    meta = cast(dict[str, Any], expert)
    tags: list[str] = [str(tag) for tag in (meta.get("tags") or [])]
    if rule_id.startswith("CWE-"):
        tag = f"external/cwe/{rule_id.lower()}"
        if tag not in tags:
            tags.insert(0, tag)
    title = str(meta.get("title") or expert_id or rule_id)
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
    }
    properties: dict[str, Any] = {}
    if tags:
        properties["tags"] = tags
    standards = [str(ref) for ref in (meta.get("standard_refs") or [])]
    if standards:
        properties["standard_refs"] = standards
    if expert_id:
        properties["expert"] = expert_id
    if properties:
        rule["properties"] = properties
    return rule


def _run_config(path: Path) -> dict[str, Any]:
    config = path / "run-config.yaml"
    if not config.exists():
        return {}
    try:
        loaded = yaml.safe_load(config.read_text())
    except yaml.YAMLError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _version_control(path: Path) -> list[dict[str, Any]]:
    source = _run_config(path).get("source")
    if not isinstance(source, dict):
        return []
    provenance: dict[str, Any] = {}
    if _is_set(source.get("git_url")):
        provenance["repositoryUri"] = str(source["git_url"])
    if _is_set(source.get("commit")):
        provenance["revisionId"] = str(source["commit"])
    if _is_set(source.get("branch")):
        provenance["branch"] = str(source["branch"])
    return [provenance] if provenance.get("repositoryUri") else []


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _accepted_decisions(path: Path) -> list[tuple[str, FindingTriage]]:
    decisions: list[tuple[str, FindingTriage]] = []
    directory = path / "finding-triage" / "decisions"
    for decision_file in sorted(directory.glob("S*-F*.json")):
        try:
            decision = cast(FindingTriage, _load(decision_file))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Unreadable triage decision {decision_file.name}: {exc}") from exc
        if decision.get("decision") in ACCEPTING_DECISIONS:
            decisions.append((decision_file.stem, decision))
    return decisions


def build_sarif(target: str, run_id: str) -> dict[str, Any]:
    """Build the SARIF log for every triage-accepted finding in a run."""
    path = run_path(target, run_id)
    if not path.exists():
        raise ValueError(f"Unknown run: {target}/{run_id}")

    experts = _expert_index()
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for candidate_id, decision in _accepted_decisions(path):
        finding = cast(Finding, decision.get("finding") or {})
        if not finding:
            raise ValueError(
                f"Accepting triage decision {candidate_id} carries no finding; "
                "re-record it with `openhack record-finding-triage`."
            )
        candidate_file = path / "finding-candidates" / f"{candidate_id}.json"
        candidate = cast(
            FindingCandidate, _load(candidate_file) if candidate_file.exists() else {}
        )
        result_file = path / "scenarios" / "finished" / f"{candidate.get('scenario_id', '')}.json"
        scenario_result = cast(
            ScenarioResult, _load(result_file) if result_file.exists() else {}
        )

        expert_id = str(candidate.get("expert", ""))
        rule_id = _rule_id(finding, expert_id)
        rules.setdefault(rule_id, _rule(rule_id, expert_id, experts))

        severity = str(finding.get("severity", "unknown")).strip().lower()
        level = _SEVERITY.get(severity, _SEVERITY["unknown"])[0]
        locations, related = _locations(finding, scenario_result)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": 0,  # rewritten below, once the rule order is final
            "level": level,
            "message": {"text": _message(finding)},
            "locations": locations,
            "properties": _finding_properties(
                candidate_id, candidate, decision, finding, severity
            ),
        }
        if related:
            result["relatedLocations"] = related
        if _is_set(finding.get("title")):
            result["properties"]["title"] = str(finding["title"]).strip()
        results.append(result)

    ordered = sorted(rules)
    index = {rule_id: position for position, rule_id in enumerate(ordered)}
    for result in results:
        result["ruleIndex"] = index[result["ruleId"]]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": "https://github.com/hadrian-security/openhack",
                "rules": [rules[rule_id] for rule_id in ordered],
            }
        },
        "automationDetails": {"id": f"{target}/{run_id}"},
        "results": results,
    }
    provenance = _version_control(path)
    if provenance:
        run["versionControlProvenance"] = provenance

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def emit_sarif(target: str, run_id: str, out: Path | None = None) -> tuple[Path, int]:
    """Write the SARIF log for a run. Returns the path and the result count."""
    path = run_path(target, run_id)
    log = build_sarif(target, run_id)
    destination = out or (path / DEFAULT_OUTPUT)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n")
    count = len(log["runs"][0]["results"])
    emit(
        path,
        "sarif-emitter",
        "complete",
        f"Emitted {count} triage-accepted finding(s) as SARIF",
        evidence=[str(destination)],
    )
    return destination, count
