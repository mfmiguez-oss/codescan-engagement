from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .expert_scope import filter_agent_registry, require_run_expert_scope
from .log import emit
from .paths import root, run_path
from .router_context import load_inventory, read_jsonl, routing_paths
from .template_contract import strip_markers


MAX_RECON_ITEMS_PER_PATH = 3
MAX_RECON_ITEMS = 300

#: Characters of target source embedded in a scenario prompt. A bound is
#: required — a single generated file can be larger than a model's whole
#: context — and, like every bound here, it is reported when it bites rather
#: than applied silently: a reviewer who cannot see the rest of the file must
#: know that, or "I read it and found nothing" is a claim about a file nobody
#: read.
MAX_SOURCE_CHARS = 60_000


def _numbered(text: str) -> str:
    """Number lines from 1, matching what the recorder validates against.

    The integrity check compares an evidence `snippet` to the cited line of the
    checkout, 1-indexed, after collapsing whitespace. Numbering the embedded
    copy the same way is what lets a reviewer cite a line correctly instead of
    counting, and what makes a wrong citation the reviewer's error rather than
    an artifact of how the prompt was rendered.
    """
    lines = text.splitlines()
    width = len(str(len(lines))) if lines else 1
    return "\n".join(f"{number:>{width}} | {line}" for number, line in enumerate(lines, 1))


def _source_block(path: Path, target_path: str) -> str:
    """The target file, inline, so the reviewer has read what it must cite.

    The instructions have always said "read the source file" and the recorder
    has always rejected snippets that do not match it. Both assume a reviewer
    that can open files. A subagent driven over an API has no filesystem, so
    for that reviewer the instruction was unfollowable and the requirement
    unmeetable — and the observed result was not refusal but fabrication: a
    live BenchmarkPython run produced fluent, plausible, entirely invented
    evidence for a file the model had never seen. The integrity check caught
    every item, which is the system working; supplying the source is how the
    reviewer stops being asked to guess in the first place.

    A file that cannot be supplied says so in the prompt. Silence would leave
    exactly the gap this exists to close, and an absent file is a fact the
    reviewer needs in order to answer `needs_context` honestly.
    """
    if not target_path:
        return (
            "The scenario names no target path, so no source is embedded below. "
            "Cite only files whose contents you have actually been given, and "
            "answer `needs_context` for anything you cannot see."
        )
    source = (path / "sourcecode" / target_path).resolve()
    try:
        source.relative_to((path / "sourcecode").resolve())
    except ValueError:
        return (
            f"`{target_path}` resolves outside this run's checkout and was not "
            "embedded. Answer `needs_context`; do not infer its contents."
        )
    if not source.is_file():
        return (
            f"`{target_path}` is not a file in this run's checkout, so its source "
            "could not be embedded. Answer `needs_context` for every obligation "
            "that depends on it; do not infer its contents."
        )
    text = source.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > MAX_SOURCE_CHARS
    body = _numbered(text[:MAX_SOURCE_CHARS])
    header = (
        f"Below is `{target_path}` from this run's checkout, with line numbers. "
        "Cite these line numbers directly. Each evidence `snippet` must be the "
        "content of the cited line, copied without the leading number and `|` "
        "separator."
    )
    if truncated:
        header += (
            f"\n\n**This file was truncated at {MAX_SOURCE_CHARS} characters.** "
            "You are seeing the beginning of it, not all of it. Do not cite or "
            "reason about anything past the last line shown — answer "
            "`needs_context` for obligations that depend on the rest."
        )
    return f"{header}\n\n```\n{body}\n```"


def _expert_routing_context(experts: Iterable[str]) -> str:
    selected = set(experts)
    parts = []
    for expert in sorted((root() / "agents" / "experts").glob("*.md")):
        if expert.stem not in selected:
            continue
        parts.append(f"### Expert: {expert.stem}\n\n{expert.read_text()}")
    return "\n\n".join(parts)


def _compact_recon_items(items: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    compact: list[dict] = []
    for item in items:
        item_path = item.get("path", "")
        counts[item_path] = counts.get(item_path, 0) + 1
        if counts[item_path] > MAX_RECON_ITEMS_PER_PATH:
            continue
        compact.append(item)
        if len(compact) >= MAX_RECON_ITEMS:
            break
    return compact


def prepare_scenario_router(target: str, run_id: str) -> Path:
    path = run_path(target, run_id)
    experts = require_run_expert_scope(path)
    inventory = load_inventory(path)
    paths = routing_paths(inventory.get("coverage_gaps", {}))
    items = [
        item for item in read_jsonl(path / "recon-output" / "recon-items.jsonl")
        if not paths or item.get("path") in paths
    ]
    routing_units = inventory.get("routing_units", [])
    if routing_units:
        items = _compact_recon_items(items)
    template = (root() / "templates" / "scenario-router-prompt.md").read_text()
    text = template.replace(
        "<routing_units_json>",
        json.dumps(routing_units, separators=(",", ":")),
    )
    text = text.replace("<recon_items_json>", json.dumps(items, separators=(",", ":")))
    text = text.replace(
        "<recon_inventory_json>",
        json.dumps(
            {
                key: value for key, value in inventory.items()
                if key not in {"routing_units", "inventory_samples"}
            },
            separators=(",", ":"),
        ),
    )
    text = text.replace(
        "<agent_registry_json>",
        json.dumps(filter_agent_registry(experts), separators=(",", ":")),
    )
    if not routing_units:
        text += "\n\n## All Expert Routing Context\n\n"
        text += _expert_routing_context(experts)
    text += "\n\n## Scenario Router Manifest\n\n"
    text += (root() / "agents" / "orchestration" / "scenario-router.md").read_text()
    out = path / "scenarios" / "scenario-router-prompt.md"
    out.write_text(text)
    detail = (
        f"Prepared agent prompt for {len(routing_units)} routing units"
        if routing_units
        else f"Prepared agent prompt for {len(items)} recon items"
    )
    emit(path, "scenario-router", "needs_agent", detail, evidence=[str(out)])
    return out


def render_prompt(target: str, run_id: str, scenario_id: str) -> Path:
    path = run_path(target, run_id)
    scenario = json.loads((path / "scenarios" / "backlog" / f"{scenario_id}.json").read_text())
    scenario["scenario_id"] = scenario["id"]
    scenario.setdefault("routing_unit_id", "legacy-no-routing-unit")
    scenario.setdefault(
        "security_invariant",
        "Legacy scenario without an explicit security invariant; use the proof question as the invariant.",
    )
    scenario.setdefault(
        "proof_obligations",
        [{
            "id": "legacy_main_question",
            "question": scenario.get("proof_question", "Answer the scenario proof question."),
            "evidence_required": scenario.get("evidence_required", "Cited source evidence is required."),
            "central": True,
        }],
    )
    text = strip_markers((root() / "templates" / "scenario-prompt.md").read_text())
    for key, value in scenario.items():
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, indent=2, sort_keys=True)
        else:
            rendered = str(value)
        text = text.replace(f"<{key}>", rendered)
    text += "\n\n## Target Source\n\n"
    text += _source_block(path, str(scenario.get("target_path", "")))
    expert = root() / "agents" / "experts" / f"{scenario['expert']}.md"
    text += f"\n\n## Expert Manifest\n\n{expert.read_text()}"
    out = path / "scenarios" / "backlog" / f"{scenario_id}.md"
    out.write_text(text)
    emit(path, "scenario-router", "prompted", f"Rendered prompt for {scenario_id}", evidence=[str(out)])
    return out
