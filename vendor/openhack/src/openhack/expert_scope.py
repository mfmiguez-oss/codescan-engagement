from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence

from .models import AgentRegistry, Expert, ExpertScope
from .registry import expert_ids, filter_registry, load_experts


def all_experts() -> list[Expert]:
    return load_experts()


def all_expert_ids() -> list[str]:
    return expert_ids()


def expert_options_text() -> str:
    lines = ["all agents"]
    for expert in all_experts():
        title = expert.get("title") or expert.get("category", "unknown")
        lines.append(f"{expert['id']} - {title}")
    return "\n".join(f"- {line}" for line in lines)


def _remove_scope_block(lines: list[str]) -> list[str]:
    out: list[str] = []
    index = 0
    while index < len(lines):
        if lines[index] == "expert_scope:":
            index += 1
            while index < len(lines) and (
                lines[index].startswith("  ") or not lines[index].strip()
            ):
                index += 1
            continue
        out.append(lines[index])
        index += 1
    return out


def _quote(value: str) -> str:
    return json.dumps(value)


def set_run_expert_scope(
    path: Path,
    experts: Iterable[str] | None = None,
    all_agents: bool = False,
) -> list[str]:
    known = set(all_expert_ids())
    if all_agents:
        selected = all_expert_ids()
        mode = "all"
    else:
        selected = list(dict.fromkeys(experts or []))
        unknown = sorted(set(selected) - known)
        if unknown:
            raise ValueError(f"Unknown expert id(s): {', '.join(unknown)}")
        if not selected:
            raise ValueError("Choose at least one expert or use all agents.")
        mode = "selected"

    config = path / "run-config.yaml"
    lines = _remove_scope_block(config.read_text().splitlines())
    block = [
        "expert_scope:",
        f"  mode: {_quote(mode)}",
        "  experts:",
        *[f"    - {_quote(expert)}" for expert in selected],
    ]
    insert_at = len(lines)
    for index, line in enumerate(lines):
        if line.startswith("quality_gates:"):
            insert_at = index
            break
    lines[insert_at:insert_at] = block
    config.write_text("\n".join(lines).rstrip() + "\n")
    return selected


def read_run_expert_scope(path: Path) -> ExpertScope | None:
    config = path / "run-config.yaml"
    if not config.exists():
        return None
    lines = config.read_text().splitlines()
    in_scope = False
    in_experts = False
    mode = None
    experts = []
    for raw in lines:
        if raw == "expert_scope:":
            in_scope = True
            in_experts = False
            continue
        if in_scope and raw and not raw.startswith(" "):
            break
        if not in_scope:
            continue
        stripped = raw.strip()
        if stripped.startswith("mode:"):
            mode = json.loads(stripped.split(":", 1)[1].strip())
            in_experts = False
        elif stripped == "experts:":
            in_experts = True
        elif in_experts and stripped.startswith("- "):
            experts.append(json.loads(stripped[2:].strip()))
    if not mode:
        return None
    return {"mode": mode, "experts": experts}


def require_run_expert_scope(path: Path) -> list[str]:
    scope = read_run_expert_scope(path)
    if scope and scope.get("experts"):
        return scope["experts"]
    raise ValueError(
        "Choose security experts before recon. Use --all-agents or repeat "
        "--expert <id>. Available options:\n" + expert_options_text()
    )


def scope_summary(experts: Sequence[str]) -> str:
    all_ids = all_expert_ids()
    if list(experts) == all_ids:
        return f"all agents ({len(all_ids)} experts)"
    return f"{len(experts)} selected expert(s): {', '.join(experts)}"


def filter_agent_registry(experts: Iterable[str]) -> AgentRegistry:
    return filter_registry(experts)


def scope_constraint_text(experts: Sequence[str]) -> str:
    """The binding statement of scope, for a prompt whose guidance ignores it.

    The router manifest is written for the whole methodology: it says things
    like "route to `sensitive-information-exposure` when the response leaks
    secrets", naming every expert the method defines. A scoped run narrows the
    agent registry and the routing context but appends that manifest verbatim,
    so the model is *instructed* to route outside the scope — and
    `record-scenario-backlog` then rejects the backlog for doing what it was
    told. A live pygoat run scoped to two experts died exactly there, after
    five router calls had already been paid for.

    Filtering the manifest's prose was the alternative and is worse: the
    guidance is connected sentences with conditionals, and cutting expert names
    out of them leaves instructions that mean something else. So the scope is
    stated instead — plainly, and *after* the manifest, because a constraint
    that arrives before the guidance it overrides is the one that loses.

    Returns an empty string when the run selects every expert, since there is
    then nothing to constrain and a redundant warning only dilutes the ones
    that matter.
    """
    selected = list(experts)
    if not selected or set(selected) >= set(all_expert_ids()):
        return ""
    listed = "\n".join(f"- {expert}" for expert in selected)
    return (
        "\n\n## Expert Scope (binding — overrides the guidance above)\n\n"
        "This run is scoped to these experts only:\n\n"
        f"{listed}\n\n"
        "Every scenario you emit must name one of them in its `expert` field. "
        "The routing guidance above describes the whole methodology, including "
        "experts this run has excluded; where it tells you to route to one that "
        "is not listed here, emit no scenario for it and move on. Do not "
        "substitute a listed expert for an unlisted one either — a boundary "
        "that only an excluded expert covers is out of scope for this run, not "
        "work to be reassigned.\n\n"
        "A scenario naming an unlisted expert is rejected, and the rejection "
        "fails the entire backlog rather than that one scenario.\n"
    )
