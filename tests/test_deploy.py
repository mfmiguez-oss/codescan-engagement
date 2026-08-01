"""The deployment files, checked against each other.

These caught nothing when they were written, because they were written after
the bug they describe: the control-plane container's command was ``uvicorn``
while the image installed only the provider extras, so it built cleanly and
failed to start. Nothing in the suite noticed, because the gate deliberately
runs without extras and nothing exercised the built image.

Cross-file consistency is exactly the kind of thing that rots silently — two
files edited in different turns, each correct alone — so it is asserted here
rather than left to whoever next reads both.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
BICEP = (ROOT / "deploy" / "azure" / "main.bicep").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

EXTRAS = PYPROJECT["project"]["optional-dependencies"]


def _installed_extras() -> set[str]:
    """The extras the image actually installs."""
    match = re.search(r'pip install --no-cache-dir "\.\[([^\]]+)\]"', DOCKERFILE)
    assert match, "could not find the extras the Dockerfile installs"
    return {name.strip() for name in match.group(1).split(",")}


def test_every_extra_the_image_installs_exists() -> None:
    unknown = _installed_extras() - set(EXTRAS)
    assert not unknown, f"Dockerfile installs undeclared extras: {unknown}"


def test_the_image_installs_what_the_control_plane_command_needs() -> None:
    """The bug this file exists for: Bicep runs `uvicorn`, so the image has to
    contain it, and it only arrives with the `api` extra."""
    commands = re.findall(r"command:\s*\['([^']+)'\]", BICEP)
    assert commands, "no container command found in the Bicep template"

    provided = {
        # binary -> the extra that installs it
        "uvicorn": "uvicorn",
        "engagement": None,  # the package's own entry point
    }
    installed = _installed_extras()
    for command in commands:
        requirement = provided.get(command)
        if requirement is None:
            continue
        satisfying = {
            name
            for name, deps in EXTRAS.items()
            if any(requirement in dep for dep in deps)
        }
        assert satisfying & installed, (
            f"the Bicep template runs {command!r} but the image installs "
            f"{sorted(installed)}; it is provided by {sorted(satisfying)}"
        )


def test_the_image_carries_the_vendored_workspace() -> None:
    """Without it the container builds and then cannot scan — which is the one
    thing it exists to do."""
    assert "COPY vendor ./vendor" in DOCKERFILE
    assert "pip install --no-cache-dir ./vendor/openhack" in DOCKERFILE
    assert "OPENHACK_ROOT" in DOCKERFILE


def test_the_workspace_root_is_not_shadowed_by_a_volume() -> None:
    """Mounting over the root would hide the vendored methodology and leave a
    container with no experts to route to, so only `runs/` is a volume."""
    volumes = re.search(r'VOLUME \[([^\]]+)\]', DOCKERFILE)
    assert volumes, "no VOLUME declaration found"
    declared = {item.strip().strip('"') for item in volumes.group(1).split(",")}
    assert "/workspace" not in declared
    assert "/workspace/runs" in declared


def test_the_container_does_not_run_as_root() -> None:
    """It reads source under review, which is untrusted by definition."""
    assert re.search(r"^USER \w+", DOCKERFILE, re.M), "no USER directive"
    assert DOCKERFILE.rstrip().count("USER root") == 0


def test_the_control_plane_is_opt_in() -> None:
    """An endpoint that accepts state changes should not appear by accident."""
    assert re.search(
        r"param deployControlPlane bool = false", BICEP
    ), "deployControlPlane must default to false"


def test_the_triage_extra_points_somewhere_installable() -> None:
    """`triagekit` is on no index, so a bare requirement resolves to nothing.
    A direct reference at least fails with an address rather than a shrug."""
    triage = EXTRAS["triage"]
    assert any("@" in dep and "git+" in dep for dep in triage), (
        f"the triage extra must name a resolvable source, got {triage}"
    )


#: Environment variables the template sets that this package deliberately does
#: not read, each with the thing that does. Anything not listed here and not
#: read by the code is dead configuration.
_READ_ELSEWHERE = {
    "AZURE_CLIENT_ID": "the Azure SDK's default credential chain",
    "OPENHACK_ROOT": "the vendored openhack package",
}


def _package_source() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src" / "engagement").rglob("*.py"))
    )


def _is_referenced(name: str, source: str) -> bool:
    """Whether the package mentions this variable name at all.

    Deliberately asks "is it referenced" rather than "is it read at a call site
    matching one of these shapes". The first version of this check matched only
    ``env.get("LITERAL")`` and reported a live variable as dead, because it is
    read through a helper that takes the name as an argument. Indirection is
    normal; a detector that breaks on it produces false alarms about the very
    thing it exists to police.
    """
    return f'"{name}"' in source or f"'{name}'" in source


def test_every_environment_variable_the_template_sets_is_read_somewhere() -> None:
    """Dead configuration is worse than absent configuration.

    `ENGAGEMENT_MAX_CALLS` was set by this template and read by nothing, so an
    operator who configured a budget silently got the default — a bound that
    looks applied and is not. Nothing caught it because the deploy checks
    compared files to each other and never to the code.
    """
    declared = set(re.findall(r"\{\s*name:\s*'([A-Z][A-Z0-9_]+)'", BICEP))
    assert declared, "no environment variables found in the template"

    source = _package_source()
    unread = sorted(
        name
        for name in declared
        if name not in _READ_ELSEWHERE and not _is_referenced(name, source)
    )
    assert not unread, (
        f"the template sets {unread}, which nothing reads — either wire them "
        "up or remove them from the template"
    )


def test_the_budget_can_be_configured_from_the_environment() -> None:
    """The template's whole reason for setting it."""
    for name in ("ENGAGEMENT_MAX_CALLS", "ENGAGEMENT_MAX_TOKENS"):
        assert _is_referenced(name, _package_source()), f"{name} is not read"
    assert "ENGAGEMENT_MAX_CALLS" in BICEP
