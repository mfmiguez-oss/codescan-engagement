"""End-to-end: a real workspace, and then the built image.

Everything else in this suite runs against a fake workspace, which is the right
default — it is fast, deterministic, and enforces the same rules. What it cannot
prove is that the *adapter* speaks the real recorder's language. Two defects
that shipped past a green suite were both in that gap: a prompt digest computed
over decoded text rather than file bytes, and a container whose command was not
installed.

So these two tests are deliberately expensive. The first drives the vendored
workspace in-process; the second drives the image. Both skip cleanly when their
prerequisite is absent, so a lone checkout still runs its own gate.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from e2e_runner import build_fixture_repo, drive
from engagement.workspace import seed_workspace

IMAGE = "codescan-engagement:ci"


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


def _docker_image_present() -> bool:
    if not _has("docker"):
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, check=False
    )
    return result.returncode == 0


openhack_installed = pytest.importorskip


@pytest.mark.skipif(not _has("git"), reason="git is required to clone the fixture")
def test_a_real_workspace_runs_end_to_end(tmp_path: Path) -> None:
    """The integration the fake cannot prove: the adapter against the real
    recorders, with every integrity check enforced.

    A scripted provider supplies judgement, but nothing else is stubbed —
    coverage validation, prompt-hash binding, evidence re-read from the
    checkout and agent-id uniqueness all run for real, and each one is capable
    of failing this test.
    """
    pytest.importorskip("openhack", reason="vendored workspace is not installed")

    workspace = seed_workspace(tmp_path / "workspace")
    target = build_fixture_repo(tmp_path / "target")

    subprocess.run(
        ["python", "-m", "openhack", "init-run", "e2e", str(target), "--run-id", "r1"],
        cwd=workspace, capture_output=True, check=True,
        env={**_env(workspace)},
    )

    report, provider = drive(workspace, "e2e", "r1")

    # one call per phase, which is the whole cost model
    assert provider.calls == ["router", "expert", "triage"]
    assert report.model_calls == 3
    assert report.scenarios_completed == 1
    assert report.is_complete()
    assert report.reviewed_fraction == 1.0

    run_dir = workspace / "runs" / "e2e" / "r1"
    findings = list((run_dir / "findings").glob("*.md"))
    assert findings, "an accepted triage decision should materialize a finding"

    # the provenance chain the driver stamped, as the recorder stored it
    result = json.loads((run_dir / "scenarios" / "finished" / "S001.json").read_text())
    assert result["subagent_id"].startswith("expert-S001-")
    assert len(result["scenario_prompt_sha256"]) == 64

    sarif = json.loads((run_dir / "findings.sarif").read_text())
    entry = sarif["runs"][0]["results"][0]
    assert entry["ruleId"] == "CWE-89"
    assert entry["properties"]["openhack_severity"] == "critical"


def _env(workspace: Path) -> dict[str, str]:
    import os

    return {**os.environ, "OPENHACK_ROOT": str(workspace)}


@pytest.mark.skipif(
    not _docker_image_present(),
    reason=f"{IMAGE} not built (docker build -f deploy/Dockerfile -t {IMAGE} .)",
)
def test_the_built_image_runs_a_scan_end_to_end(tmp_path: Path) -> None:
    """The check that would have caught a container whose command was missing,
    and whose workspace was baked into the wrong place."""
    target = build_fixture_repo(tmp_path / "target")
    runner = Path(__file__).parent / "e2e_runner.py"

    script = (
        "set -e\n"
        # the mounted checkout is owned by the host user, not uid 10001
        "git config --global --add safe.directory '*'\n"
        "python -m openhack init-run ctr /target --run-id c1 >/dev/null\n"
        "python /e2e_runner.py /workspace ctr c1\n"
    )
    completed = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{target}:/target:ro",
            "-v", f"{runner}:/e2e_runner.py:ro",
            "--entrypoint", "bash", IMAGE, "-c", script,
        ],
        capture_output=True, text=True, check=False, timeout=600,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]

    summary = json.loads(completed.stdout.strip().splitlines()[-1])
    assert summary["dispatched"] == ["router", "expert", "triage"]
    assert summary["complete"] is True
    assert summary["scenarios_completed"] == 1
    assert summary["candidates"] == 1
    assert summary["reviewed_fraction"] == 1.0
    # written inside the container, at the baked workspace root
    assert summary["sarif"].startswith("/workspace/runs/ctr/c1")


@pytest.mark.skipif(not _docker_image_present(), reason=f"{IMAGE} not built")
def test_the_image_does_not_run_as_root() -> None:
    """It reads source under review, which is untrusted by definition."""
    completed = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "id", IMAGE],
        capture_output=True, text=True, check=True, timeout=120,
    )
    assert "uid=0(root)" not in completed.stdout
    assert "uid=10001" in completed.stdout
