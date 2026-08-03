"""The vendored workspace, and whether it still is what it claims to be.

Vendoring buys a hermetic image and pays for it in drift. That is only an
acceptable trade while the drift is *detectable*, which is what these tests
are: the first two catch the copy being edited in place or going missing, and
the last catches it falling behind the upstream it was taken from — but only
when that upstream happens to be on disk, so the gate stays runnable from a
lone checkout.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor" / "openhack"
MANIFEST = VENDOR / "vendor-manifest.json"
UPSTREAM = ROOT.parent / "OpenHack-main"


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_the_vendored_workspace_is_present_and_complete() -> None:
    """The image copies this tree wholesale; a missing piece is a container
    that builds and then cannot scan."""
    assert MANIFEST.is_file(), "vendored workspace is missing its manifest"
    for required in (
        VENDOR / "src" / "openhack" / "cli.py",
        VENDOR / "agents" / "experts",
        VENDOR / "templates" / "scenario-prompt.md",
        VENDOR / "config" / "finding-schema.json",
        VENDOR / "pyproject.toml",
    ):
        assert required.exists(), f"vendored workspace is missing {required.name}"


def test_the_root_markers_openhack_looks_for_are_present() -> None:
    """OpenHack resolves its root by these two paths. Vendoring everything
    else and missing one of them produces a tree it will refuse to use."""
    assert (VENDOR / "agents" / "experts").is_dir()
    assert (VENDOR / "templates" / "scenario-prompt.md").is_file()


def test_no_vendored_file_has_been_edited_in_place() -> None:
    """A vendored copy is a mirror, not a fork. An edit here is a change that
    would be silently lost the next time it is refreshed."""
    manifest = _manifest()
    files = manifest["files"]
    assert isinstance(files, dict)

    changed: list[str] = []
    missing: list[str] = []
    for relative, expected in sorted(files.items()):
        path = VENDOR / relative
        if not path.is_file():
            missing.append(relative)
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            changed.append(relative)

    assert not missing, f"vendored files missing: {missing[:5]}"
    assert not changed, (
        f"vendored files edited in place: {changed[:5]} — change them upstream "
        "and re-run scripts/vendor_openhack.py"
    )


def test_no_run_artifacts_were_vendored() -> None:
    """Run folders are someone else's data and must never ride along."""
    assert not (VENDOR / "runs").exists()
    assert not list(VENDOR.rglob("__pycache__"))


#: Build output setuptools writes *into* a source tree it installs from, which
#: the documented install (``pip install ./vendor/openhack``) therefore creates.
#: Gitignored, so it can never be committed — which is exactly the scope of the
#: guard below: it stops pollution entering the mirror, not pollution existing
#: transiently in a working tree.
_BUILD_ARTIFACT_PREFIXES = ("build/", "src/openhack.egg-info/")


def test_build_artifacts_are_gitignored() -> None:
    """The guard below tolerates these paths only because they cannot be
    committed. If that stops being true, the tolerance is a hole."""
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "vendor/**/build/" in ignored
    assert "vendor/**/*.egg-info/" in ignored


def test_the_mirror_contains_nothing_the_manifest_does_not_track() -> None:
    """Catches pollution, not just edits.

    Checking only that *tracked* files are unmodified misses a whole class of
    problem: files the manifest never heard of, sitting in a tree that is
    deliberately committed. Anything not gitignored and not in the manifest
    would be committed as if it were part of the vendored methodology.
    """
    manifest = _manifest()
    tracked = set(manifest["files"])  # type: ignore[arg-type]
    tracked.add("vendor-manifest.json")

    on_disk = {
        str(path.relative_to(VENDOR)).replace("\\", "/")
        for path in VENDOR.rglob("*")
        if path.is_file()
    }
    committable = {
        path
        for path in on_disk
        if not path.startswith(_BUILD_ARTIFACT_PREFIXES)
    }
    untracked = sorted(committable - tracked)
    assert not untracked, (
        f"the vendored mirror has {len(untracked)} untracked file(s), e.g. "
        f"{untracked[:3]} — anything not gitignored would be committed as "
        "vendored methodology"
    )


def test_the_manifest_records_whether_the_source_was_dirty() -> None:
    """The mirror must never claim a provenance it does not have.

    `vendor_openhack.py` copies the **working tree** while recording `git HEAD`
    as the source commit, so vendoring from a dirty checkout produces a
    manifest naming a commit that does not contain what was vendored. The
    in-place guard still passes — it compares against the hashes recorded here
    — so nothing fails and the mirror silently stops being reproducible.

    An empty list is the honest answer for a clean checkout; the field being
    *absent* means it was vendored before anyone thought to record it.
    """
    manifest = _manifest()
    assert "source_dirty" in manifest, (
        "the manifest does not record whether the source tree was clean, so "
        "`source_commit` cannot be trusted to reproduce it — re-run "
        "scripts/vendor_openhack.py"
    )
    assert isinstance(manifest["source_dirty"], list)


@pytest.mark.skipif(
    not (UPSTREAM / "src" / "openhack").is_dir(),
    reason="upstream OpenHack checkout not present alongside this repo",
)
def test_the_vendored_copy_has_not_fallen_behind_upstream() -> None:
    """The drift check proper.

    Skipped when the upstream is not on disk, because a lone checkout must
    still be able to run its own gate — the cost is that CI cannot catch drift
    on its own, only a developer with both repos can.
    """
    manifest = _manifest()
    files = manifest["files"]
    assert isinstance(files, dict)

    stale: list[str] = []
    for relative, vendored_hash in sorted(files.items()):
        if relative in {"vendor-manifest.json"}:
            continue
        # the manifest is flat over the vendored root, which mirrors upstream
        source = UPSTREAM / relative
        if not source.is_file():
            stale.append(f"{relative} (removed upstream)")
            continue
        if hashlib.sha256(source.read_bytes()).hexdigest() != vendored_hash:
            stale.append(f"{relative} (changed upstream)")

    assert not stale, (
        f"vendored workspace has fallen behind upstream: {stale[:5]} — "
        "re-run scripts/vendor_openhack.py"
    )


@pytest.mark.skipif(
    not (UPSTREAM / "src" / "openhack").is_dir(),
    reason="upstream OpenHack checkout not present alongside this repo",
)
def test_upstream_has_not_gained_a_file_the_mirror_never_took() -> None:
    """The half of drift the manifest cannot see by itself.

    Walking the manifest catches a vendored file that changed or vanished
    upstream, because both are questions *about a file the manifest lists*. An
    added one is not: it appears nowhere in `files`, so the loop never asks. A
    commit that only adds — a new expert manifest, a new schema, a new module —
    leaves the mirror silently one file short.

    Found the way it would bite in production: an upstream change added
    `template_contract.py`, and the drift check named the three files it also
    touched while saying nothing about the new one. Had that commit added only
    the module, the mirror would have gone on reporting itself current.

    The traversal rules are restated here rather than imported from
    `vendor_openhack.py`, so a mistake in the script's idea of what to copy is
    something this can still catch.
    """
    manifest = _manifest()
    files = manifest["files"]
    trees = manifest["trees"]
    assert isinstance(files, dict)
    assert isinstance(trees, list)

    missing: list[str] = []
    for tree in sorted(trees):
        source = UPSTREAM / str(tree)
        if not source.is_dir():
            continue
        for item in sorted(source.rglob("*")):
            relative = item.relative_to(UPSTREAM)
            if not item.is_file():
                continue
            if "__pycache__" in relative.parts or item.suffix in {".pyc", ".pyo"}:
                continue
            if relative.as_posix() not in files:
                missing.append(relative.as_posix())

    assert not missing, (
        f"upstream has {len(missing)} file(s) the mirror never took, e.g. "
        f"{missing[:5]} — re-run scripts/vendor_openhack.py"
    )
