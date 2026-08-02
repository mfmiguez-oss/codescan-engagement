"""Refresh the vendored OpenHack workspace from a source checkout.

The container has to be able to run a scan without reaching a private
repository at build time, so the workspace the driver operates on is vendored
into this repo rather than fetched. That buys reproducibility and pays for it
in drift, which is only an acceptable trade when the drift is *detectable* —
so this script records the source commit and a hash of every copied file, and
``tests/test_vendor.py`` fails when the vendored tree stops matching its own
manifest.

Usage:

    python scripts/vendor_openhack.py ../OpenHack-main

Run it whenever the upstream methodology changes, and commit the result as one
deliberate change rather than letting the copy quietly diverge.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor" / "openhack"
MANIFEST = VENDOR / "vendor-manifest.json"

#: Directories copied wholesale. This is the methodology plus the code that
#: enforces it — the expert manifests, the prompt templates, the schemas the
#: recorders validate against, and the package itself.
TREES = ("src/openhack", "agents", "templates", "config")

#: Individual files worth carrying: the package metadata needed to install it,
#: the licence, which travels with the code it covers, and the README the
#: metadata declares — setuptools reads it at build time, so omitting it makes
#: the vendored tree fail to install on a stricter setuptools than today's.
FILES = ("pyproject.toml", "LICENSE", "README.md")

#: Never vendored. Run artifacts are someone else's data, and caches are noise.
EXCLUDE_DIRS = {"__pycache__", ".git", "runs", ".venv", "node_modules"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


def _keep(path: Path) -> bool:
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return False
    return path.suffix not in EXCLUDE_SUFFIXES


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_commit(source: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


def _source_url(source: Path) -> str:
    """Where the vendored tree actually came from.

    Recorded rather than hard-coded, because "OpenHack" alone does not say
    *which* OpenHack: the methodology originates at
    ``hadriansecurity/openhack`` and is vendored here through a fork. A commit
    id is only a provenance if you also know the repository it belongs to, and
    a reader chasing a vendored line needs to land in the right one.
    """
    try:
        return subprocess.check_output(
            ["git", "-C", str(source), "remote", "get-url", "origin"], text=True
        ).strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


def _uncommitted(source: Path) -> list[str]:
    """Paths modified in the source tree but not committed.

    This script copies the **working tree** while recording ``git HEAD`` as the
    provenance, so a dirty checkout produces a manifest naming a commit that
    does not contain what was actually vendored. The drift guard still passes —
    it compares the vendored files against the hashes recorded here — so nothing
    fails, and the mirror quietly stops being reproducible from the commit it
    claims. R22 is about exactly that kind of silent divergence, so it is
    reported rather than assumed away.
    """
    try:
        out = subprocess.check_output(
            ["git", "-C", str(source), "status", "--porcelain"], text=True
        )
    except (subprocess.CalledProcessError, OSError):
        return []
    return [line[3:].strip() for line in out.splitlines() if line.strip()]


def _force_remove(func: object, path: str, exc: BaseException) -> None:
    """Clear a read-only attribute and retry.

    Windows refuses to unlink a read-only file, and a tree copied with
    ``copy2`` inherits whatever attributes the source carried — so a refresh
    fails on exactly the files a previous refresh created.
    """
    import os
    import stat

    target = Path(path)
    if target.exists():
        os.chmod(path, stat.S_IWRITE)
        if target.is_dir():
            os.rmdir(path)
        else:
            os.unlink(path)
        return
    raise exc


def vendor(source: Path) -> int:
    if not (source / "src" / "openhack").is_dir():
        raise SystemExit(f"not an OpenHack checkout: {source}")

    if VENDOR.exists():
        shutil.rmtree(VENDOR, onexc=_force_remove)  # type: ignore[call-arg]
    VENDOR.mkdir(parents=True)

    copied: list[Path] = []
    for tree in TREES:
        src = source / tree
        if not src.is_dir():
            raise SystemExit(f"missing from source checkout: {tree}")
        dest = VENDOR / tree
        dest.mkdir(parents=True, exist_ok=True)
        for item in sorted(src.rglob("*")):
            if not item.is_file() or not _keep(item.relative_to(src)):
                continue
            target = dest / item.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            copied.append(target)

    for name in FILES:
        item = source / name
        if item.is_file():
            shutil.copy2(item, VENDOR / name)
            copied.append(VENDOR / name)

    dirty = _uncommitted(source)
    manifest = {
        "source_repo": "OpenHack",
        "source_url": _source_url(source),
        #: The methodology's origin, for a reader tracing a vendored line back
        #: past whatever fork it was mirrored through.
        "upstream_origin": "https://github.com/hadriansecurity/openhack",
        "source_commit": _source_commit(source),
        # Recorded, so the mirror never claims a provenance it does not have.
        # A reader re-vendoring from `source_commit` alone would otherwise get
        # different bytes and no indication why.
        "source_dirty": sorted(dirty),
        "vendored_at": datetime.now(UTC).isoformat(),
        "trees": list(TREES),
        "files": {
            str(path.relative_to(VENDOR)).replace("\\", "/"): _digest(path)
            for path in sorted(copied)
        },
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return len(copied)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    count = vendor(Path(sys.argv[1]).resolve())
    manifest = json.loads(MANIFEST.read_text())
    print(f"vendored {count} file(s) from {manifest['source_commit'][:12]}")
    print(f"  -> {VENDOR.relative_to(ROOT)}")
    dirty = manifest.get("source_dirty") or []
    if dirty:
        print(
            f"warning: the source tree had {len(dirty)} uncommitted change(s), so "
            f"this mirror is NOT reproducible from {manifest['source_commit'][:12]}. "
            "Commit them upstream and re-vendor before relying on the pin:",
            file=sys.stderr,
        )
        for path in dirty[:10]:
            print(f"  {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
