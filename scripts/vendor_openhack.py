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

    manifest = {
        "source_repo": "OpenHack",
        "source_commit": _source_commit(source),
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
