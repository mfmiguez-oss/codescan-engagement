"""The adapter's contract with the recorder it drives."""

from __future__ import annotations

import sys
from hashlib import sha256
from pathlib import Path

import pytest

from engagement.workspace import CliWorkspace, _rendered


def test_prompt_digest_hashes_bytes_not_decoded_text(tmp_path: Path) -> None:
    """The digest must match the file the recorder reads.

    Found by driving a real workspace on Windows: reading a prompt as text
    rewrites CRLF to LF, so re-encoding produced a different byte sequence and
    every answer was rejected for a prompt-hash mismatch the driver could not
    see. The workspace owns the artifact, so it owns the artifact's identity.
    """
    prompt = tmp_path / "S001.md"
    prompt.write_bytes(b"# scenario\r\nreview the material\r\n")

    rendered = _rendered(prompt)

    assert rendered.digest == sha256(prompt.read_bytes()).hexdigest()
    # the trap that produced the bug: ``read_text`` translates CRLF to LF, so
    # hashing what it returns hashes a byte sequence that is not on disk
    via_read_text = sha256(prompt.read_text().encode("utf-8")).hexdigest()
    assert rendered.digest != via_read_text
    # and the rendered text still carries the original line endings, so a
    # consumer re-encoding it would arrive back at the correct digest
    assert sha256(rendered.text.encode("utf-8")).hexdigest() == rendered.digest


def test_adapter_defaults_to_the_interpreter_running_it(tmp_path: Path) -> None:
    """A bare PATH lookup can resolve a *different* install of the workspace
    tooling than the environment this driver was installed into."""
    workspace = CliWorkspace(root=tmp_path)
    assert workspace._command[0] == sys.executable
    assert workspace._command[1:] == ["-m", "openhack"]


def test_the_cli_runs_in_utf8_mode_whatever_the_platform_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OpenHack writes prompt and result files with no explicit encoding, so it
    inherits the platform default — cp1252 on Windows, which cannot represent
    most of what a security review writes down. A live run completed the whole
    router phase and then died on a `≥` in a scenario."""
    import subprocess

    captured: dict[str, object] = {}

    def _capture(*args: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _capture)
    CliWorkspace(root=tmp_path)._run("state")

    env = captured["env"]
    assert isinstance(env, dict)
    assert env["PYTHONUTF8"] == "1"
    # And the pipes this end are read as UTF-8 too, so a character the child
    # can now write is not lost on the way back.
    assert captured["encoding"] == "utf-8"
