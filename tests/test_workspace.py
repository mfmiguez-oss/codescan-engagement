"""The adapter's contract with the recorder it drives."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

import pytest

from engagement.contracts import RunRef
from engagement.workspace import CliWorkspace, _complaint, _rendered


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


def test_a_refusal_leads_with_the_reason_not_the_traceback() -> None:
    """Callers abbreviate this for a parked reason, and abbreviating keeps the
    front — so a message that opens with stack frames throws away exactly the
    half worth reading. A live run parked two scenarios with a reason naming
    `cli.py, line 327, in main` and nothing about why."""
    traceback = (
        "Traceback (most recent call last):\n"
        '  File "C:\\repo\\src\\openhack\\cli.py", line 327, in main\n'
        "    args.func(args)\n"
        '  File "C:\\repo\\src\\openhack\\results.py", line 480, in _record\n'
        "    validate_result(result, scenario_id)\n"
        "ValueError: result S001 does not match scenario-result-schema.json:\n"
        "- $.same_root_expansion: 'prose' is not of type 'array'"
    )

    complaint = _complaint(traceback)

    assert complaint.startswith("ValueError: result S001 does not match")
    # the per-field detail is the actionable part and must survive
    assert "$.same_root_expansion" in complaint
    # and the first 200 characters — all a parked reason keeps — are now useful
    assert "cli.py" not in complaint[:200]


def test_a_refusal_with_no_exception_line_still_reports_something() -> None:
    """Not every non-zero exit is a Python traceback. Whatever the process last
    said is still closer to why it stopped than its opening words."""
    assert _complaint("usage: openhack ...\nerror: unrecognized arguments").endswith(
        "error: unrecognized arguments"
    )


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


def test_a_caller_search_is_literal_never_a_compiled_pattern(tmp_path: Path) -> None:
    """The term comes from model output. Compiling it would hand untrusted text
    control over the search — `.*` would match every file, and a pathological
    pattern would hang the run."""
    src = tmp_path / "runs" / "acme" / "run-001" / "sourcecode"
    src.mkdir(parents=True)
    (src / "routes.py").write_text("from db import get_connection\n", encoding="utf-8")
    (src / "unrelated.py").write_text("x = 1\n", encoding="utf-8")
    ref = RunRef(target="acme", run_id="run-001")
    workspace = CliWorkspace(root=tmp_path)

    assert workspace.search_source(ref, ["get_connection"]) == ["routes.py"]
    # a regex metacharacter matches nothing, because nothing contains it
    assert workspace.search_source(ref, [".*"]) == []


def test_a_caller_search_prefers_files_nearer_the_root(tmp_path: Path) -> None:
    """A cheap proxy for relevance: an application's routes sit nearer the root
    than its vendored dependencies.

    Built so the ordering has to *bind*. The earlier version of this test had
    two matches against a default limit of five, with the shallow file already
    first in the walk's alphabetical order — so it passed with the depth sort
    deleted, and passed while the search truncated before sorting and returned
    nothing but vendored copies. Here there are more matches than slots and the
    root file sorts last, which is the only arrangement that tells a search
    ordered by depth from one ordered by name.
    """
    src = tmp_path / "runs" / "acme" / "run-001" / "sourcecode"
    (src / "admin" / "vendor").mkdir(parents=True)
    (src / "api" / "vendor").mkdir(parents=True)
    (src / "assets").mkdir(parents=True)
    (src / "zroutes.py").write_text("token()\n", encoding="utf-8")
    (src / "assets" / "c.py").write_text("token()\n", encoding="utf-8")
    (src / "admin" / "vendor" / "a.py").write_text("token()\n", encoding="utf-8")
    (src / "api" / "vendor" / "b.py").write_text("token()\n", encoding="utf-8")
    ref = RunRef(target="acme", run_id="run-001")

    assert CliWorkspace(root=tmp_path).search_source(ref, ["token"], limit=2) == [
        "zroutes.py",
        "assets/c.py",
    ]


def test_a_caller_search_refuses_a_symlink_out_of_the_checkout(tmp_path: Path) -> None:
    """The checkout is a clone of the repository under review, so a link
    committed into it points wherever its author chose. `read_source` resolves
    and contains for exactly this reason; a search that walked past the check
    would read the host's own files and hand them to the model provider."""
    src = tmp_path / "runs" / "acme" / "run-001" / "sourcecode"
    src.mkdir(parents=True)
    outside = tmp_path / "host-secret.py"
    outside.write_text("aws_secret_access_key = 'token'\n", encoding="utf-8")
    try:
        (src / "settings.py").symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform-gated
        pytest.skip("creating symlinks needs a privilege this platform withholds")
    ref = RunRef(target="acme", run_id="run-001")

    assert CliWorkspace(root=tmp_path).search_source(ref, ["token"]) == []


def _checkout(tmp_path: Path, *paths: str) -> RunRef:
    src = tmp_path / "runs" / "acme" / "run-001" / "sourcecode"
    for path in paths:
        target = src / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x = 1\n", encoding="utf-8")
    src.mkdir(parents=True, exist_ok=True)
    return RunRef(target="acme", run_id="run-001")


def test_a_named_file_resolves_from_the_name_the_source_uses(tmp_path: Path) -> None:
    """A reviewer names ``views.py``, not its path from a checkout root it has
    never been shown. Resolving that literally reported the file absent while it
    sat two directories down, and parked the scenario for a gap that was not
    real: a live pygoat run lost 34 that way."""
    ref = _checkout(tmp_path, "introduction/views.py", "challenge/views.py")

    assert CliWorkspace(root=tmp_path).resolve_source(ref, ["views.py"]) == {
        "views.py": ["challenge/views.py", "introduction/views.py"]
    }


def test_a_partial_path_resolves_the_same_way_as_a_bare_name(tmp_path: Path) -> None:
    """``A9/api.py`` is the same request as ``api.py`` with more of the path
    given, so it is one suffix rule rather than a basename special case."""
    ref = _checkout(tmp_path, "introduction/playground/A9/api.py")

    assert CliWorkspace(root=tmp_path).resolve_source(ref, ["A9/api.py"]) == {
        "A9/api.py": ["introduction/playground/A9/api.py"]
    }


def test_resolution_matches_only_whole_path_components(tmp_path: Path) -> None:
    """A bare suffix comparison would answer ``api.py`` with ``legacy_api.py``
    and hand the reviewer a file it never asked about, which it would then cite
    as though it had."""
    ref = _checkout(tmp_path, "app/legacy_api.py", "app/api.py")

    assert CliWorkspace(root=tmp_path).resolve_source(ref, ["api.py"]) == {
        "api.py": ["app/api.py"]
    }


def test_resolution_answers_ambiguity_with_every_match_not_a_guess(
    tmp_path: Path,
) -> None:
    """Three files named ``views.py`` are three candidates the reviewer can cite
    from. Picking one for it would invent the answer to its own question — and
    the bound on how many is real, so it truncates shallowest-first."""
    ref = _checkout(
        tmp_path, "a/views.py", "b/views.py", "deep/nested/views.py", "views.py"
    )

    resolved = CliWorkspace(root=tmp_path).resolve_source(ref, ["views.py"], limit=3)

    assert resolved == {"views.py": ["views.py", "a/views.py", "b/views.py"]}


def test_what_is_not_a_path_resolves_to_nothing(tmp_path: Path) -> None:
    """The path extractor also offers up ``request.POST`` and
    ``django.contrib.auth.logout``. A fallback that guessed at those would
    supply files nobody asked for; these stay honestly unresolved."""
    ref = _checkout(tmp_path, "app/views.py")
    workspace = CliWorkspace(root=tmp_path)

    assert workspace.resolve_source(ref, ["request.POST", "requests.get"]) == {}
    # and the jail still holds: no traversal resolves, however it is spelled
    assert workspace.resolve_source(ref, ["../../host/views.py"]) == {}


def test_resolution_refuses_a_symlink_out_of_the_checkout(tmp_path: Path) -> None:
    """Same jail as `read_source` and `search_source`, for the same reason: a
    link committed into the checkout points wherever its author chose."""
    ref = _checkout(tmp_path, "app/keep.py")
    src = tmp_path / "runs" / "acme" / "run-001" / "sourcecode"
    outside = tmp_path / "host-secret.py"
    outside.write_text("aws_secret_access_key = 'token'\n", encoding="utf-8")
    try:
        (src / "settings.py").symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform-gated
        pytest.skip("creating symlinks needs a privilege this platform withholds")

    assert CliWorkspace(root=tmp_path).resolve_source(ref, ["settings.py"]) == {}


def test_every_path_is_resolved_in_one_walk(tmp_path: Path) -> None:
    """The caller holds a lock across this call, so a walk per path is a full
    re-read of the checkout no other worker can interleave with."""
    ref = _checkout(tmp_path, "a/views.py", "b/urls.py", "c/models.py")
    walks: list[str] = []
    workspace = CliWorkspace(root=tmp_path)
    real = Path.rglob

    def counting(self: Path, pattern: str) -> Iterator[Path]:
        walks.append(pattern)
        return real(self, pattern)

    with patch.object(Path, "rglob", counting):
        resolved = workspace.resolve_source(ref, ["views.py", "urls.py", "models.py"])

    assert set(resolved) == {"views.py", "urls.py", "models.py"}
    assert len(walks) == 1


def test_every_term_is_matched_in_one_walk(tmp_path: Path) -> None:
    """Per-term walks re-read the whole checkout once each, under a lock no
    other worker can take. Four functions asked about is one scan, not four."""
    src = tmp_path / "runs" / "acme" / "run-001" / "sourcecode"
    src.mkdir(parents=True)
    (src / "a.py").write_text("get_connection()\n", encoding="utf-8")
    (src / "b.py").write_text("render_template()\n", encoding="utf-8")
    (src / "c.py").write_text("unrelated()\n", encoding="utf-8")
    ref = RunRef(target="acme", run_id="run-001")

    assert CliWorkspace(root=tmp_path).search_source(
        ref, ["get_connection", "render_template"]
    ) == ["a.py", "b.py"]
