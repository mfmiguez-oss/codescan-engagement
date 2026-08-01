"""Configuration precedence, and refusing a bound that would not apply."""

from __future__ import annotations

import pytest

from engagement.budget import Budget
from engagement.cli import _bound

NAME = "ENGAGEMENT_MAX_CALLS"
DEFAULT = Budget().max_calls


def test_nothing_set_uses_the_bounded_default() -> None:
    assert _bound(None, {}, NAME, DEFAULT) == DEFAULT


def test_the_environment_configures_the_ceiling() -> None:
    """The template sets this. It read as configured and applied the default
    for as long as nothing read it."""
    assert _bound(None, {NAME: "25"}, NAME, DEFAULT) == 25


def test_a_flag_overrides_the_environment() -> None:
    assert _bound(9, {NAME: "25"}, NAME, DEFAULT) == 9


def test_a_malformed_value_is_refused_not_ignored() -> None:
    """Falling back to the built-in would mean an operator who set a budget
    silently got a different one — the same failure as a bound that does not
    apply, only harder to notice because the configuration looks set."""
    with pytest.raises(ValueError, match="not an integer"):
        _bound(None, {NAME: "lots"}, NAME, DEFAULT)


def test_a_ceiling_below_one_is_refused() -> None:
    """A zero ceiling is a run that cannot dispatch, which is a configuration
    mistake rather than a very small budget."""
    with pytest.raises(ValueError, match="at least 1"):
        _bound(None, {NAME: "0"}, NAME, DEFAULT)


def test_an_empty_value_falls_back_rather_than_failing() -> None:
    """An unset variable often arrives as an empty string from a template."""
    assert _bound(None, {NAME: "  "}, NAME, DEFAULT) == DEFAULT


def test_a_dotenv_supplies_configuration_when_the_environment_does_not(tmp_path):
    from engagement.cli import load_dotenv

    path = tmp_path / ".env"
    path.write_text('# comment\nFOUNDRY_RESOURCE="acme"\nMAX=5\n\nbroken line\n', encoding="utf-8")
    merged = load_dotenv(path, {})

    assert merged["FOUNDRY_RESOURCE"] == "acme"
    assert merged["MAX"] == "5"
    assert "broken line" not in merged


def test_a_real_environment_variable_always_beats_the_file(tmp_path):
    """An operator who exported a value meant it. A file that silently
    overrode it would make a run's actual configuration unknowable."""
    from engagement.cli import load_dotenv

    path = tmp_path / ".env"
    path.write_text("FOUNDRY_RESOURCE=from-file\n", encoding="utf-8")

    assert load_dotenv(path, {"FOUNDRY_RESOURCE": "from-env"})["FOUNDRY_RESOURCE"] == "from-env"


def test_a_missing_dotenv_is_not_an_error(tmp_path):
    from engagement.cli import load_dotenv

    assert load_dotenv(tmp_path / "absent", {"A": "1"}) == {"A": "1"}
