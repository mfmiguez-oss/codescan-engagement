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
