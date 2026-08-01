"""Where secrets come from.

The load-bearing test is
``test_a_configured_vault_never_falls_back_to_the_environment``. A deployment
that believes it reads from a vault and is actually reading a stale `.env` has
the ceremony of a secret store and none of the rotation — and nothing about it
looks wrong.
"""

from __future__ import annotations

import pytest

from engagement.egress import build_policy
from engagement.secrets import (
    SecretError,
    SecretRef,
    SecretResolver,
    build_plan,
    resolve_optional,
)

_VAULT = {"ENGAGEMENT_KEY_VAULT": "acme-kv", "FOUNDRY_RESOURCE": "acme", "FOUNDRY_API_KEY": "k"}


def test_without_a_vault_the_environment_is_used_unchanged() -> None:
    """Local development must not need a vault."""
    resolver = SecretResolver({"FOUNDRY_API_KEY": "from-env"})

    assert resolver.resolve(SecretRef(env_var="FOUNDRY_API_KEY")) == "from-env"


def test_a_configured_vault_is_read_instead_of_the_environment() -> None:
    resolver = SecretResolver(
        {"FOUNDRY_API_KEY": "stale-env-value"}, fetch=lambda ref: "from-vault"
    )
    ref = SecretRef(env_var="FOUNDRY_API_KEY", vault="acme-kv")

    assert resolver.resolve(ref) == "from-vault"


def test_a_configured_vault_never_falls_back_to_the_environment() -> None:
    """A silent fallback would mean rotating the vault changes nothing."""

    def explode(ref: SecretRef) -> str:
        raise RuntimeError("managed identity unavailable")

    resolver = SecretResolver({"FOUNDRY_API_KEY": "stale-env-value"}, fetch=explode)

    with pytest.raises(RuntimeError, match="managed identity unavailable"):
        resolver.resolve(SecretRef(env_var="FOUNDRY_API_KEY", vault="acme-kv"))


def test_an_optional_secret_missing_from_the_environment_is_not_an_error() -> None:
    """A run with no Snyk token is a normal run."""
    resolver = SecretResolver({})

    assert resolve_optional(resolver, SecretRef(env_var="SNYK_TOKEN")) == ""


def test_an_optional_secret_still_raises_when_a_vault_is_broken() -> None:
    """Absent is fine; a configured-and-failing vault is a broken deployment."""

    def explode(ref: SecretRef) -> str:
        raise SecretError("vault unreachable")

    resolver = SecretResolver({}, fetch=explode)

    with pytest.raises(SecretError):
        resolve_optional(resolver, SecretRef(env_var="SNYK_TOKEN", vault="acme-kv"))


def test_the_secret_is_fetched_once_per_run() -> None:
    """A vault call per dispatch is a rate limit waiting to happen."""
    calls: list[str] = []

    def counting(ref: SecretRef) -> str:
        calls.append(ref.name_in_vault)
        return "v"

    resolver = SecretResolver({}, fetch=counting)
    ref = SecretRef(env_var="FOUNDRY_API_KEY", vault="acme-kv")
    for _ in range(5):
        resolver.resolve(ref)

    assert calls == ["foundry-api-key"]


def test_the_default_secret_name_follows_the_key_vault_naming_rule() -> None:
    """So the common case needs no extra configuration."""
    assert SecretRef(env_var="FOUNDRY_API_KEY", vault="v").name_in_vault == "foundry-api-key"
    assert SecretRef(env_var="SNYK_TOKEN", vault="v").name_in_vault == "snyk-token"


def test_an_explicit_secret_name_overrides_the_default() -> None:
    ref = SecretRef(env_var="FOUNDRY_API_KEY", vault="v", secret_name="prod-foundry")

    assert ref.name_in_vault == "prod-foundry"


def test_a_failure_names_the_coordinates_and_never_the_value() -> None:
    def explode(ref: SecretRef) -> str:
        raise SecretError("could not read 'foundry-api-key' from vault 'acme-kv'")

    resolver = SecretResolver({}, fetch=explode)
    with pytest.raises(SecretError) as caught:
        resolver.resolve(SecretRef(env_var="FOUNDRY_API_KEY", vault="acme-kv"))

    assert "acme-kv" in str(caught.value)
    assert "foundry-api-key" in str(caught.value)


def test_the_vault_host_is_on_the_egress_allowlist() -> None:
    """The fetch happens before any model call and would otherwise be refused
    by the very control this package added."""
    plan = build_plan(_VAULT)
    allowed = build_policy(_VAULT).allowed

    assert plan.vault_hosts == ["acme-kv.vault.azure.net"]
    for host in plan.vault_hosts:
        assert host in allowed
    assert "login.microsoftonline.com" in allowed, "managed identity needs the token endpoint"


def test_no_vault_configured_adds_no_vault_host() -> None:
    assert build_plan({}).vault_hosts == []
    assert not any("vault.azure.net" in h for h in build_policy({}).allowed)


def test_the_plan_describes_the_source_without_reading_anything() -> None:
    described = build_plan(_VAULT).describe()

    assert any("vault acme-kv/foundry-api-key" in line for line in described)
    assert not any("k" == line for line in described), "no value may appear"


def test_the_plan_falls_back_to_the_environment_when_no_vault_is_set() -> None:
    described = build_plan({"FOUNDRY_API_KEY": "k"}).describe()

    assert any("FOUNDRY_API_KEY <- environment" in line for line in described)
