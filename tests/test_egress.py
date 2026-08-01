"""The network boundary: where this process may send bytes.

An agent that reads attacker-controlled source and then makes network calls has
an exfiltration path. Prompt injection does not need the *model* to leak
anything — it only needs some later stage to fetch a URL. The defence is a hard
boundary, not an instruction.

The load-bearing test is
``test_nothing_observed_can_widen_the_allowlist``: the allowlist is derived from
operator configuration only, so a host named in a repository, a finding, or a
model's answer is unreachable by construction rather than by policy.
"""

from __future__ import annotations

import pytest

from engagement.egress import (
    CONSTANT_HOSTS,
    EgressBlocked,
    EgressPolicy,
    build_policy,
    host_of,
)

_FOUNDRY = {"FOUNDRY_RESOURCE": "acme-eastus2", "FOUNDRY_API_KEY": "k"}


def test_the_configured_model_endpoint_is_reachable() -> None:
    policy = build_policy(_FOUNDRY)

    assert policy.permits("https://acme-eastus2.services.ai.azure.com/openai/v1/chat")


def test_an_unconfigured_host_is_refused() -> None:
    policy = build_policy(_FOUNDRY)

    with pytest.raises(EgressBlocked, match="not an allowed destination"):
        policy.check("https://evil.example.com/collect", purpose="model dispatch")


def test_nothing_observed_can_widen_the_allowlist() -> None:
    """The whole point: a host that appears in the source under review, in a
    finding, or in a model's answer is unreachable — there is no code path from
    observed text to the allowlist."""
    policy = build_policy(_FOUNDRY)
    for injected in (
        "https://attacker.test/exfil",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://acme-eastus2.services.ai.azure.com.attacker.test/",  # suffix trick
    ):
        with pytest.raises(EgressBlocked):
            policy.check(injected)

    assert sorted(policy.denied) == sorted(
        [host_of(u) for u in (
            "https://attacker.test/exfil",
            "http://169.254.169.254/latest/meta-data/",
            "https://acme-eastus2.services.ai.azure.com.attacker.test/",
        )]
    )


def test_a_lookalike_host_does_not_match_by_prefix() -> None:
    policy = build_policy(_FOUNDRY)

    assert not policy.permits("https://acme-eastus2.services.ai.azure.com.evil.test/x")
    assert not policy.permits("https://evil.test/acme-eastus2.services.ai.azure.com")


def test_the_cisa_catalogue_host_is_allowed_by_default() -> None:
    assert "www.cisa.gov" in CONSTANT_HOSTS
    assert build_policy({}).permits(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )


def test_bedrock_gets_its_region_endpoint() -> None:
    policy = build_policy({"BEDROCK_REGION": "us-east-1"})

    assert policy.permits("https://bedrock-runtime.us-east-1.amazonaws.com/")
    assert not policy.permits("https://bedrock-runtime.eu-west-1.amazonaws.com/")


def test_a_deployment_with_no_provider_can_reach_almost_nothing() -> None:
    policy = build_policy({})

    assert policy.allowed == set(CONSTANT_HOSTS) | {"api.snyk.io"}


def test_an_operator_can_add_a_proxy_deliberately() -> None:
    policy = build_policy({**_FOUNDRY, "ENGAGEMENT_EGRESS_EXTRA": "proxy.corp,mirror.corp"})

    assert policy.permits("https://proxy.corp/v1")
    assert policy.permits("https://mirror.corp/v1")


def test_an_unparseable_url_fails_closed() -> None:
    policy = build_policy(_FOUNDRY)

    assert not policy.permits("::::")
    with pytest.raises(EgressBlocked):
        policy.check("::::")


def test_enforcement_can_be_disabled_for_adoption_but_still_records() -> None:
    """Adopting the control on a live deployment must not break it — but a
    permitted denial is still a denial and must show up."""
    policy = build_policy({**_FOUNDRY, "ENGAGEMENT_EGRESS_ENFORCE": "0"})
    policy.check("https://evil.example.com/collect")

    assert policy.denied == ["evil.example.com"]
    assert not policy.enforce


def test_the_provider_refuses_before_the_request_is_sent() -> None:
    """Blocked means no connection attempt, not a failed one — not even a
    handshake that would confirm the host is reachable from here."""
    from engagement.providers import FoundryProvider, ModelRequest

    policy = EgressPolicy(allowed={"only-this.example.com"})
    provider = FoundryProvider(resource="acme-eastus2", api_key="k", egress=policy)

    with pytest.raises(EgressBlocked):
        provider.complete(ModelRequest(deployment="claude-haiku-4-5", system="s", user="u"))


def test_host_extraction_is_case_insensitive() -> None:
    assert host_of("https://ACME-EastUS2.Services.AI.Azure.COM/x") == (
        "acme-eastus2.services.ai.azure.com"
    )
