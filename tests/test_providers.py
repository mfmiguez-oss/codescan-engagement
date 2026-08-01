"""Provider selection and request shapes — asserted without calling anything."""

from __future__ import annotations

import subprocess
import sys

import pytest

from engagement.providers import (
    BedrockProvider,
    FoundryProvider,
    ModelRequest,
    ProviderError,
    build_provider,
    unwrap_json,
)

FOUNDRY_ENV = {"FOUNDRY_RESOURCE": "res", "FOUNDRY_API_KEY": "k"}
BEDROCK_ENV = {"BEDROCK_REGION": "us-east-1"}


def _request(deployment: str = "gpt-5-mini") -> ModelRequest:
    return ModelRequest(deployment=deployment, system="s", user="u")


def test_offline_path_never_imports_a_provider_client_library() -> None:
    code = (
        "import sys; import engagement.providers, engagement.driver, engagement.cli; "
        "leaked=[m for m in ('httpx','boto3') if m in sys.modules]; "
        "print(leaked); raise SystemExit(1 if leaked else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True)
    assert result.returncode == 0, f"importing engagement pulled in {result.stdout!r}"


def test_a_single_configured_provider_is_selected_without_being_named() -> None:
    assert build_provider(FOUNDRY_ENV).name == "foundry"
    assert build_provider(BEDROCK_ENV).name == "bedrock"


def test_two_configured_providers_refuse_rather_than_pick_a_bill() -> None:
    with pytest.raises(ProviderError) as excinfo:
        build_provider({**FOUNDRY_ENV, **BEDROCK_ENV})
    message = str(excinfo.value)
    assert "ENGAGEMENT_PROVIDER" in message
    assert "foundry" in message and "bedrock" in message
    # naming one resolves it rather than leaving the operator stuck
    chosen = build_provider({**FOUNDRY_ENV, **BEDROCK_ENV, "ENGAGEMENT_PROVIDER": "bedrock"})
    assert chosen.name == "bedrock"


def test_no_configured_provider_is_refused_not_defaulted() -> None:
    with pytest.raises(ProviderError, match="no model provider"):
        build_provider({})


def test_unknown_provider_names_the_valid_ones() -> None:
    with pytest.raises(ProviderError, match="unknown provider"):
        build_provider({"ENGAGEMENT_PROVIDER": "openai", **BEDROCK_ENV})


def test_foundry_key_travels_in_a_header_never_the_url() -> None:
    shape = FoundryProvider(resource="res", api_key="sekret").build_request(_request())
    assert shape["headers"]["api-key"] == "sekret"
    assert "sekret" not in shape["url"]


def test_foundry_claude_family_uses_the_anthropic_native_surface() -> None:
    shape = FoundryProvider(resource="res", api_key="k").build_request(
        _request("claude-opus-5")
    )
    assert shape["url"].endswith("/anthropic/v1/messages")
    assert shape["body"]["system"] == "s"


def test_foundry_gpt5_family_uses_max_completion_tokens() -> None:
    shape = FoundryProvider(resource="res", api_key="k").build_request(_request("gpt-5-mini"))
    assert "max_completion_tokens" in shape["body"]
    assert "max_tokens" not in shape["body"]


def test_bedrock_applies_the_inference_profile_prefix_at_most_once() -> None:
    provider = BedrockProvider(region="us-east-1", inference_geo="us")
    assert provider.resolve_model_id("anthropic.claude-opus-5") == "us.anthropic.claude-opus-5"
    assert provider.resolve_model_id("eu.anthropic.claude-opus-5") == "eu.anthropic.claude-opus-5"


def test_bedrock_family_without_a_system_channel_keeps_the_directive_refusal() -> None:
    """Dropping the system prompt would drop the instruction forbidding the
    model to follow directives found in the material under review."""
    shape = BedrockProvider(region="us-east-1").build_request(
        _request("amazon.titan-text-premier-v1:0")
    )
    assert "system" not in shape
    assert shape["messages"][0]["content"][0]["text"] == "s\n\nu"


def test_bedrock_request_carries_no_credential_material() -> None:
    """SigV4 signs at dispatch, so there is no key for a built request to leak."""
    shape = BedrockProvider(region="us-east-1").build_request(_request("anthropic.claude-opus-5"))
    assert set(shape) <= {"modelId", "system", "messages", "inferenceConfig"}


def test_a_fenced_json_answer_is_still_parsed() -> None:
    assert unwrap_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert unwrap_json('{"a": 1}') == {"a": 1}
