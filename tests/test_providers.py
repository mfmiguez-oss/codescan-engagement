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


class _FakeStream:
    """The only part of an httpx streaming response this code path touches."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self.status_code = 200

    def iter_lines(self) -> object:
        return iter(self._lines)

    def read(self) -> bytes:  # pragma: no cover - only the error path calls it
        return b""

    def raise_for_status(self) -> None:
        return None

    def __enter__(self) -> _FakeStream:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def test_dispatch_streams_so_a_long_answer_is_not_mistaken_for_a_hang() -> None:
    """Two live BenchmarkPython runs died on a whole-response deadline while the
    model was working normally. Streamed, the timeout measures silence instead."""
    body = FoundryProvider(resource="res", api_key="k").build_request(
        _request("claude-haiku-4-5")
    )["body"]
    assert body["stream"] is True

    chat = FoundryProvider(resource="res", api_key="k").build_request(
        _request("gpt-5-mini")
    )["body"]
    assert chat["stream"] is True
    # Without this a streamed chat answer reports no usage at all, and a run
    # that spent money would meter as free.
    assert chat["stream_options"] == {"include_usage": True}


def test_an_anthropic_stream_rebuilds_both_the_text_and_the_usage() -> None:
    """Usage arrives split across the stream: input and cache counts up front,
    the output count at the end. Metering has to survive that."""
    from engagement.providers import _accumulate_stream, _stream_events

    text, usage = _accumulate_stream(_stream_events(_FakeStream([
        "event: message_start",
        'data: {"type":"message_start","message":{"usage":'
        '{"input_tokens":11,"cache_read_input_tokens":222,'
        '"cache_creation_input_tokens":0}}}',
        "",
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"{\\"a\\":"}}',
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" 1}"}}',
        'data: {"type":"message_delta","usage":{"output_tokens":7}}',
        "data: [DONE]",
    ])))

    assert text == '{"a": 1}'
    assert usage["input_tokens"] == 11
    assert usage["output_tokens"] == 7
    assert usage["cache_read_input_tokens"] == 222


def test_a_chat_completions_stream_rebuilds_both_the_text_and_the_usage() -> None:
    from engagement.providers import _accumulate_stream, _stream_events

    text, usage = _accumulate_stream(_stream_events(_FakeStream([
        'data: {"choices":[{"delta":{"content":"he"}}]}',
        'data: {"choices":[{"delta":{"content":"llo"}}]}',
        'data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}',
        "data: [DONE]",
    ])))

    assert text == "hello"
    assert usage["prompt_tokens"] == 3
    assert usage["completion_tokens"] == 2


def test_one_unreadable_stream_line_does_not_discard_the_whole_answer() -> None:
    """The answer is already paid for by the time it is being parsed. Losing a
    delta degrades it; raising throws away everything that did arrive."""
    from engagement.providers import _accumulate_stream, _stream_events

    text, _ = _accumulate_stream(_stream_events(_FakeStream([
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"ok"}}',
        "data: {this is not json",
        ": a comment line",
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"!"}}',
    ])))

    assert text == "ok!"


def test_a_stalled_stream_says_what_it_cost_and_that_it_is_not_a_long_answer() -> None:
    """A timeout is the one failure that spends money invisibly: the ledger and
    audit trail are written from the completed response, so a call that dies mid
    stream is billed by the vendor and recorded nowhere here. It surfaced once as
    120 lines of transport traceback, naming neither the cost nor the cause."""
    import httpx

    from engagement.providers import READ_TIMEOUT_SECONDS, ProviderTimeout

    def _stall(*args: object, **kwargs: object) -> object:
        raise httpx.ReadTimeout("the read operation timed out")

    provider = FoundryProvider(resource="res", api_key="k")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(httpx, "stream", _stall)
        with pytest.raises(ProviderTimeout) as stalled:
            provider.complete(
                ModelRequest(deployment="claude-haiku-4-5", system="s", user="u")
            )

    message = str(stalled.value)
    assert f"{READ_TIMEOUT_SECONDS:.0f}s" in message
    assert "stalled connection rather than a long generation" in message
    assert "NOT in this run's ledger" in message


def test_a_streamed_dispatch_meters_what_the_stream_reported() -> None:
    """End to end through complete(): the ledger's numbers come from the stream,
    not from a response body that no longer exists."""
    import httpx

    lines = [
        'data: {"type":"message_start","message":{"usage":'
        '{"input_tokens":9,"cache_read_input_tokens":100}}}',
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"{}"}}',
        'data: {"type":"message_delta","usage":{"output_tokens":4}}',
    ]
    provider = FoundryProvider(resource="res", api_key="k")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(httpx, "stream", lambda *a, **k: _FakeStream(lines))
        response = provider.complete(
            ModelRequest(deployment="claude-haiku-4-5", system="s", user="u")
        )

    assert response.content == "{}"
    assert response.input_tokens == 9
    assert response.output_tokens == 4
    assert response.cache_read_tokens == 100
