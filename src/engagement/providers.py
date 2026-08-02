"""Model providers behind one protocol.

Cloud neutrality is a property of this module and nowhere else: the driver, the
budget governor and the workspace adapter never learn which cloud they are on.
Adding a provider is a new class and a registry entry, not a change to the
workflow.

Each client library is imported lazily inside ``complete``, so the base package
installs without any of them and the offline path never touches the network.
Every provider exposes ``build_request`` as a pure function returning the exact
call that would be made, which is what lets the request *shape* — the part that
actually differs per cloud — be asserted offline in the gate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from .contracts import StrictModel
from .egress import EgressPolicy
from .models import sampling_for

PROVIDERS = ("foundry", "bedrock")


def merge_prefix(system: str, cache_prefix: str) -> str:
    """Fold a cache prefix back into a plain system prompt.

    For every surface that cannot mark a breakpoint. The prefix follows the
    system text in the same order the Anthropic surface sends its two blocks,
    so the model sees the same prompt either way and only the billing differs.
    """
    if not cache_prefix:
        return system
    return f"{system}\n\n{cache_prefix}" if system else cache_prefix


class ModelRequest(StrictModel):
    """One dispatch.

    ``temperature`` and ``seed`` are *requests*, not guarantees: whether either
    reaches the wire is decided per model family by
    :func:`engagement.models.sampling_for`. Recent Anthropic models removed
    sampling parameters and reject them with a 400, so a request that always
    sent ``temperature=0`` would fail outright on exactly the models an operator
    is most likely to route the hardest work to.
    """

    deployment: str
    system: str
    user: str
    #: Invariant text placed *ahead* of everything variable and marked as a
    #: cache breakpoint. Empty means dispatch normally. See
    #: :mod:`engagement.caching` for why only some content may go here.
    cache_prefix: str = ""
    max_output_tokens: int = 4096
    #: Zero by default: an unattended run should re-run to the same answer where
    #: the family allows it, because a queue that changes between identical runs
    #: cannot be reviewed or regression-tested.
    temperature: float = 0.0
    #: Reproducible sampling where the surface supports it (OpenAI-style only).
    seed: int | None = None


class ModelResponse(StrictModel):
    deployment: str
    content: str
    input_tokens: int = 0
    output_tokens: int = 0
    #: Tokens served from cache, billed at roughly a tenth of the input rate,
    #: and tokens written to it, billed at a premium. Reported separately from
    #: ``input_tokens`` because the provider reports them separately: folding
    #: them in would make a run that got cheaper look identical to one that did
    #: not, which is the whole reason the discount is invisible without this.
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@runtime_checkable
class ModelProvider(Protocol):
    name: str

    def complete(self, request: ModelRequest) -> ModelResponse: ...

    def list_deployments(self) -> list[str]:
        """Every deployment this provider will actually serve.

        Part of what a provider *is*, rather than an optional extra: a provider
        that cannot say what it serves is one no run can be checked against
        before it starts spending.

        An empty list means **"could not tell"**, never "serves nothing". The
        distinction is the whole contract — preflight refuses a run whose model
        is known to be absent and lets one proceed when the answer is unknown,
        and collapsing the two would either block runs on an unreachable list
        endpoint or wave through a deployment that does not exist.
        """
        ...


class ProviderError(RuntimeError):
    """Configuration that would produce a silently degraded run."""


# ---------------------------------------------------------------------------
# Microsoft Azure AI Foundry (default)
# ---------------------------------------------------------------------------


_ANTHROPIC_FAMILIES = ("claude",)
_COMPLETION_TOKENS_FAMILIES = ("gpt-5", "o3", "o4")
_RESPONSES_API_FAMILIES = ("codex",)


class FoundryProvider:
    """Azure AI Foundry. The default provider, and the one the estate runs on.

    Live-verified surface split: ``claude-*`` deployments answer only on the
    Anthropic-native surface, everything else on the OpenAI-compatible one.
    Per-family request quirks live here, in one place, and are asserted by
    shape rather than by calling anything.
    """

    name = "foundry"

    def __init__(
        self,
        resource: str,
        api_key: str,
        base_url: str | None = None,
        egress: EgressPolicy | None = None,
    ) -> None:
        self._resource = resource
        self._api_key = api_key
        self._egress = egress
        root = f"https://{resource}.services.ai.azure.com"
        self._openai_base = (base_url or f"{root}/openai/v1").rstrip("/")
        self._anthropic_base = f"{root}/anthropic/v1"

    @staticmethod
    def _matches(deployment: str, families: tuple[str, ...]) -> bool:
        lowered = deployment.lower()
        return any(family in lowered for family in families)

    def build_request(self, request: ModelRequest) -> dict[str, Any]:
        """The exact HTTP request that would be sent — pure, testable offline.

        Determinism parameters are added only where the family accepts them.
        The one-line rule lives in :mod:`engagement.models` so that a family
        gaining or losing sampling support is a single edit, not a change at
        every surface below.
        """
        sampling = sampling_for(request.deployment, request.temperature, request.seed)
        if self._matches(request.deployment, _ANTHROPIC_FAMILIES):
            # The cache breakpoint goes on the *last* system block, so the span
            # it covers is the instruction text plus the invariant prefix — in
            # that order, because caching is a prefix match and the shorter,
            # stabler block has to come first for the longer one to extend it.
            system: Any = request.system
            if request.cache_prefix:
                system = [
                    {"type": "text", "text": request.system},
                    {
                        "type": "text",
                        "text": request.cache_prefix,
                        "cache_control": {"type": "ephemeral"},
                    },
                ]
            body: dict[str, Any] = {
                "model": request.deployment,
                "max_tokens": request.max_output_tokens,
                "system": system,
                "messages": [{"role": "user", "content": request.user}],
            }
            # the Anthropic surface has no `seed`; temperature only, and only
            # on the generations that still accept it
            if "temperature" in sampling:
                body["temperature"] = sampling["temperature"]
            return {
                "url": f"{self._anthropic_base}/messages",
                # the key travels in a header, never the URL, so it cannot be
                # captured by proxy logs or access logs that record the path
                "headers": {
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                "body": body,
            }
        headers = {
            "api-key": self._api_key,
            "authorization": f"Bearer {self._api_key}",
            "content-type": "application/json",
        }
        # These surfaces have no cache_control. The prefix is still *content*,
        # so it is folded into the system prompt rather than dropped: a hoisted
        # expert manifest that silently vanished on a non-Anthropic deployment
        # would change what the model was asked, which is a correctness bug
        # wearing a cost optimisation's clothes.
        instructions = merge_prefix(request.system, request.cache_prefix)
        if self._matches(request.deployment, _RESPONSES_API_FAMILIES):
            return {
                "url": f"{self._openai_base}/responses",
                "headers": headers,
                "body": {
                    "model": request.deployment,
                    "instructions": instructions,
                    "input": request.user,
                    "max_output_tokens": request.max_output_tokens,
                    **sampling,
                },
            }
        chat: dict[str, Any] = {
            "model": request.deployment,
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": request.user},
            ],
            **sampling,
        }
        token_key = (
            "max_completion_tokens"
            if self._matches(request.deployment, _COMPLETION_TOKENS_FAMILIES)
            else "max_tokens"
        )
        chat[token_key] = request.max_output_tokens
        return {
            "url": f"{self._openai_base}/chat/completions",
            "headers": headers,
            "body": chat,
        }

    def deployments_url(self) -> str:
        """Where the resource lists what it serves. Pure, so it can be checked
        against the egress allowlist without a network call."""
        return f"{self._openai_base}/models"

    def list_deployments(self) -> list[str]:
        """Ask the resource which deployments exist.

        The OpenAI-compatible listing is used for both surfaces because it is
        resource-wide: a Claude deployment on Foundry appears here alongside
        the rest, and asking the Anthropic surface separately would produce two
        partial answers to one question.

        Returns an empty list on any failure. Not a silent swallow — the caller
        treats empty as *unknown* and says so — but a list endpoint that is
        unreachable is a reason to skip a check, never a reason to fail a run
        whose inference calls may work perfectly well.
        """
        import httpx  # lazy: optional extra

        url = self.deployments_url()
        if self._egress is not None:
            self._egress.check(url, purpose="deployment listing")
        try:
            response = httpx.get(
                url, headers={"api-key": self._api_key}, timeout=30.0
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:  # noqa: BLE001 - an advisory check never raises
            return []
        rows = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            return []
        return sorted(
            {
                str(row["id"])
                for row in rows
                if isinstance(row, dict) and row.get("id")
            }
        )

    def complete(self, request: ModelRequest) -> ModelResponse:
        import httpx  # lazy: optional extra

        shape = self.build_request(request)
        # The last point before bytes leave the process. Checked here rather
        # than at construction so a base_url changed at runtime cannot slip past.
        if self._egress is not None:
            self._egress.check(str(shape["url"]), purpose="model dispatch")
        response = httpx.post(
            shape["url"], headers=shape["headers"], json=shape["body"], timeout=300.0
        )
        response.raise_for_status()
        data = response.json()
        usage = data.get("usage", {})
        return ModelResponse(
            deployment=request.deployment,
            content=_foundry_content(data),
            input_tokens=int(usage.get("prompt_tokens", usage.get("input_tokens", 0))),
            output_tokens=int(usage.get("completion_tokens", usage.get("output_tokens", 0))),
            # Absent on every surface that does not cache, which is why these
            # default to zero rather than being required: a provider that says
            # nothing about caching did none, and that is a fact worth recording
            # as zero rather than as an error.
            cache_read_tokens=int(usage.get("cache_read_input_tokens", 0)),
            cache_write_tokens=int(usage.get("cache_creation_input_tokens", 0)),
        )


def _foundry_content(data: dict[str, Any]) -> str:
    """Text out of any Foundry surface: chat, Anthropic messages, or responses."""
    if "choices" in data:
        return str(data["choices"][0]["message"]["content"])
    if isinstance(data.get("content"), list):
        return "".join(
            str(block.get("text", ""))
            for block in data["content"]
            if isinstance(block, dict) and block.get("type") == "text"
        )
    if "output_text" in data:
        return str(data["output_text"])
    return ""


# ---------------------------------------------------------------------------
# Amazon Bedrock
# ---------------------------------------------------------------------------


#: Geo prefixes marking a cross-region inference profile. Several models are
#: only invocable through a profile, so the prefix is part of the identifier
#: rather than a routing hint — family matching runs against the stripped id.
INFERENCE_GEOS = ("us.", "eu.", "apac.")

#: Bedrock families with no system channel on Converse. Their system prompt is
#: folded into the user turn rather than dropped, because discarding it would
#: take the directive-refusing instruction with it.
_NO_SYSTEM_FAMILIES = ("amazon.titan", "cohere.command-text", "cohere.command-light")


class BedrockProvider:
    """Amazon Bedrock over the Converse API.

    Converse rather than the Anthropic-native surface because it reaches
    Anthropic, Meta, Mistral, Amazon and Cohere deployments through one request
    shape — the same reason the estate wants more than one model family
    available behind a single code path.

    No credential is held here: botocore resolves them from the standard AWS
    chain and signs with SigV4 at dispatch, so nothing ``build_request``
    returns carries key material.
    """

    name = "bedrock"

    def __init__(
        self,
        region: str,
        inference_geo: str | None = None,
        endpoint_url: str | None = None,
        egress: EgressPolicy | None = None,
    ) -> None:
        self._egress = egress
        self._region = region
        self._geo = (inference_geo or "").strip().strip(".").lower() or None
        self._endpoint_url = endpoint_url
        self._client: Any | None = None

    def resolve_model_id(self, deployment: str) -> str:
        model_id = deployment.strip()
        if self._geo and not model_id.startswith(INFERENCE_GEOS):
            return f"{self._geo}.{model_id}"
        return model_id

    @staticmethod
    def base_model_id(model_id: str) -> str:
        for geo in INFERENCE_GEOS:
            if model_id.startswith(geo):
                return model_id[len(geo) :]
        return model_id

    def build_request(self, request: ModelRequest) -> dict[str, Any]:
        """The exact Converse call that would be made — pure, testable offline."""
        model_id = self.resolve_model_id(request.deployment)
        family = self.base_model_id(model_id).lower()
        inference: dict[str, Any] = {"maxTokens": request.max_output_tokens}
        # Converse names it `temperature` too, but the same per-family rule
        # applies: the models that removed it reject it here as well.
        sampling = sampling_for(family, request.temperature, request.seed)
        if "temperature" in sampling:
            inference["temperature"] = sampling["temperature"]
        shape: dict[str, Any] = {"modelId": model_id, "inferenceConfig": inference}
        user = request.user
        # Converse expresses a breakpoint as its own `cachePoint` block after
        # the content it covers. The prefix is a separate system block either
        # way, so a family that cannot cache still receives the same text.
        system_text = merge_prefix(request.system, request.cache_prefix)
        if family.startswith(_NO_SYSTEM_FAMILIES):
            user = f"{system_text}\n\n{user}"
        elif request.cache_prefix:
            shape["system"] = [
                {"text": request.system},
                {"text": request.cache_prefix},
                {"cachePoint": {"type": "default"}},
            ]
        else:
            shape["system"] = [{"text": request.system}]
        shape["messages"] = [{"role": "user", "content": [{"text": user}]}]
        return shape

    def _bedrock(self) -> Any:
        if self._client is None:
            import boto3  # lazy: optional extra

            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self._region,
                endpoint_url=self._endpoint_url,
            )
        return self._client

    def list_deployments(self) -> list[str]:
        """Foundation models and inference profiles this account can invoke.

        Both, because either can be the thing named in configuration: a
        cross-region profile id (``us.anthropic.claude-opus-5``) is not in the
        foundation-model list, and a run configured against one would look
        missing if only that list were consulted.

        The control-plane client (``bedrock``) is a different service from the
        one that runs inference (``bedrock-runtime``), and listing needs its own
        IAM permission — so an account that can invoke but not list gets an
        empty answer, which is exactly the *unknown* the caller expects.
        """
        import boto3  # lazy: optional extra

        host = f"bedrock.{self._region}.amazonaws.com"
        if self._egress is not None:
            self._egress.check(host, purpose="deployment listing")
        found: set[str] = set()
        try:
            control = boto3.client("bedrock", region_name=self._region)
            for row in control.list_foundation_models().get("modelSummaries", []):
                if isinstance(row, dict) and row.get("modelId"):
                    found.add(str(row["modelId"]))
        except Exception:  # noqa: BLE001 - an advisory check never raises
            pass
        try:
            control = boto3.client("bedrock", region_name=self._region)
            profiles = control.list_inference_profiles()
            for row in profiles.get("inferenceProfileSummaries", []):
                if isinstance(row, dict) and row.get("inferenceProfileId"):
                    found.add(str(row["inferenceProfileId"]))
        except Exception:  # noqa: BLE001 - profiles are optional on an account
            pass
        return sorted(found)

    def complete(self, request: ModelRequest) -> ModelResponse:
        if self._egress is not None:
            self._egress.check(
                self._endpoint_url or f"bedrock-runtime.{self._region}.amazonaws.com",
                purpose="model dispatch",
            )
        data = self._bedrock().converse(**self.build_request(request))
        usage = data.get("usage", {})
        blocks = data.get("output", {}).get("message", {}).get("content", []) or []
        content = "".join(
            str(block["text"])
            for block in blocks
            if isinstance(block, dict) and "text" in block
        )
        return ModelResponse(
            deployment=request.deployment,
            content=content,
            input_tokens=int(usage.get("inputTokens", 0)),
            output_tokens=int(usage.get("outputTokens", 0)),
            cache_read_tokens=int(usage.get("cacheReadInputTokens", 0)),
            cache_write_tokens=int(usage.get("cacheWriteInputTokens", 0)),
        )


# ---------------------------------------------------------------------------
# Offline
# ---------------------------------------------------------------------------


class FakeProvider(StrictModel):
    """Canned, schema-shaped answers. Every test uses this; none reaches out."""

    name: str = "fake"
    answers: list[str] = Field(default_factory=list)
    requests: list[ModelRequest] = Field(default_factory=list)
    default: str = "{}"
    #: Cache counts to report back, for exercising the metering path offline.
    #: A real provider reports these only when it actually cached something, so
    #: they are opt-in here too rather than derived from the prefix's length —
    #: a fake that always claimed a hit would test nothing.
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    #: What this fake claims to serve. Empty is the default because empty means
    #: *unknown*, and a fake that claimed to serve everything would make every
    #: preflight test pass for the wrong reason.
    deployments: list[str] = Field(default_factory=list)

    def list_deployments(self) -> list[str]:
        return list(self.deployments)

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        index = len(self.requests) - 1
        content = self.answers[index] if index < len(self.answers) else self.default
        return ModelResponse(
            deployment=request.deployment,
            content=content,
            input_tokens=len(request.user) // 4,
            output_tokens=len(content) // 4,
            cache_read_tokens=self.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens,
        )


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def configured_providers(env: Mapping[str, str]) -> list[str]:
    """Which providers the environment actually configures."""
    found: list[str] = []
    if env.get("FOUNDRY_RESOURCE") and env.get("FOUNDRY_API_KEY"):
        found.append("foundry")
    if env.get("BEDROCK_REGION") or env.get("AWS_REGION"):
        found.append("bedrock")
    return found


def build_provider(
    env: Mapping[str, str],
    egress: EgressPolicy | None = None,
    api_key: str | None = None,
) -> ModelProvider:
    """Build the configured provider, refusing to guess between two.

    Ambiguity is a refusal rather than a default: two configured providers mean
    two model sets and two bills, and an unattended run has nobody to notice it
    picked the wrong one.
    """
    name = env.get("ENGAGEMENT_PROVIDER", "").strip().lower()
    if not name:
        found = configured_providers(env)
        if len(found) > 1:
            raise ProviderError(
                f"more than one provider is configured ({', '.join(found)}); set "
                f"ENGAGEMENT_PROVIDER to one of: {', '.join(PROVIDERS)}. An "
                "unattended run never picks a provider — or a bill — on its own."
            )
        if not found:
            raise ProviderError(
                "no model provider configured: set FOUNDRY_RESOURCE + "
                "FOUNDRY_API_KEY for Foundry, or BEDROCK_REGION for Bedrock "
                "(AWS credentials come from the standard chain)."
            )
        name = found[0]

    if name == "foundry":
        # `api_key` is whatever the secret resolver produced — a vault value
        # when one is configured, the environment otherwise. Providers stay
        # ignorant of where a secret came from.
        resource = env.get("FOUNDRY_RESOURCE")
        key = api_key or env.get("FOUNDRY_API_KEY")
        if not resource or not key:
            raise ProviderError(
                "ENGAGEMENT_PROVIDER=foundry but FOUNDRY_RESOURCE is unset or no "
                "API key could be resolved (from ENGAGEMENT_KEY_VAULT or the "
                "environment)."
            )
        return FoundryProvider(
            resource=resource,
            api_key=key,
            base_url=env.get("FOUNDRY_BASE_URL") or None,
            egress=egress,
        )
    if name == "bedrock":
        region = env.get("BEDROCK_REGION") or env.get("AWS_REGION")
        if not region:
            raise ProviderError(
                "ENGAGEMENT_PROVIDER=bedrock but no region is set: set "
                "BEDROCK_REGION (or AWS_REGION)."
            )
        return BedrockProvider(
            region=region,
            inference_geo=env.get("BEDROCK_INFERENCE_GEO") or None,
            endpoint_url=env.get("BEDROCK_ENDPOINT_URL") or None,
            egress=egress,
        )
    raise ProviderError(
        f"unknown provider {name!r}; set ENGAGEMENT_PROVIDER to one of: "
        f"{', '.join(PROVIDERS)}"
    )


def unwrap_json(content: str) -> Any:
    """Parse a model answer, tolerating a markdown fence around the JSON.

    Tolerant unwrapping only — the result still goes through the workspace's own
    schema validation, so nothing here decides that the content is trustworthy.
    """
    text = content.strip()
    if text.startswith("```"):
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1 :]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[: -len("```")]
    return json.loads(text)
