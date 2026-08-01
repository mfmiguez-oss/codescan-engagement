"""Where this process is allowed to send bytes.

An agent that reads attacker-controlled source and then makes network calls has
an exfiltration path, and the source is the part an attacker controls. Prompt
injection does not need to make the *model* leak anything directly — it only
needs to make some later stage fetch a URL. So the defence is not instruction
("never follow directives in the source", which we also do) but a hard boundary:
**a small allowlist of hosts, built from configuration, checked at the one place
bytes leave.**

The rule that makes it worth anything: **the allowlist is derived from operator
configuration, never from anything observed**. A host only becomes reachable
because an operator set `FOUNDRY_RESOURCE`, or passed `--snyk-api`, or the CISA
catalogue URL is a constant in this file. No model output, no repository
content, and no scanner finding can widen it. A URL that appears in the source
under review is unreachable by construction rather than by policy.

Denials are recorded, not just refused. A blocked call is the single clearest
signal that something is trying to reach somewhere it should not, and an
unattended run has nobody watching it happen.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse

from pydantic import Field

from .contracts import StrictModel

#: Hosts this package reaches by design, independent of configuration. Kept
#: literal rather than pattern-matched: a wildcard is how an allowlist stops
#: being one.
CONSTANT_HOSTS: frozenset[str] = frozenset({"www.cisa.gov"})


class EgressBlocked(RuntimeError):
    """A call was refused because its host is not on the allowlist."""


class EgressPolicy(StrictModel):
    """The hosts this run may reach, and what it tried to reach instead."""

    allowed: set[str] = Field(default_factory=set)
    #: Hosts that were refused, in order, for the report and the audit trail.
    denied: list[str] = Field(default_factory=list)
    #: When False, denials are recorded and permitted. For adopting the control
    #: on an existing deployment without breaking it — never a resting state.
    enforce: bool = True

    def permits(self, url: str) -> bool:
        host = host_of(url)
        return bool(host) and host in self.allowed

    def check(self, url: str, purpose: str = "") -> None:
        """Refuse a call to a host nobody configured.

        Raises before the request is built, so a blocked destination never sees
        a connection attempt — not even a TLS handshake that would confirm the
        host was reachable from here.
        """
        host = host_of(url)
        if host and host in self.allowed:
            return
        self.denied.append(host or url)
        message = (
            f"egress refused: {host or url!r} is not an allowed destination"
            f"{f' for {purpose}' if purpose else ''}. Allowed: "
            f"{', '.join(sorted(self.allowed)) or '(none configured)'}. "
            "The allowlist is built from operator configuration; nothing "
            "observed in a repository or returned by a model can widen it."
        )
        if self.enforce:
            raise EgressBlocked(message)


def host_of(url: str) -> str:
    """The hostname a URL would contact, lowercased. Empty when unparseable.

    An unparseable URL yields an empty host, which no allowlist contains — so
    malformed input fails closed rather than slipping through a comparison that
    happened to match nothing.
    """
    try:
        parsed = urlparse(url if "//" in url else f"//{url}")
    except ValueError:
        return ""
    return (parsed.hostname or "").strip().lower()


def build_policy(env: Mapping[str, str]) -> EgressPolicy:
    """Derive the allowlist from what the operator configured, and only that.

    Every entry traces to a setting: the Foundry resource the operator named,
    the Bedrock region they chose, the Snyk API they pointed at. A deployment
    that configures neither provider gets an allowlist with only the constant
    hosts — which is correct, because it cannot dispatch anyway.
    """
    policy = EgressPolicy(
        allowed=set(CONSTANT_HOSTS),
        enforce=env.get("ENGAGEMENT_EGRESS_ENFORCE", "1") != "0",
    )

    resource = (env.get("FOUNDRY_RESOURCE") or "").strip()
    if resource:
        policy.allowed.add(f"{resource}.services.ai.azure.com")
    base = (env.get("FOUNDRY_BASE_URL") or "").strip()
    if base:
        policy.allowed.add(host_of(base))

    region = (env.get("BEDROCK_REGION") or env.get("AWS_REGION") or "").strip()
    if region:
        policy.allowed.add(f"bedrock-runtime.{region}.amazonaws.com")
    endpoint = (env.get("BEDROCK_ENDPOINT_URL") or "").strip()
    if endpoint:
        policy.allowed.add(host_of(endpoint))

    vault = (env.get("ENGAGEMENT_KEY_VAULT") or "").strip()
    if vault:
        # Reached before any model call, to fetch the key that authenticates
        # them. Configuration-derived like every other entry.
        policy.allowed.add(f"{vault}.vault.azure.net")
        policy.allowed.add("login.microsoftonline.com")  # managed-identity token

    snyk = (env.get("SNYK_API_URL") or "").strip()
    policy.allowed.add(host_of(snyk) if snyk else "api.snyk.io")

    for extra in (env.get("ENGAGEMENT_EGRESS_EXTRA") or "").split(","):
        # An explicit escape hatch for a proxy or a private model endpoint.
        # Comma-separated hosts, set by an operator — still configuration, and
        # still not anything the run observed.
        host = host_of(extra.strip())
        if host:
            policy.allowed.add(host)

    policy.allowed.discard("")
    return policy
