"""Turning a bearer token into a principal.

:mod:`engagement.identity` says what a principal may do. This says who the
principal *is*, which is the half that has to be right for the other half to
mean anything: an authorization model over a subject anyone can assert is a
suggestion.

Signature verification is delegated to PyJWT rather than implemented here.
Hand-rolled JWT validation is a well-populated graveyard — algorithm confusion,
unverified `kid`, missing audience checks, `alg: none` — and none of those
mistakes are ones this project is better placed to avoid than a library that
exists to avoid them.

Everything fails closed. A token that cannot be verified yields no principal; a
verified token carrying no recognised role yields a principal that can do
nothing. There is deliberately no path from "we could not check" to "allow".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from pydantic import Field

from .contracts import StrictModel
from .identity import Principal, Role

#: Claims that must be present and verified on every token. Listed explicitly
#: so a provider that omits one is rejected rather than defaulted.
REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")

#: The only signing algorithms accepted. Passed to the verifier explicitly so
#: the *token* can never choose — which is what turns a public-key deployment
#: into an HMAC forgery, and is the single most common JWT failure.
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384")

#: Small tolerance for clock drift between the issuer and this host. Seconds.
CLOCK_SKEW_SECONDS = 60


class AuthError(PermissionError):
    """The credential was absent, malformed, or did not verify."""


class TokenVerifier(Protocol):
    """Verifies a raw bearer token and returns its claims."""

    def verify(self, token: str) -> Mapping[str, Any]: ...


class RoleMapping(StrictModel):
    """How a provider's group or role claims become this system's roles.

    Kept as configuration rather than code because the mapping is a deployment
    decision: the same binary serves an org that grants roles through Entra app
    roles and one that grants them through group object ids.
    """

    #: Claim to read role values from, in order of preference.
    claims: list[str] = Field(default_factory=lambda: ["roles", "groups"])
    #: Provider value -> role. Values not listed here grant nothing.
    mapping: dict[str, Role] = Field(default_factory=dict)
    #: Claim carrying the tenant this principal belongs to.
    tenant_claim: str = "tid"
    #: Claim carrying a human-readable name, for display only.
    display_claim: str = "name"

    def roles_for(self, claims: Mapping[str, Any]) -> list[Role]:
        """Map provider values to roles, ignoring anything unrecognised.

        Unrecognised values grant nothing rather than being guessed at: a
        directory group named ``security-approvers`` must be mapped
        deliberately, because inferring authority from a string that happens to
        look right is how a rename becomes a privilege escalation.
        """
        granted: list[Role] = []
        for claim in self.claims:
            values = claims.get(claim)
            if values is None:
                continue
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, Sequence):
                continue
            for value in values:
                role = self.mapping.get(str(value))
                if role is not None and role not in granted:
                    granted.append(role)
        return granted


def principal_from_claims(
    claims: Mapping[str, Any], mapping: RoleMapping | None = None
) -> Principal:
    """Build a principal from verified claims.

    ``subject`` is taken from ``oid`` when present and ``sub`` otherwise: on
    Entra, ``sub`` is pairwise per-application while ``oid`` is the stable
    object id for the user across the directory, and a decision record needs to
    still name the same person after the application is re-registered.
    """
    mapping = mapping or RoleMapping()
    subject = str(claims.get("oid") or claims.get("sub") or "").strip()
    if not subject:
        raise AuthError("verified token carries no subject")
    return Principal(
        subject=subject,
        display=str(claims.get(mapping.display_claim, "") or ""),
        roles=mapping.roles_for(claims),
        tenant=str(claims.get(mapping.tenant_claim, "") or ""),
    )


class OidcVerifier:
    """Verifies tokens against an OIDC issuer's published keys.

    Works for Entra ID and any other standards-compliant issuer; the provider
    difference is configuration, not code. ``PyJWT`` is imported lazily so the
    base package installs and its gate runs without it.
    """

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        algorithms: Sequence[str] = ALLOWED_ALGORITHMS,
        cache_seconds: int = 600,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._audience = audience
        self._algorithms = list(algorithms)
        self._cache_seconds = cache_seconds
        self._client: Any | None = None

    def _jwk_client(self) -> Any:
        if self._client is None:
            from jwt import PyJWKClient  # lazy: optional extra

            # cache keys, but bound the cache: a rotated signing key must be
            # picked up without a restart, and an unknown `kid` must trigger a
            # refetch rather than a rejection
            self._client = PyJWKClient(
                self._jwks_uri, cache_keys=True, lifespan=self._cache_seconds
            )
        return self._client

    def verify(self, token: str) -> Mapping[str, Any]:
        try:
            import jwt  # lazy: optional extra
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise AuthError(
                "token verification requires the 'api' extra (PyJWT)"
            ) from exc

        try:
            signing_key = self._jwk_client().get_signing_key_from_jwt(token)
            claims: Mapping[str, Any] = jwt.decode(
                token,
                signing_key.key,
                # the algorithm list comes from configuration, never from the
                # token header — otherwise a forger picks HS256 and signs with
                # the public key
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except Exception as exc:
            # the reason is logged by the caller, never returned to the client:
            # a verification oracle helps only the party holding a bad token
            raise AuthError(f"token verification failed: {type(exc).__name__}") from exc
        return claims


class StaticVerifier(StrictModel):
    """Accepts a fixed set of tokens. For the gate and local development only.

    Deliberately not usable by accident: it holds tokens in memory, so it can
    only exist where something constructed it with them.
    """

    tokens: dict[str, dict[str, Any]] = Field(default_factory=dict)

    def verify(self, token: str) -> Mapping[str, Any]:
        claims = self.tokens.get(token)
        if claims is None:
            raise AuthError("unknown token")
        return claims


def bearer_token(header: str | None) -> str:
    """Extract a token from an ``Authorization`` header, strictly."""
    if not header:
        raise AuthError("missing Authorization header")
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthError("Authorization header is not a bearer token")
    return parts[1].strip()


def authenticate(
    header: str | None,
    verifier: TokenVerifier,
    mapping: RoleMapping | None = None,
) -> Principal:
    """Header in, principal out. Raises on anything less than full success."""
    return principal_from_claims(verifier.verify(bearer_token(header)), mapping)
