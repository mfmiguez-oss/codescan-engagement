"""Real crypto and a real ASGI server.

Opt-in: skipped unless the ``api`` extra is installed, so the base gate stays
dependency-free. These are the tests that matter most, because the failures
they cover — algorithm confusion, a token minted for another audience, an
expired token still accepted — all *look* like working code until someone
tries them.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("starlette")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from engagement.api import ApiConfig, ControlPlane, build_app  # noqa: E402
from engagement.auth import AuthError, OidcVerifier, RoleMapping  # noqa: E402
from engagement.decisions import MemoryDecisionStore  # noqa: E402
from engagement.identity import Role  # noqa: E402

ISSUER = "https://login.microsoftonline.com/acme/v2.0"
AUDIENCE = "api://engagement"

MAPPING = RoleMapping(
    mapping={
        "Engagement.Analyst": Role.analyst,
        "Engagement.Approver": Role.approver,
    }
)


@pytest.fixture(scope="module")
def keypair() -> tuple[Any, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return key, public_pem


def _issue(key: Any, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "pairwise-1",
        "oid": "oid-approver",
        "tid": "acme",
        "name": "Ada",
        "roles": ["Engagement.Approver", "Engagement.Analyst"],
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256")


def _verifier(public_pem: str) -> OidcVerifier:
    verifier = OidcVerifier(
        jwks_uri="https://example.invalid/keys", issuer=ISSUER, audience=AUDIENCE
    )

    class _Key:
        key = public_pem

    class _Client:
        def get_signing_key_from_jwt(self, token: str) -> Any:
            return _Key()

    verifier._client = _Client()  # the network is the only part being stubbed
    return verifier


def test_a_genuine_token_verifies(keypair: tuple[Any, str]) -> None:
    key, public_pem = keypair
    claims = _verifier(public_pem).verify(_issue(key))
    assert claims["oid"] == "oid-approver"


def _forge_hs256(public_pem: str, claims: dict[str, Any]) -> str:
    """Hand-roll an HS256 token keyed on the public PEM.

    Built byte by byte rather than through PyJWT, which refuses to *encode*
    this shape — an attacker has no such scruples, so testing through the
    library's guardrails would test the guardrails rather than the verifier.
    """
    import base64
    import hashlib
    import hmac
    import json as _json

    def segment(payload: dict[str, Any]) -> bytes:
        raw = _json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    signing_input = b".".join(
        [segment({"alg": "HS256", "typ": "JWT"}), segment(claims)]
    )
    signature = hmac.new(
        public_pem.encode(), signing_input, hashlib.sha256
    ).digest()
    return (
        signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    ).decode()


def test_an_algorithm_confusion_forgery_is_rejected(keypair: tuple[Any, str]) -> None:
    """The classic: sign with HS256 using the *public* key as the shared
    secret. Accepting it turns a published key into a signing key."""
    _, public_pem = keypair
    now = int(time.time())
    forged = _forge_hs256(
        public_pem,
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "x",
            "oid": "attacker",
            "roles": ["Engagement.Approver"],
            "iat": now,
            "exp": now + 300,
        },
    )
    with pytest.raises(AuthError):
        _verifier(public_pem).verify(forged)


def test_an_unsigned_token_is_rejected(keypair: tuple[Any, str]) -> None:
    """``alg: none`` — the other half of the same family."""
    import base64
    import json as _json

    _, public_pem = keypair
    now = int(time.time())

    def segment(payload: dict[str, Any]) -> bytes:
        raw = _json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    unsigned = (
        b".".join(
            [
                segment({"alg": "none", "typ": "JWT"}),
                segment(
                    {
                        "iss": ISSUER,
                        "aud": AUDIENCE,
                        "sub": "x",
                        "oid": "attacker",
                        "roles": ["Engagement.Approver"],
                        "iat": now,
                        "exp": now + 300,
                    }
                ),
                b"",
            ]
        )
    ).decode()
    with pytest.raises(AuthError):
        _verifier(public_pem).verify(unsigned)


def test_a_token_for_another_audience_is_rejected(keypair: tuple[Any, str]) -> None:
    key, public_pem = keypair
    with pytest.raises(AuthError):
        _verifier(public_pem).verify(_issue(key, aud="api://some-other-app"))


def test_a_token_from_another_issuer_is_rejected(keypair: tuple[Any, str]) -> None:
    key, public_pem = keypair
    with pytest.raises(AuthError):
        _verifier(public_pem).verify(_issue(key, iss="https://evil.example/v2.0"))


def test_an_expired_token_is_rejected(keypair: tuple[Any, str]) -> None:
    key, public_pem = keypair
    past = int(time.time()) - 3600
    with pytest.raises(AuthError):
        _verifier(public_pem).verify(_issue(key, iat=past, exp=past + 60))


def test_a_token_missing_a_required_claim_is_rejected(keypair: tuple[Any, str]) -> None:
    """Required claims are listed explicitly so a provider that omits one is
    refused rather than defaulted."""
    key, public_pem = keypair
    now = int(time.time())
    thin = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "exp": now + 300},
        key,
        algorithm="RS256",
    )
    with pytest.raises(AuthError):
        _verifier(public_pem).verify(thin)


def test_the_failure_reason_never_reaches_the_caller(keypair: tuple[Any, str]) -> None:
    key, public_pem = keypair
    with pytest.raises(AuthError) as excinfo:
        _verifier(public_pem).verify(_issue(key, aud="wrong"))
    # the class name, not the library's description of what was wrong
    assert "wrong" not in str(excinfo.value)


# -- over HTTP --------------------------------------------------------------


class _Drafter:
    def draft(self, principal: Any, fingerprint: str) -> dict[str, Any]:
        return {"finding_id": fingerprint, "requested_by": principal.actor()}


@pytest.fixture()
def client(keypair: tuple[Any, str]) -> TestClient:
    _, public_pem = keypair
    plane = ControlPlane(
        _verifier(public_pem),
        MemoryDecisionStore(),
        ApiConfig(tenant="acme"),
        MAPPING,
        _Drafter(),
    )
    return TestClient(build_app(plane))


def test_health_is_the_only_unauthenticated_route(client: TestClient) -> None:
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/whoami").status_code == 401
    assert client.post("/api/findings/fp1/state", json={"state": "confirmed"}).status_code == 401


def test_a_verified_approver_can_close_over_http(
    client: TestClient, keypair: tuple[Any, str]
) -> None:
    key, _ = keypair
    headers = {"Authorization": f"Bearer {_issue(key)}"}

    whoami = client.get("/api/whoami", headers=headers)
    assert whoami.status_code == 200
    assert set(whoami.json()["roles"]) == {"analyst", "approver"}

    closed = client.post(
        "/api/findings/fp1/state",
        headers=headers,
        json={"state": "risk_accepted", "note": "compensating control in place"},
    )
    assert closed.status_code == 200
    assert closed.json()["applied"]
    assert closed.json()["decision"]["actor"] == "oid-approver"

    read_back = client.get("/api/findings/fp1/decision", headers=headers)
    assert read_back.json()["state"] == "risk_accepted"


def test_an_analyst_is_refused_the_close_over_http(
    client: TestClient, keypair: tuple[Any, str]
) -> None:
    key, _ = keypair
    token = _issue(key, oid="oid-analyst", roles=["Engagement.Analyst"])
    headers = {"Authorization": f"Bearer {token}"}

    assert (
        client.post(
            "/api/findings/fp1/state", headers=headers, json={"state": "resolved"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/findings/fp1/state", headers=headers, json={"state": "confirmed"}
        ).status_code
        == 200
    )


def test_a_draft_can_be_requested_from_the_console_over_http(
    client: TestClient, keypair: tuple[Any, str]
) -> None:
    """The other half of the critical-only rule: what a run did not draft for
    automatically, an analyst asks for from the page they are reading."""
    key, _ = keypair
    token = _issue(key, oid="oid-analyst", roles=["Engagement.Analyst"])

    response = client.post(
        "/api/findings/fp1/poc", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json()["requested_by"] == "oid-analyst"


def test_requesting_a_draft_is_authenticated_like_a_write(client: TestClient) -> None:
    """It spends money, so it is guarded like a write even though it records
    no decision."""
    assert client.post("/api/findings/fp1/poc").status_code == 401


def test_an_error_body_carries_no_detail(client: TestClient) -> None:
    body = client.get("/api/whoami", headers={"Authorization": "Bearer nope"}).json()
    assert body == {"error": "unauthorized"}
