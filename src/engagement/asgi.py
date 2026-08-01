"""ASGI entrypoint for the control plane.

Constructed from the environment at import time so the container's command line
stays a plain ``uvicorn engagement.asgi:app``. Every value here is public —
issuer, audience, JWKS URI — because verification is by published key and there
is no secret for this process to hold.

The application refuses to start rather than starting permissively: a missing
issuer or audience means every token would be accepted on trust, so it is a
configuration error, not a default.
"""

from __future__ import annotations

import os
from pathlib import Path

from .api import ApiConfig, ControlPlane, build_app
from .auth import OidcVerifier, RoleMapping
from .decisions import JsonlDecisionStore
from .identity import Role

_ROLE_CLAIMS = {
    "Engagement.Scanner": Role.scanner,
    "Engagement.Analyst": Role.analyst,
    "Engagement.Approver": Role.approver,
    "Engagement.Admin": Role.admin,
}


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"{name} is required: without it every token would be accepted on "
            "trust, so the control plane refuses to start rather than start open"
        )
    return value


def create_app() -> object:
    verifier = OidcVerifier(
        jwks_uri=_required("ENGAGEMENT_JWKS_URI"),
        issuer=_required("ENGAGEMENT_ISSUER"),
        audience=_required("ENGAGEMENT_API_AUDIENCE"),
    )
    store = JsonlDecisionStore(
        Path(os.environ.get("ENGAGEMENT_DECISIONS", "decisions.jsonl"))
    )
    plane = ControlPlane(
        verifier,
        store,
        ApiConfig(tenant=os.environ.get("ENGAGEMENT_TENANT_ID", "")),
        RoleMapping(mapping=_ROLE_CLAIMS),
    )
    return build_app(plane)


app = create_app() if os.environ.get("ENGAGEMENT_JWKS_URI") else None
