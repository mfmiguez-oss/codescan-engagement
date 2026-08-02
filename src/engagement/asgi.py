"""ASGI entrypoint for the control plane and the analyst console.

Constructed from the environment at import time so the container's command line
stays a plain ``uvicorn engagement.asgi:app``. Every value here is public —
issuer, audience, JWKS URI, client id — because verification is by published
key and there is no secret for this process to hold.

The application refuses to start rather than starting permissively: a missing
issuer or audience means every token would be accepted on trust, so it is a
configuration error, not a default.

The console is served only when ``ENGAGEMENT_RUN_DIR`` names a run to show. A
deployment that wants the machine surface alone gets exactly that, and a
deployment that misconfigures the run directory gets an API with no page rather
than a page that renders an empty queue as though the run found nothing.
"""

from __future__ import annotations

import os
from pathlib import Path

from .api import ApiConfig, ControlPlane, build_app
from .auth import OidcVerifier, RoleMapping
from .console import render as render_console
from .decisions import JsonlDecisionStore
from .identity import Role
from .serving import ManifestQueue

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
    config = ApiConfig(
        tenant=os.environ.get("ENGAGEMENT_TENANT_ID", ""),
        authorize_url=os.environ.get("ENGAGEMENT_AUTHORIZE_URL", ""),
        token_url=os.environ.get("ENGAGEMENT_TOKEN_URL", ""),
        client_id=os.environ.get("ENGAGEMENT_CLIENT_ID", ""),
        api_audience=os.environ.get("ENGAGEMENT_API_AUDIENCE", ""),
        environment=os.environ.get("ENGAGEMENT_ENVIRONMENT", ""),
    )
    run_dir = os.environ.get("ENGAGEMENT_RUN_DIR", "").strip()
    queue = ManifestQueue(Path(run_dir)) if run_dir else None
    plane = ControlPlane(
        verifier,
        store,
        config,
        RoleMapping(mapping=_ROLE_CLAIMS),
        queue=queue,
    )
    # No drafter here: drafting spends money and needs a provider and a key,
    # which this process deliberately does not hold. `engagement console` wires
    # one for a local operator who has already resolved a secret.
    return build_app(plane, console_html=render_console() if queue else None)


app = create_app() if os.environ.get("ENGAGEMENT_JWKS_URI") else None
