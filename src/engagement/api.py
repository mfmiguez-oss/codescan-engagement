"""The HTTP surface of the control plane.

Deliberately thin. Every security decision it makes is delegated to a function
that can be tested without a socket — :func:`engagement.auth.authenticate` for
identity, :func:`engagement.identity.authorize` for permission,
:func:`engagement.decisions.resolve_write` for precedence. What is left here is
routing, status codes, and the discipline of never leaking why a credential
failed.

Starlette is an optional extra. The routes are built from a plain table so the
same surface can be mounted in another framework, and so the tests can exercise
the handlers as functions rather than through a client.

Two rules the handlers follow without exception:

- **Fail closed and fail quiet.** Anything short of a fully verified token is
  401 with no detail; an authenticated principal lacking a role is 403 with no
  detail. A caller learning *which* check failed learns how close it is.
- **No write without a principal.** There is no service-account bypass, no
  header that names an actor, and no unauthenticated path that mutates. The
  unattended run gets its authority from :func:`engagement.identity.machine`,
  which cannot close a finding.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .auth import AuthError, RoleMapping, TokenVerifier, authenticate
from .contracts import StrictModel
from .decisions import DecisionStore, record_decision
from .identity import (
    Action,
    Principal,
    Unauthorized,
    ValidationState,
    authorize,
)

logger = logging.getLogger(__name__)


class ApiConfig(StrictModel):
    """What the surface needs to know. No secrets: verification is by public
    key, and the decision store is passed in already constructed."""

    #: Reject tokens issued for a different tenant than this deployment serves.
    tenant: str = ""
    #: Maximum accepted request body, in bytes.
    max_body_bytes: int = 64 * 1024


class Problem(Exception):
    """An HTTP failure with a status and a deliberately unhelpful message."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(message)


class ControlPlane:
    """The handlers, independent of any web framework."""

    def __init__(
        self,
        verifier: TokenVerifier,
        store: DecisionStore,
        config: ApiConfig | None = None,
        mapping: RoleMapping | None = None,
    ) -> None:
        self._verifier = verifier
        self._store = store
        self._config = config or ApiConfig()
        self._mapping = mapping

    # -- identity -----------------------------------------------------------

    def principal(self, authorization: str | None) -> Principal:
        """Authenticate, or raise a 401 that says nothing useful."""
        try:
            principal = authenticate(authorization, self._verifier, self._mapping)
        except AuthError as exc:
            # the reason is logged for the operator and withheld from the
            # caller: a verification oracle only ever helps the wrong party
            logger.info("authentication failed: %s", exc)
            raise Problem(401, "unauthorized") from exc
        if self._config.tenant and principal.tenant != self._config.tenant:
            logger.info(
                "tenant mismatch: token %r, deployment %r",
                principal.tenant,
                self._config.tenant,
            )
            raise Problem(401, "unauthorized")
        return principal

    def _guard(
        self,
        principal: Principal,
        action: Action,
        state: ValidationState | None = None,
    ) -> None:
        try:
            authorize(principal, action, state, tenant=self._config.tenant or None)
        except Unauthorized as exc:
            logger.info("authorization denied for %s: %s", principal.subject, exc)
            raise Problem(403, "forbidden") from exc

    # -- handlers -----------------------------------------------------------

    def whoami(self, authorization: str | None) -> dict[str, Any]:
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        return {
            "subject": principal.subject,
            "display": principal.display,
            "tenant": principal.tenant,
            "roles": [role.value for role in principal.roles],
        }

    def get_decision(self, authorization: str | None, fingerprint: str) -> dict[str, Any]:
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        decision = self._store.get(fingerprint)
        if decision is None:
            raise Problem(404, "not found")
        return decision.model_dump(mode="json")

    def set_state(
        self, authorization: str | None, fingerprint: str, body: bytes
    ) -> dict[str, Any]:
        principal = self.principal(authorization)
        payload = self._payload(body)

        raw_state = payload.get("state")
        try:
            state = ValidationState(str(raw_state))
        except ValueError as exc:
            raise Problem(400, "unknown state") from exc

        # authorization first, so an unauthorized attempt never reaches storage
        self._guard(principal, Action.set_state, state)

        note = payload.get("note")
        resolved = record_decision(
            principal,
            self._store,
            fingerprint,
            state,
            note=str(note) if note is not None else None,
            tenant=self._config.tenant or None,
        )
        # the response reports what *survived*, which is not always what was
        # sent: a machine proposal against a human decision loses, and the
        # caller is told so rather than being allowed to assume it won
        return {
            "applied": resolved.actor == principal.actor()
            and resolved.state == state,
            "decision": resolved.model_dump(mode="json"),
        }

    def _payload(self, body: bytes) -> dict[str, Any]:
        if len(body) > self._config.max_body_bytes:
            raise Problem(413, "request too large")
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            raise Problem(400, "invalid JSON") from exc
        if not isinstance(payload, dict):
            raise Problem(400, "expected a JSON object")
        return payload


def build_app(plane: ControlPlane) -> Any:
    """Mount the control plane as a Starlette ASGI application.

    Imported lazily and constructed here so the handlers above stay importable,
    and testable, without the web framework installed.
    """
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "the HTTP surface requires the 'api' extra (starlette)"
        ) from exc

    def respond(handler: Callable[[Request], Awaitable[Any]]) -> Any:
        async def endpoint(request: Request) -> JSONResponse:
            try:
                return JSONResponse(await handler(request))
            except Problem as problem:
                return JSONResponse({"error": problem.message}, problem.status)

        return endpoint

    async def whoami(request: Request) -> Any:
        return plane.whoami(request.headers.get("authorization"))

    async def get_decision(request: Request) -> Any:
        return plane.get_decision(
            request.headers.get("authorization"), request.path_params["fingerprint"]
        )

    async def set_state(request: Request) -> Any:
        return plane.set_state(
            request.headers.get("authorization"),
            request.path_params["fingerprint"],
            await request.body(),
        )

    async def healthz(request: Request) -> JSONResponse:
        # the only unauthenticated route, and it reveals nothing but liveness
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/api/whoami", respond(whoami)),
            Route("/api/findings/{fingerprint}/decision", respond(get_decision)),
            Route(
                "/api/findings/{fingerprint}/state", respond(set_state), methods=["POST"]
            ),
        ]
    )
