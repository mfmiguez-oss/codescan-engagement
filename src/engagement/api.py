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

Spending counts as writing. ``POST /api/findings/{id}/poc`` produces no record
in the decision store and is still guarded exactly like one, because it costs
money and because a PoC drafted outside the critical set is by definition a
person's judgement — so it needs a person's identity behind it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from pydantic import ValidationError

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
from .ratelimit import RateLimited, RateLimiter
from .runs import RunRequest

__all__ = [
    "MAX_BULK",
    "SECURITY_HEADERS",
    "ApiConfig",
    "ControlPlane",
    "PocDrafter",
    "Problem",
    "QueueSource",
    "RunStarter",
    "build_app",
]

#: Findings one bulk request may carry. Bounded because the body is parsed and
#: every entry becomes a write: a caller should not be able to turn one request
#: into ten thousand of them.
MAX_BULK = 200

logger = logging.getLogger(__name__)


class ApiConfig(StrictModel):
    """What the surface needs to know. No secrets: verification is by public
    key, and the decision store is passed in already constructed."""

    #: Reject tokens issued for a different tenant than this deployment serves.
    tenant: str = ""
    #: Maximum accepted request body, in bytes.
    max_body_bytes: int = 64 * 1024
    #: Public OIDC parameters the console needs to start an auth code flow.
    #: Public by definition — a client id and an authorize URL are not secrets,
    #: and serving them beats baking a deployment's identity into the page at
    #: build time and shipping the wrong one.
    authorize_url: str = ""
    token_url: str = ""
    client_id: str = ""
    api_audience: str = ""
    #: Shown in the console header so an analyst can tell two deployments apart
    #: before acting on the wrong one.
    environment: str = ""
    #: Let the console take a bearer token typed in by hand instead of running
    #: an auth code flow. **Development only**, and set by exactly one caller:
    #: `engagement console --dev-token`, which refuses to bind anywhere but
    #: loopback. It exists because a local operator with no identity provider
    #: otherwise has a page that can never obtain a token — a console that
    #: cannot be signed into is not a smaller feature, it is no feature.
    allow_token_entry: bool = False


class Problem(Exception):
    """An HTTP failure with a status and a deliberately unhelpful message."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(message)


class QueueSource(Protocol):
    """Supplies the ranked queue the console displays.

    A protocol because the queue is a run artifact on disk and the HTTP surface
    has no business knowing where runs live. The deployment wires in something
    that reads it; the gate wires in a list.
    """

    def findings(self, run: str | None = None) -> list[dict[str, Any]]: ...

    def runs(self) -> list[dict[str, Any]]: ...

    def detail(self, fingerprint: str, run: str | None = None) -> dict[str, Any]: ...


class RunStarter(Protocol):
    """Starts scans. The most authority anything in this package is given.

    Separate from :class:`QueueSource` deliberately: a deployment that serves a
    queue read-only wires one and not the other, and the difference between
    "can look" and "can spend" stays a wiring decision rather than a role
    lookup that could be got wrong once.
    """

    def start(self, principal: Principal, request: Any) -> Any: ...

    def get(self, record_id: str) -> Any: ...

    def list(self) -> list[Any]: ...


class PocDrafter(Protocol):
    """Drafts a PoC for one finding, on request.

    A protocol rather than a concrete engine because drafting needs a provider,
    a ledger and a run's queue — none of which belong to an HTTP surface. The
    deployment wires in something that has them; the gate wires in a fake, and
    the authorization above it is identical either way.
    """

    def draft(self, principal: Principal, fingerprint: str) -> dict[str, Any]: ...


class ControlPlane:
    """The handlers, independent of any web framework."""

    def __init__(
        self,
        verifier: TokenVerifier,
        store: DecisionStore,
        config: ApiConfig | None = None,
        mapping: RoleMapping | None = None,
        drafter: PocDrafter | None = None,
        queue: QueueSource | None = None,
        runner: RunStarter | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        self._verifier = verifier
        self._store = store
        self._config = config or ApiConfig()
        self._mapping = mapping
        self._drafter = drafter
        self._queue = queue
        self._runner = runner
        self._limiter = limiter or RateLimiter()

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
        spending: bool = False,
    ) -> None:
        """Authorize, then rate-limit — in that order.

        A caller who may not do this at all should be told 403 rather than 429:
        answering "slow down" to something that will never be allowed tells
        them to keep trying, and turns the limiter into an oracle for what a
        principal *would* be permitted to do if only it waited.
        """
        try:
            authorize(principal, action, state, tenant=self._config.tenant or None)
        except Unauthorized as exc:
            logger.info("authorization denied for %s: %s", principal.subject, exc)
            raise Problem(403, "forbidden") from exc
        try:
            self._limiter.check(principal.actor(), spending=spending)
        except RateLimited as exc:
            raise Problem(429, "too many requests") from exc

    # -- handlers -----------------------------------------------------------

    def whoami(self, authorization: str | None) -> dict[str, Any]:
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        return {
            "subject": principal.subject,
            "display": principal.display,
            "tenant": principal.tenant,
            "roles": [role.value for role in principal.roles],
            # Which states this principal may actually set, computed by the same
            # function that enforces it. The console renders exactly this list,
            # so an analyst is never shown a "risk accepted" option that the
            # server will refuse — and the answer cannot drift from the rule,
            # because there is only one rule and this is it being asked nicely.
            "may_set": [state.value for state in self._settable(principal)],
            "may_draft": self._may(principal, Action.draft_poc),
        }

    def _settable(self, principal: Principal) -> list[ValidationState]:
        allowed: list[ValidationState] = []
        for state in ValidationState:
            try:
                authorize(
                    principal,
                    Action.set_state,
                    state,
                    tenant=self._config.tenant or None,
                )
            except Unauthorized:
                continue
            allowed.append(state)
        return allowed

    def _may(self, principal: Principal, action: Action) -> bool:
        try:
            authorize(principal, action, tenant=self._config.tenant or None)
        except Unauthorized:
            return False
        return True

    def public_config(self) -> dict[str, Any]:
        """What the console needs before anyone has signed in.

        Unauthenticated on purpose, and it is the only route besides health
        that is: a page cannot present a sign-in button without knowing where
        to send the user. Every value here is public by construction — an
        authorize URL, a client id, an audience, an environment label. There is
        no branch on the caller, because there is no caller to branch on yet.
        """
        return {
            "authorize_url": self._config.authorize_url,
            "token_url": self._config.token_url,
            "client_id": self._config.client_id,
            "audience": self._config.api_audience,
            "tenant": self._config.tenant,
            "environment": self._config.environment,
            "allow_token_entry": self._config.allow_token_entry,
            #: The console hides controls these disable. The server refuses
            #: regardless — a hidden button is a courtesy, never a control.
            "runs_enabled": self._runner is not None,
            "bulk_limit": MAX_BULK,
            #: The console disables its write controls when this is false, and
            #: the server refuses them regardless. Two layers, because a UI
            #: that hides a button is a courtesy and never a control.
            "drafting": self._drafter is not None,
        }

    def list_runs(self, authorization: str | None) -> dict[str, Any]:
        """Every run in the workspace that produced a queue."""
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        if self._queue is None:
            raise Problem(503, "no queue is configured")
        return {"runs": self._queue.runs()}

    def finding_detail(
        self, authorization: str | None, fingerprint: str, run: str | None = None
    ) -> dict[str, Any]:
        """One finding, with its evidence, chains, draft and decision history.

        Four sources joined server-side because the alternative is four round
        trips from a page that is showing one row, and because the join needs
        to know which absences mean "no" and which mean "never asked".
        """
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        if self._queue is None:
            raise Problem(503, "no queue is configured")
        try:
            detail = self._queue.detail(fingerprint, run)
        except ValueError as exc:
            raise Problem(404, "not found") from exc
        if detail.get("finding") is None:
            raise Problem(404, "not found")
        decision = self._store.get(fingerprint)
        return {
            **detail,
            "decision": decision.model_dump(mode="json") if decision else None,
            "history": [
                item.model_dump(mode="json")
                for item in self._store.history(fingerprint)
            ],
        }

    def decision_history(
        self, authorization: str | None, fingerprint: str
    ) -> dict[str, Any]:
        """Every decision ever recorded for one finding, oldest first.

        A separate route as well as part of the detail, because "who closed
        this, and when" is asked about findings that are currently open and an
        auditor should not have to fetch a queue to ask it.
        """
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        return {
            "fingerprint": fingerprint,
            "history": [
                item.model_dump(mode="json")
                for item in self._store.history(fingerprint)
            ],
        }

    def list_findings(self, authorization: str | None, run: str | None = None) -> dict[str, Any]:
        """The ranked queue, with each finding's current decision joined on.

        Joined here rather than in the page because precedence is a server-side
        rule: the console must show what the store actually holds, not what the
        analyst last clicked. A finding with no decision comes back with a null
        one rather than being defaulted to ``new`` — "nobody has looked at this"
        and "somebody set it to new" are different facts.
        """
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        if self._queue is None:
            raise Problem(503, "no queue is configured")
        rows: list[dict[str, Any]] = []
        try:
            listed = self._queue.findings(run)
        except ValueError as exc:
            raise Problem(404, "not found") from exc
        for finding in listed:
            fingerprint = str(finding.get("id", ""))
            decision = self._store.get(fingerprint) if fingerprint else None
            rows.append(
                {
                    **finding,
                    "decision": decision.model_dump(mode="json") if decision else None,
                }
            )
        return {"findings": rows, "count": len(rows)}

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

    def set_states(self, authorization: str | None, body: bytes) -> dict[str, Any]:
        """Set one state across several findings.

        Reports **per finding**, and does not stop at the first refusal. A bulk
        action that aborted halfway would leave the caller unable to say which
        half happened; one that reported only a count would hide that a
        machine proposal lost to a human decision on three of them. So each
        entry carries its own outcome, and the response is a 200 describing a
        partial result rather than an error describing none of it.
        """
        principal = self.principal(authorization)
        payload = self._payload(body)

        raw_state = payload.get("state")
        try:
            state = ValidationState(str(raw_state))
        except ValueError as exc:
            raise Problem(400, "unknown state") from exc

        fingerprints = payload.get("fingerprints")
        if not isinstance(fingerprints, list) or not fingerprints:
            raise Problem(400, "expected a non-empty fingerprints array")
        if len(fingerprints) > MAX_BULK:
            raise Problem(413, "too many findings in one request")

        # Authorized once, before anything is written: the answer cannot differ
        # per finding, and checking inside the loop would mean a refusal
        # arrived after some of the work had already been done.
        self._guard(principal, Action.set_state, state)

        note = payload.get("note")
        results: list[dict[str, Any]] = []
        for raw in dict.fromkeys(str(item) for item in fingerprints):
            resolved = record_decision(
                principal,
                self._store,
                raw,
                state,
                note=str(note) if note is not None else None,
                tenant=self._config.tenant or None,
            )
            results.append(
                {
                    "fingerprint": raw,
                    "applied": resolved.actor == principal.actor()
                    and resolved.state == state,
                    "decision": resolved.model_dump(mode="json"),
                }
            )
        return {
            "results": results,
            "applied": sum(1 for row in results if row["applied"]),
            "total": len(results),
        }

    # -- starting work ------------------------------------------------------

    def start_run(self, authorization: str | None, body: bytes) -> dict[str, Any]:
        """Begin a scan. The most authority this surface grants.

        `run_scan`, not `set_state`: the role that may spend is deliberately
        separate from the role that may adjudicate, and an analyst who can
        close a finding still cannot start a run.
        """
        principal = self.principal(authorization)
        self._guard(principal, Action.run_scan, spending=True)
        if self._runner is None:
            raise Problem(503, "starting runs is not enabled on this deployment")
        payload = self._payload(body)
        try:
            record = self._runner.start(principal, RunRequest.model_validate(payload))
        except ValidationError as exc:
            raise Problem(400, "invalid run request") from exc
        except ValueError as exc:
            raise Problem(400, "invalid run request") from exc
        except RuntimeError as exc:
            # A run already in progress for this target. 409, because the
            # request is well-formed and will succeed later — which is a
            # different thing to tell a caller than "you may not".
            raise Problem(409, "a run for this target is already in progress") from exc
        started: dict[str, Any] = record.model_dump(mode="json")
        return started

    def list_started_runs(self, authorization: str | None) -> dict[str, Any]:
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        if self._runner is None:
            return {"runs": [], "enabled": False}
        return {
            "runs": [record.model_dump(mode="json") for record in self._runner.list()],
            "enabled": True,
        }

    def started_run(self, authorization: str | None, record_id: str) -> dict[str, Any]:
        principal = self.principal(authorization)
        self._guard(principal, Action.view)
        if self._runner is None:
            raise Problem(503, "starting runs is not enabled on this deployment")
        record = self._runner.get(record_id)
        if record is None:
            raise Problem(404, "not found")
        dumped: dict[str, Any] = record.model_dump(mode="json")
        return dumped

    def request_poc(self, authorization: str | None, fingerprint: str) -> dict[str, Any]:
        """Draft a PoC for one finding, on an analyst's explicit request.

        A run drafts only for what came out critical; this is the other half of
        that rule, and it is a *write* in the sense that matters — it spends
        model budget — so it is authenticated, authorized and audited like one.
        503 rather than 404 when no drafter is configured: the route exists and
        the deployment has not wired it, which is an operator's problem to see
        and not a caller's to guess at.
        """
        principal = self.principal(authorization)
        self._guard(principal, Action.draft_poc, spending=True)
        if self._drafter is None:
            raise Problem(503, "drafting is not available")
        try:
            return self._drafter.draft(principal, fingerprint)
        except Problem:
            raise
        except Exception as exc:  # noqa: BLE001 - a drafting failure is not a 500 story
            logger.warning("poc drafting failed for %s: %s", fingerprint, exc)
            raise Problem(502, "drafting failed") from exc

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


#: Sent on every response. The console is a single self-contained page with no
#: external origin to reach, so the policy can be this tight: no third-party
#: script, no framing, no referrer. `'unsafe-inline'` covers the page's own
#: inline script and style, which is the price of shipping one file with no
#: build step — it does not admit anything from another origin.
SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
        "img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; "
        "base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def build_app(plane: ControlPlane, console_html: str | None = None) -> Any:
    """Mount the control plane as a Starlette ASGI application.

    Imported lazily and constructed here so the handlers above stay importable,
    and testable, without the web framework installed.

    ``console_html`` mounts the analyst console at ``/``. Passing nothing
    serves the API alone — a deployment that only wants the machine surface
    should not be made to serve a page it has no use for.
    """
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import HTMLResponse, JSONResponse
        from starlette.routing import Route
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "the HTTP surface requires the 'api' extra (starlette)"
        ) from exc

    def respond(handler: Callable[[Request], Awaitable[Any]]) -> Any:
        async def endpoint(request: Request) -> JSONResponse:
            try:
                return JSONResponse(await handler(request), headers=SECURITY_HEADERS)
            except Problem as problem:
                return JSONResponse(
                    {"error": problem.message}, problem.status, headers=SECURITY_HEADERS
                )

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

    async def request_poc(request: Request) -> Any:
        return plane.request_poc(
            request.headers.get("authorization"), request.path_params["fingerprint"]
        )

    async def list_findings(request: Request) -> Any:
        return plane.list_findings(
            request.headers.get("authorization"), request.query_params.get("run")
        )

    async def list_runs(request: Request) -> Any:
        return plane.list_runs(request.headers.get("authorization"))

    async def finding_detail(request: Request) -> Any:
        return plane.finding_detail(
            request.headers.get("authorization"),
            request.path_params["fingerprint"],
            request.query_params.get("run"),
        )

    async def decision_history(request: Request) -> Any:
        return plane.decision_history(
            request.headers.get("authorization"), request.path_params["fingerprint"]
        )

    async def set_states(request: Request) -> Any:
        return plane.set_states(
            request.headers.get("authorization"), await request.body()
        )

    async def start_run(request: Request) -> Any:
        return plane.start_run(
            request.headers.get("authorization"), await request.body()
        )

    async def list_started_runs(request: Request) -> Any:
        return plane.list_started_runs(request.headers.get("authorization"))

    async def started_run(request: Request) -> Any:
        return plane.started_run(
            request.headers.get("authorization"), request.path_params["record_id"]
        )

    async def public_config(request: Request) -> Any:
        return plane.public_config()

    async def healthz(request: Request) -> JSONResponse:
        # reveals nothing but liveness
        return JSONResponse({"status": "ok"}, headers=SECURITY_HEADERS)

    async def console(request: Request) -> HTMLResponse:
        return HTMLResponse(console_html or "", headers=SECURITY_HEADERS)

    routes = [
        Route("/healthz", healthz),
        Route("/api/config", respond(public_config)),
        Route("/api/whoami", respond(whoami)),
        Route("/api/runs", respond(list_runs)),
        Route("/api/scans", respond(list_started_runs)),
        Route("/api/scans", respond(start_run), methods=["POST"]),
        Route("/api/scans/{record_id}", respond(started_run)),
        Route("/api/findings", respond(list_findings)),
        Route("/api/findings/state", respond(set_states), methods=["POST"]),
        Route("/api/findings/{fingerprint}", respond(finding_detail)),
        Route("/api/findings/{fingerprint}/decision", respond(get_decision)),
        Route("/api/findings/{fingerprint}/history", respond(decision_history)),
        Route("/api/findings/{fingerprint}/state", respond(set_state), methods=["POST"]),
        Route("/api/findings/{fingerprint}/poc", respond(request_poc), methods=["POST"]),
    ]
    if console_html is not None:
        routes.append(Route("/", console))
    return Starlette(routes=routes)
