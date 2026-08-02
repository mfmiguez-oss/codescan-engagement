"""Who may do what.

The estate's central invariant is that a machine proposal never overwrites a
human decision and never sets a terminal state. That rule is only as strong as
the word "human" in it, and until now "human" was an unauthenticated actor
string — anything that could write to the store could claim to be one.

This module gives that word a referent. A :class:`Principal` carries a stable
subject from the identity provider (an Entra object id, an IAM principal), the
roles granted to it, and the tenant it belongs to. Authorization is a pure
function over those, so it is testable offline and identical whichever provider
issued the token.

Three roles fall out of the invariants rather than being invented for
symmetry:

- **scanner** may spend budget and run scans, and nothing else.
- **analyst** may investigate — the non-terminal states.
- **approver** may close a finding — the terminal states, which are the ones
  that end review and therefore the ones worth a second person.

Separating the last two is the point. A terminal state is an assertion that
nobody needs to look again; letting whoever triages also close is how a queue
quietly empties itself.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .contracts import StrictModel


class Role(str, Enum):
    scanner = "scanner"
    analyst = "analyst"
    approver = "approver"
    admin = "admin"


class Action(str, Enum):
    view = "view"
    run_scan = "run_scan"
    set_state = "set_state"
    export = "export"
    #: Ask for a PoC draft against a finding the automatic rule passed over.
    draft_poc = "draft_poc"


class ValidationState(str, Enum):
    """Mirrors the triage backbone's states, so authorization can reason about
    them without importing an optional dependency."""

    new = "new"
    under_investigation = "under_investigation"
    confirmed = "confirmed"
    false_positive = "false_positive"
    risk_accepted = "risk_accepted"
    duplicate = "duplicate"
    resolved = "resolved"


#: States that end review. Human-only, and approver-only among humans.
TERMINAL_STATES: frozenset[ValidationState] = frozenset(
    {
        ValidationState.false_positive,
        ValidationState.risk_accepted,
        ValidationState.duplicate,
        ValidationState.resolved,
    }
)

#: The only states a machine actor may ever set.
MACHINE_STATES: frozenset[ValidationState] = frozenset(
    {ValidationState.new, ValidationState.under_investigation}
)

MACHINE_SUBJECT_PREFIX = "machine:"


class Unauthorized(PermissionError):
    """The principal may not take this action. Never a silent no-op."""


class Principal(StrictModel):
    """An authenticated actor. Built from a verified token, never from input."""

    subject: str
    display: str = ""
    roles: list[Role] = Field(default_factory=list)
    tenant: str = ""

    @property
    def is_machine(self) -> bool:
        """Machine actors are named as such at issuance.

        Derived from the subject rather than the role set, because a role can
        be granted by mistake while the subject is minted by whatever issued
        the credential.
        """
        return self.subject.startswith(MACHINE_SUBJECT_PREFIX)

    def has(self, role: Role) -> bool:
        return role in self.roles or Role.admin in self.roles

    def actor(self) -> str:
        """The string recorded on a decision. Identity, not a display name."""
        return self.subject


def machine(name: str = "engagement") -> Principal:
    """The principal an unattended run acts as.

    It holds ``scanner`` and nothing else: a run may spend budget and record
    findings, and may not adjudicate them. That is the whole point of running
    it unattended.
    """
    return Principal(
        subject=f"{MACHINE_SUBJECT_PREFIX}{name}",
        display=f"{name} (unattended)",
        roles=[Role.scanner],
    )


def operator(name: str) -> Principal:
    """The principal a CLI invocation acts as.

    **Asserted, not verified.** On a shell there is no token to check, and the
    honest thing is to record who claimed to be there rather than to mint a
    principal that looks as trustworthy as one the control plane proved. The
    name is required for exactly that reason: a default would put an
    unattributable action in the trail and read like an attributable one.

    It carries ``analyst`` and never ``approver``, so the unverified path can
    ask for work to be done and still cannot close a finding. The states that
    end review stay behind the control plane, which is the only place identity
    is actually proven.
    """
    subject = name.strip()
    if not subject:
        raise Unauthorized(
            "a CLI action must name the operator taking it — set "
            "ENGAGEMENT_OPERATOR so the audit trail can attribute it"
        )
    return Principal(
        subject=f"operator:{subject}",
        display=f"{subject} (cli, unverified)",
        roles=[Role.analyst],
    )


def authorize(
    principal: Principal,
    action: Action,
    state: ValidationState | None = None,
    tenant: str | None = None,
) -> None:
    """Raise unless ``principal`` may take ``action``.

    Raising rather than returning a boolean is deliberate: a caller that
    forgets to check a returned flag fails open, and this is the one decision
    in the system where failing open means an unauthenticated actor closing
    findings.
    """
    if tenant and principal.tenant and principal.tenant != tenant:
        raise Unauthorized(
            f"{principal.subject} belongs to tenant {principal.tenant!r} and "
            f"cannot act on {tenant!r}"
        )

    if action is Action.view:
        if not principal.roles:
            raise Unauthorized(f"{principal.subject} holds no roles")
        return

    if action is Action.run_scan:
        if not principal.has(Role.scanner):
            raise Unauthorized(f"{principal.subject} may not run scans")
        return

    if action is Action.export:
        if not (principal.has(Role.analyst) or principal.has(Role.scanner)):
            raise Unauthorized(f"{principal.subject} may not export findings")
        return

    if action is Action.draft_poc:
        # A run drafts for what came out critical and stops. Everything below
        # that is drafted because a person judged the rule wrong about one
        # finding — so a machine actor is refused here even holding every role.
        # An unattended run that could authorise its own exceptions has no rule.
        if principal.is_machine:
            raise Unauthorized(
                f"{principal.subject} is a machine actor: a PoC outside the "
                "critical set is drafted on a person's request, never on a run's"
            )
        if not (principal.has(Role.analyst) or principal.has(Role.approver)):
            raise Unauthorized(f"{principal.subject} may not request PoC drafts")
        return

    if action is Action.set_state:
        if state is None:
            raise Unauthorized("a state change must name the state it sets")
        _authorize_state(principal, state)
        return

    raise Unauthorized(f"unknown action {action!r}")  # pragma: no cover


def _authorize_state(principal: Principal, state: ValidationState) -> None:
    if principal.is_machine:
        # the estate's oldest invariant, now enforced against an identity
        # rather than against a self-declared actor string
        if state not in MACHINE_STATES:
            raise Unauthorized(
                f"{principal.subject} is a machine actor and may only set "
                f"{sorted(item.value for item in MACHINE_STATES)}, not {state.value!r}"
            )
        return
    if state in TERMINAL_STATES:
        if not principal.has(Role.approver):
            raise Unauthorized(
                f"{principal.subject} may investigate but not close: {state.value!r} "
                "ends review and requires the approver role"
            )
        return
    if not (principal.has(Role.analyst) or principal.has(Role.approver)):
        raise Unauthorized(f"{principal.subject} may not set validation states")
