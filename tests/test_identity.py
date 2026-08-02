"""Authorization: the referent for the word "human" in the core invariant."""

from __future__ import annotations

import pytest

from engagement.identity import (
    Action,
    Principal,
    Role,
    Unauthorized,
    ValidationState,
    authorize,
    machine,
    operator,
)

ANALYST = Principal(subject="oid-1", roles=[Role.analyst], tenant="acme")
APPROVER = Principal(subject="oid-2", roles=[Role.analyst, Role.approver], tenant="acme")
SCANNER = Principal(subject="oid-3", roles=[Role.scanner], tenant="acme")
ADMIN = Principal(subject="oid-4", roles=[Role.admin], tenant="acme")


def test_a_machine_may_never_set_a_terminal_state() -> None:
    """The estate's oldest invariant, now enforced against an identity rather
    than a self-declared actor string."""
    with pytest.raises(Unauthorized, match="machine actor"):
        authorize(machine(), Action.set_state, ValidationState.risk_accepted)


def test_a_machine_may_set_the_non_terminal_states_it_proposes() -> None:
    authorize(machine(), Action.set_state, ValidationState.under_investigation)
    authorize(machine(), Action.set_state, ValidationState.new)


def test_an_unattended_run_may_scan_but_not_adjudicate() -> None:
    """The whole point of running it unattended."""
    authorize(machine(), Action.run_scan)
    with pytest.raises(Unauthorized):
        authorize(machine(), Action.set_state, ValidationState.confirmed)


def test_a_run_may_not_authorise_its_own_exception_to_the_critical_rule() -> None:
    """A run drafts for what came out critical and stops. If it could also ask
    for the rest, the rule would not exist — so the machine actor is refused
    here even though it is exactly the actor that spends on every other stage."""
    with pytest.raises(Unauthorized, match="machine actor"):
        authorize(machine(), Action.draft_poc)


def test_a_machine_holding_every_role_is_still_refused_a_requested_draft() -> None:
    """Derived from the subject, not the role set: a role can be granted by
    mistake, while the subject is minted by whatever issued the credential."""
    over_privileged = Principal(subject="machine:runner", roles=list(Role))
    with pytest.raises(Unauthorized):
        authorize(over_privileged, Action.draft_poc)


def test_the_people_who_work_the_queue_may_request_a_draft() -> None:
    authorize(ANALYST, Action.draft_poc)
    authorize(APPROVER, Action.draft_poc)
    authorize(ADMIN, Action.draft_poc)


def test_a_scanner_may_run_scans_and_not_request_drafts() -> None:
    with pytest.raises(Unauthorized):
        authorize(SCANNER, Action.draft_poc)


def test_a_cli_operator_must_be_named() -> None:
    """A default would put an unattributable action in the trail and make it
    read like an attributable one."""
    for blank in ("", "   "):
        with pytest.raises(Unauthorized):
            operator(blank)


def test_a_cli_operator_may_ask_for_work_and_still_not_close_a_finding() -> None:
    """Identity on a shell is asserted, not verified. It buys the ability to
    spend, never the ability to end review."""
    ada = operator("ada")

    assert not ada.is_machine
    authorize(ada, Action.draft_poc)
    with pytest.raises(Unauthorized):
        authorize(ada, Action.set_state, ValidationState.risk_accepted)


def test_an_analyst_may_investigate_but_not_close() -> None:
    """A terminal state asserts nobody needs to look again; letting whoever
    triages also close is how a queue quietly empties itself."""
    authorize(ANALYST, Action.set_state, ValidationState.confirmed)
    with pytest.raises(Unauthorized, match="requires the approver role"):
        authorize(ANALYST, Action.set_state, ValidationState.false_positive)


def test_an_approver_may_close() -> None:
    for state in (
        ValidationState.false_positive,
        ValidationState.risk_accepted,
        ValidationState.duplicate,
        ValidationState.resolved,
    ):
        authorize(APPROVER, Action.set_state, state)


def test_a_scanner_may_not_set_states_at_all() -> None:
    with pytest.raises(Unauthorized):
        authorize(SCANNER, Action.set_state, ValidationState.confirmed)


def test_admin_subsumes_every_role() -> None:
    authorize(ADMIN, Action.run_scan)
    authorize(ADMIN, Action.set_state, ValidationState.risk_accepted)


def test_a_state_change_must_name_its_state() -> None:
    with pytest.raises(Unauthorized, match="must name the state"):
        authorize(APPROVER, Action.set_state)


def test_a_principal_cannot_act_across_tenants() -> None:
    with pytest.raises(Unauthorized, match="cannot act on"):
        authorize(APPROVER, Action.view, tenant="other-corp")


def test_a_principal_with_no_roles_cannot_even_view() -> None:
    with pytest.raises(Unauthorized, match="holds no roles"):
        authorize(Principal(subject="oid-9"), Action.view)


def test_authorization_raises_rather_than_returning_a_flag() -> None:
    """A caller that forgets to check a returned boolean fails open, and this
    is the one decision where failing open means anonymous closure."""
    assert authorize(APPROVER, Action.view) is None


def test_machine_identity_comes_from_the_subject_not_the_role_set() -> None:
    """A role can be granted by mistake; the subject is minted at issuance."""
    impostor = Principal(subject="machine:sneaky", roles=[Role.admin])
    assert impostor.is_machine
    with pytest.raises(Unauthorized, match="machine actor"):
        authorize(impostor, Action.set_state, ValidationState.resolved)
