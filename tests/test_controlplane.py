"""The control plane: identity, authorization, and the write path together."""

from __future__ import annotations

from pathlib import Path

import pytest

from engagement.api import ApiConfig, ControlPlane, Problem
from engagement.auth import (
    AuthError,
    RoleMapping,
    StaticVerifier,
    authenticate,
    bearer_token,
    principal_from_claims,
)
from engagement.decisions import (
    Decision,
    DecisionError,
    JsonlDecisionStore,
    MemoryDecisionStore,
    record_decision,
    resolve_write,
)
from engagement.identity import (
    Principal,
    Role,
    Unauthorized,
    ValidationState,
    machine,
)

MAPPING = RoleMapping(
    mapping={
        "Engagement.Analyst": Role.analyst,
        "Engagement.Approver": Role.approver,
        "Engagement.Scanner": Role.scanner,
    }
)


def _claims(*roles: str, oid: str = "oid-1", tid: str = "acme") -> dict[str, object]:
    return {
        "oid": oid,
        "sub": "pairwise-1",
        "name": "Ada",
        "tid": tid,
        "roles": list(roles),
    }


class _Drafter:
    """A drafter that records who asked, and never calls a model."""

    def __init__(self, fail: bool = False) -> None:
        self.asked: list[tuple[str, str]] = []
        self._fail = fail

    def draft(self, principal: Principal, fingerprint: str) -> dict[str, object]:
        if self._fail:
            raise RuntimeError("the provider was unreachable")
        self.asked.append((principal.actor(), fingerprint))
        return {"finding_id": fingerprint, "drafted": True}


def _plane(
    drafter: _Drafter | None = None, **kwargs: object
) -> tuple[ControlPlane, MemoryDecisionStore]:
    store = MemoryDecisionStore()
    verifier = StaticVerifier(
        tokens={
            "analyst-token": _claims("Engagement.Analyst"),
            "approver-token": _claims(
                "Engagement.Analyst", "Engagement.Approver", oid="oid-2"
            ),
            "stranger-token": _claims(oid="oid-3"),
            "other-tenant": _claims("Engagement.Approver", oid="oid-4", tid="other"),
            "scanner-token": _claims("Engagement.Scanner", oid="oid-5"),
        }
    )
    config = ApiConfig(tenant="acme", **kwargs)  # type: ignore[arg-type]
    return ControlPlane(verifier, store, config, MAPPING, drafter), store


# -- authentication ---------------------------------------------------------


def test_a_bearer_header_must_actually_be_a_bearer_header() -> None:
    for bad in (None, "", "Basic abc", "Bearer", "Bearer   ", "token abc"):
        with pytest.raises(AuthError):
            bearer_token(bad)
    assert bearer_token("Bearer abc123") == "abc123"


def test_an_unverifiable_token_yields_no_principal() -> None:
    with pytest.raises(AuthError):
        authenticate("Bearer forged", StaticVerifier(), MAPPING)


def test_the_subject_prefers_the_stable_directory_id() -> None:
    """``sub`` is pairwise per-application; ``oid`` still names the same person
    after the application is re-registered."""
    principal = principal_from_claims(_claims("Engagement.Analyst"), MAPPING)
    assert principal.subject == "oid-1"


def test_unmapped_directory_values_grant_nothing() -> None:
    """Inferring authority from a group name that looks right is how a rename
    becomes a privilege escalation."""
    principal = principal_from_claims(_claims("security-approvers"), MAPPING)
    assert principal.roles == []


def test_a_token_without_a_subject_is_refused() -> None:
    with pytest.raises(AuthError, match="no subject"):
        principal_from_claims({"name": "nobody"}, MAPPING)


# -- the surface ------------------------------------------------------------


def test_every_authentication_failure_looks_the_same_to_the_caller() -> None:
    """A caller learning which check failed learns how close it is."""
    plane, _ = _plane()
    for header in (None, "Bearer forged", "Basic abc"):
        with pytest.raises(Problem) as excinfo:
            plane.whoami(header)
        assert excinfo.value.status == 401
        assert excinfo.value.message == "unauthorized"


def test_a_token_from_another_tenant_is_not_authenticated_here() -> None:
    plane, _ = _plane()
    with pytest.raises(Problem) as excinfo:
        plane.whoami("Bearer other-tenant")
    assert excinfo.value.status == 401


def test_whoami_reports_the_roles_actually_granted() -> None:
    plane, _ = _plane()
    assert plane.whoami("Bearer approver-token")["roles"] == ["analyst", "approver"]


def test_an_analyst_cannot_close_a_finding_through_the_api() -> None:
    plane, store = _plane()
    with pytest.raises(Problem) as excinfo:
        plane.set_state("Bearer analyst-token", "fp1", b'{"state":"risk_accepted"}')
    assert excinfo.value.status == 403
    assert store.get("fp1") is None  # nothing reached storage


def test_an_approver_can_close_a_finding() -> None:
    plane, store = _plane()
    result = plane.set_state(
        "Bearer approver-token", "fp1", b'{"state":"risk_accepted"}'
    )
    recorded = store.get("fp1")
    assert result["applied"]
    assert recorded is not None and recorded.actor == "oid-2"


def test_an_analyst_can_still_investigate() -> None:
    plane, _ = _plane()
    result = plane.set_state("Bearer analyst-token", "fp1", b'{"state":"confirmed"}')
    assert result["applied"]


def test_a_principal_with_no_roles_can_do_nothing() -> None:
    plane, _ = _plane()
    with pytest.raises(Problem) as excinfo:
        plane.whoami("Bearer stranger-token")
    assert excinfo.value.status == 403


def test_a_malformed_body_is_refused() -> None:
    plane, _ = _plane()
    with pytest.raises(Problem) as excinfo:
        plane.set_state("Bearer approver-token", "fp1", b"not json")
    assert excinfo.value.status == 400


def test_an_oversized_body_is_refused_before_it_is_parsed() -> None:
    plane, _ = _plane(max_body_bytes=32)
    with pytest.raises(Problem) as excinfo:
        plane.set_state("Bearer approver-token", "fp1", b'{"n":"' + b"x" * 64 + b'"}')
    assert excinfo.value.status == 413


def test_an_unknown_state_is_refused() -> None:
    plane, _ = _plane()
    with pytest.raises(Problem) as excinfo:
        plane.set_state("Bearer approver-token", "fp1", b'{"state":"deleted"}')
    assert excinfo.value.status == 400


# -- the overwrite rule -----------------------------------------------------


def _human(subject: str = "oid-2") -> Principal:
    return Principal(subject=subject, roles=[Role.approver], tenant="acme")


def test_a_machine_never_overwrites_a_human_decision() -> None:
    human = Decision.by(_human(), "fp1", ValidationState.confirmed)
    proposal = Decision.by(machine(), "fp1", ValidationState.under_investigation)
    assert resolve_write(human, proposal) is human


def test_a_machine_never_reopens_a_terminal_state() -> None:
    closed = Decision.by(_human(), "fp1", ValidationState.risk_accepted)
    proposal = Decision.by(machine(), "fp1", ValidationState.new)
    assert resolve_write(closed, proposal) is closed


def test_a_machine_proposal_of_a_terminal_state_is_structurally_refused() -> None:
    """Belt and braces: authorization refuses it, and the overwrite rule
    refuses it again without consulting authorization."""
    proposal = Decision(
        fingerprint="fp1",
        state=ValidationState.resolved,
        actor="machine:x",
        machine=True,
    )
    with pytest.raises(DecisionError):
        resolve_write(None, proposal)


def test_a_human_may_override_another_human() -> None:
    first = Decision.by(_human("a"), "fp1", ValidationState.confirmed)
    second = Decision.by(_human("b"), "fp1", ValidationState.resolved)
    assert resolve_write(first, second) is second


def test_a_machine_may_advance_its_own_earlier_proposal() -> None:
    first = Decision.by(machine(), "fp1", ValidationState.new)
    second = Decision.by(machine(), "fp1", ValidationState.under_investigation)
    assert resolve_write(first, second) is second


def test_recording_requires_authorization_before_storage() -> None:
    store = MemoryDecisionStore()
    analyst = Principal(subject="oid-1", roles=[Role.analyst], tenant="acme")
    with pytest.raises(Unauthorized):
        record_decision(analyst, store, "fp1", ValidationState.duplicate)
    assert store.get("fp1") is None


# -- the log ----------------------------------------------------------------


def test_the_decision_log_keeps_history_not_just_current_state(tmp_path: Path) -> None:
    """Who closed this, and when, is asked about findings that are currently
    open — which an overwriting store cannot answer."""
    store = JsonlDecisionStore(tmp_path / "decisions.jsonl")
    approver = _human()
    record_decision(approver, store, "fp1", ValidationState.confirmed)
    record_decision(approver, store, "fp1", ValidationState.resolved)

    current = store.get("fp1")
    assert current is not None and current.state is ValidationState.resolved
    assert [d.state.value for d in store.history("fp1")] == ["confirmed", "resolved"]


def test_a_corrupt_line_is_an_error_not_a_skip(tmp_path: Path) -> None:
    """Silently dropping a line loses a decision, which is the one thing this
    file exists to never do."""
    path = tmp_path / "decisions.jsonl"
    path.write_text('{"not":"a decision"}\n', encoding="utf-8")
    with pytest.raises(DecisionError):
        JsonlDecisionStore(path).get("fp1")


# -- requesting a PoC -------------------------------------------------------


def test_an_analyst_can_request_a_draft_for_a_finding_the_run_passed_over() -> None:
    drafter = _Drafter()
    plane, _ = _plane(drafter)

    result = plane.request_poc("Bearer analyst-token", "fp1")

    assert result["drafted"] is True
    assert drafter.asked == [("oid-1", "fp1")], "the request lost who made it"


def test_requesting_a_draft_without_a_credential_is_refused() -> None:
    drafter = _Drafter()
    plane, _ = _plane(drafter)

    with pytest.raises(Problem) as exc:
        plane.request_poc(None, "fp1")

    assert exc.value.status == 401
    assert drafter.asked == [], "an unauthenticated caller reached the model budget"


def test_a_principal_without_a_queue_role_may_not_spend_on_drafts() -> None:
    """A scanner runs scans; asking for a draft outside the critical set is a
    judgement about the queue, which is an analyst's call and not a runner's."""
    drafter = _Drafter()
    plane, _ = _plane(drafter)

    with pytest.raises(Problem) as exc:
        plane.request_poc("Bearer scanner-token", "fp1")

    assert exc.value.status == 403
    assert drafter.asked == []


def test_a_deployment_with_no_drafter_says_so_rather_than_404ing() -> None:
    plane, _ = _plane(None)

    with pytest.raises(Problem) as exc:
        plane.request_poc("Bearer analyst-token", "fp1")

    assert exc.value.status == 503


def test_a_drafting_failure_is_not_reported_as_a_server_fault() -> None:
    plane, _ = _plane(_Drafter(fail=True))

    with pytest.raises(Problem) as exc:
        plane.request_poc("Bearer analyst-token", "fp1")

    assert exc.value.status == 502
    assert "unreachable" not in exc.value.message, "the failure leaked outward"
