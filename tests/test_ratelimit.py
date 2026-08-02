"""Rate limiting: R25, closed.

The tests that matter are the ones about *which* limit applies and *when it is
checked*, not the arithmetic. A limiter checked before authorization becomes an
oracle for what a principal would be allowed to do; a single limit shared by
reading and spending is either useless for one or absurd for the other.
"""

from __future__ import annotations

import pytest

from engagement.api import ApiConfig, ControlPlane, Problem
from engagement.auth import RoleMapping, StaticVerifier
from engagement.decisions import MemoryDecisionStore
from engagement.identity import Role
from engagement.ratelimit import RateLimited, RateLimiter, RateLimits

MAPPING = RoleMapping(
    mapping={
        "Engagement.Analyst": Role.analyst,
        "Engagement.Scanner": Role.scanner,
    }
)


def _limiter(**kwargs: int) -> RateLimiter:
    return RateLimiter(RateLimits(burst=1.0, **kwargs))  # type: ignore[arg-type]


# -- the buckets -------------------------------------------------------------


def test_a_caller_within_its_allowance_is_never_refused() -> None:
    limiter = _limiter(requests_per_minute=60)
    for _ in range(60):
        limiter.check("ada")


def test_a_caller_past_its_allowance_is_refused() -> None:
    limiter = _limiter(requests_per_minute=5)
    for _ in range(5):
        limiter.check("ada")

    with pytest.raises(RateLimited):
        limiter.check("ada")


def test_the_refusal_says_how_long_to_wait() -> None:
    """A 429 with no retry hint invites an immediate retry that also fails."""
    limiter = _limiter(requests_per_minute=1)
    limiter.check("ada")

    with pytest.raises(RateLimited) as exc:
        limiter.check("ada")

    assert exc.value.retry_after >= 1


def test_one_caller_cannot_exhaust_anothers_allowance() -> None:
    """Per principal, not per process: a token is what authority attaches to."""
    limiter = _limiter(requests_per_minute=2)
    limiter.check("ada")
    limiter.check("ada")

    limiter.check("grace")  # must not raise


def test_spending_has_its_own_much_smaller_allowance() -> None:
    """One limit for reading and spending is too loose for the expensive path
    or absurd for the cheap one."""
    limiter = _limiter(requests_per_minute=100, spending_per_minute=2)
    limiter.check("ada", spending=True)
    limiter.check("ada", spending=True)

    with pytest.raises(RateLimited):
        limiter.check("ada", spending=True)


def test_exhausting_the_spending_budget_leaves_reading_working() -> None:
    """The behaviour you want when the expensive path is the one being abused:
    the analyst can still read and adjudicate."""
    limiter = _limiter(requests_per_minute=100, spending_per_minute=1)
    limiter.check("ada", spending=True)
    with pytest.raises(RateLimited):
        limiter.check("ada", spending=True)

    limiter.check("ada")  # reading still allowed


def test_a_spending_call_also_costs_a_general_request() -> None:
    """A request that costs money is also a request."""
    limiter = _limiter(requests_per_minute=2, spending_per_minute=100)
    limiter.check("ada", spending=True)
    limiter.check("ada", spending=True)

    with pytest.raises(RateLimited):
        limiter.check("ada")


def test_the_principal_map_cannot_itself_become_the_exhaustion_vector() -> None:
    """A stream of distinct subjects would otherwise grow it without bound,
    turning a control against resource exhaustion into a means of it."""
    limiter = _limiter(requests_per_minute=10)
    for n in range(RateLimiter.MAX_PRINCIPALS + 500):
        limiter.check(f"subject-{n}")

    assert len(limiter._seen) <= RateLimiter.MAX_PRINCIPALS


# -- where it sits in the request ---------------------------------------------


def _plane(limiter: RateLimiter) -> ControlPlane:
    verifier = StaticVerifier(
        tokens={
            "analyst": {"oid": "oid-1", "sub": "s", "tid": "acme",
                        "roles": ["Engagement.Analyst"]},
            "stranger": {"oid": "oid-2", "sub": "s", "tid": "acme", "roles": []},
        }
    )
    return ControlPlane(
        verifier, MemoryDecisionStore(), ApiConfig(tenant="acme"), MAPPING,
        limiter=limiter,
    )


def test_an_over_limit_caller_gets_429() -> None:
    plane = _plane(_limiter(requests_per_minute=1))
    plane.whoami("Bearer analyst")

    with pytest.raises(Problem) as exc:
        plane.whoami("Bearer analyst")

    assert exc.value.status == 429


def test_authorization_is_answered_before_the_limit() -> None:
    """Answering "slow down" to something that will never be allowed tells the
    caller to keep trying, and turns the limiter into an oracle."""
    plane = _plane(_limiter(requests_per_minute=1))

    for _ in range(3):
        with pytest.raises(Problem) as exc:
            plane.whoami("Bearer stranger")
        assert exc.value.status == 403, "a forbidden caller was told to retry"


def test_an_unauthenticated_caller_never_reaches_the_limiter() -> None:
    """401 costs no allowance: a caller with no credential has no principal to
    charge, and charging one would let anyone exhaust a stranger's bucket."""
    plane = _plane(_limiter(requests_per_minute=1))
    for _ in range(5):
        with pytest.raises(Problem) as exc:
            plane.whoami(None)
        assert exc.value.status == 401
