"""Work claims: exclusion, expiry, and bounded retries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from engagement.claims import Claim, ClaimStatus, MemoryClaimStore

BATCH = "nightly-2026-08-01"
REPOS = ["acme/api", "acme/web", "acme/worker"]


def _store(**kwargs: object) -> MemoryClaimStore:
    store = MemoryClaimStore(**kwargs)  # type: ignore[arg-type]
    store.seed(BATCH, REPOS)
    return store


def test_two_workers_never_hold_the_same_repo() -> None:
    """The property the whole mechanism exists for."""
    store = _store()
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda n: store.acquire(BATCH, f"w{n}"), range(8)))

    held = [claim.repo for claim in claims if claim is not None]
    assert sorted(held) == sorted(REPOS)  # each repo claimed exactly once
    assert len(held) == len(set(held))
    assert claims.count(None) == 5  # the rest stepped over held rows


def test_an_expired_lease_returns_the_repo_to_the_queue() -> None:
    """A worker that dies must not strand its repo forever."""
    store = _store()
    first = store.acquire(BATCH, "w1", lease_seconds=3600)
    assert first is not None

    # the worker dies; its lease runs out
    store.claims[(BATCH, first.repo)].leased_until = datetime.now(UTC) - timedelta(seconds=1)

    reclaimed = [store.acquire(BATCH, "w2") for _ in range(3)]
    assert first.repo in [claim.repo for claim in reclaimed if claim]


def test_a_completed_repo_is_never_handed_out_again() -> None:
    store = _store()
    claim = store.acquire(BATCH, "w1")
    assert claim is not None
    store.complete(claim)

    seen = set()
    while (nxt := store.acquire(BATCH, "w2")) is not None:
        seen.add(nxt.repo)
    assert claim.repo not in seen


def test_a_repo_that_fails_every_time_is_failed_not_leased_forever() -> None:
    """Bounded retries: a repo that cannot be cloned must stop consuming
    workers rather than cycling through them."""
    store = _store(max_attempts=2)
    for _ in range(6):
        claim = store.acquire(BATCH, "w1")
        if claim is None:
            break
        store.release(claim, detail="clone failed")

    stats = store.stats(BATCH)
    assert stats.failed == len(REPOS)
    assert stats.is_drained()


def test_a_transient_failure_is_retried_while_attempts_remain() -> None:
    store = _store(max_attempts=3)
    claim = store.acquire(BATCH, "w1")
    assert claim is not None
    store.release(claim, detail="network blip")

    assert store.claims[(BATCH, claim.repo)].status is ClaimStatus.pending
    again = store.acquire(BATCH, "w2")
    assert again is not None


def test_stats_report_what_is_left_not_only_what_succeeded() -> None:
    store = _store()
    done = store.acquire(BATCH, "w1")
    assert done is not None
    store.complete(done)
    store.acquire(BATCH, "w2")

    stats = store.stats(BATCH)
    assert stats.total == 3
    assert stats.done == 1 and stats.claimed == 1 and stats.pending == 1
    assert stats.outstanding == 2
    assert not stats.is_drained()


def test_reseeding_a_batch_never_resets_work_already_done() -> None:
    store = _store()
    claim = store.acquire(BATCH, "w1")
    assert claim is not None
    store.complete(claim)

    added = store.seed(BATCH, REPOS)
    assert added == 0
    assert store.stats(BATCH).done == 1


def test_an_unheld_claim_is_ignored_rather_than_creating_one() -> None:
    store = _store()
    store.complete(Claim(batch_id=BATCH, repo="acme/ghost"))
    assert store.stats(BATCH).total == 3
