"""Sharing one repo list across several hosts, without an orchestrator.

A worker leases a repo, scans it, and marks it done. Another worker stepping
over a held row rather than blocking on it is what turns a list into a work
queue, and a lease that *expires* is what stops a worker dying mid-scan from
stranding its repo forever.

The transactional version of this lives in the database already run for state
and the index — ``SELECT ... FOR UPDATE SKIP LOCKED`` is the whole mechanism,
and it is why the store is relational rather than a document collection. This
module is the port onto it, with an in-memory implementation the gate can drive
deterministically.

Three properties matter more than throughput, and each has a test named after
it: two workers never hold the same repo; an expired lease returns the repo to
the queue; and a repo that fails every time is marked failed rather than leased
forever.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
from threading import Lock
from typing import Protocol

from .contracts import StrictModel

DEFAULT_LEASE_SECONDS = 3600
DEFAULT_MAX_ATTEMPTS = 3


class ClaimStatus(str, Enum):
    pending = "pending"
    claimed = "claimed"
    done = "done"
    failed = "failed"


class Claim(StrictModel):
    batch_id: str
    repo: str
    status: ClaimStatus = ClaimStatus.pending
    worker: str = ""
    leased_until: datetime | None = None
    attempts: int = 0
    detail: str = ""

    def is_available(self, now: datetime) -> bool:
        """Pending, or claimed by a worker whose lease has run out."""
        if self.status is ClaimStatus.pending:
            return True
        if self.status is ClaimStatus.claimed:
            return self.leased_until is None or self.leased_until <= now
        return False


class ClaimStats(StrictModel):
    """The denominator for a batch: what is left, not just what succeeded."""

    total: int = 0
    pending: int = 0
    claimed: int = 0
    done: int = 0
    failed: int = 0

    @property
    def outstanding(self) -> int:
        return self.pending + self.claimed

    def is_drained(self) -> bool:
        return self.outstanding == 0


class ClaimStore(Protocol):
    def seed(self, batch_id: str, repos: list[str]) -> int: ...

    def acquire(
        self, batch_id: str, worker: str, lease_seconds: int = DEFAULT_LEASE_SECONDS
    ) -> Claim | None: ...

    def complete(self, claim: Claim) -> None: ...

    def release(self, claim: Claim, detail: str = "") -> None: ...

    def stats(self, batch_id: str) -> ClaimStats: ...


class MemoryClaimStore:
    """In-process store. Correct for one host, and the gate's driver.

    A plain class rather than a model: it owns a lock and mutable shared state,
    neither of which is data worth validating. The lock is what makes concurrent
    workers in the same process observe the exclusion the database provides
    across hosts — without it the tests would pass while proving nothing about
    the property they name.
    """

    def __init__(self, max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> None:
        self.claims: dict[tuple[str, str], Claim] = {}
        self.max_attempts = max_attempts
        self._lock = Lock()

    def seed(self, batch_id: str, repos: list[str]) -> int:
        """Register a batch. Re-seeding never resets work already done."""
        added = 0
        with self._lock:
            for repo in repos:
                key = (batch_id, repo)
                if key not in self.claims:
                    self.claims[key] = Claim(batch_id=batch_id, repo=repo)
                    added += 1
        return added

    def acquire(
        self, batch_id: str, worker: str, lease_seconds: int = DEFAULT_LEASE_SECONDS
    ) -> Claim | None:
        now = datetime.now(UTC)
        with self._lock:
            for key in sorted(self.claims):
                if key[0] != batch_id:
                    continue
                claim = self.claims[key]
                if not claim.is_available(now):
                    continue
                if claim.attempts >= self.max_attempts:
                    # bounded retries: a repo that fails to clone every time
                    # must not be leased forever
                    claim.status = ClaimStatus.failed
                    claim.detail = claim.detail or "attempt limit reached"
                    continue
                claim.status = ClaimStatus.claimed
                claim.worker = worker
                claim.attempts += 1
                claim.leased_until = now + timedelta(seconds=lease_seconds)
                return claim.model_copy(deep=True)
        return None

    def complete(self, claim: Claim) -> None:
        with self._lock:
            held = self.claims.get((claim.batch_id, claim.repo))
            if held is None:
                return
            held.status = ClaimStatus.done
            held.leased_until = None

    def release(self, claim: Claim, detail: str = "") -> None:
        """Hand a repo back after a failed attempt.

        Returned to ``pending`` rather than ``failed`` while attempts remain,
        so a transient clone failure is retried and a permanent one is not.
        """
        with self._lock:
            held = self.claims.get((claim.batch_id, claim.repo))
            if held is None:
                return
            held.detail = detail
            held.leased_until = None
            held.worker = ""
            held.status = (
                ClaimStatus.failed
                if held.attempts >= self.max_attempts
                else ClaimStatus.pending
            )

    def stats(self, batch_id: str) -> ClaimStats:
        now = datetime.now(UTC)
        stats = ClaimStats()
        with self._lock:
            for key, claim in self.claims.items():
                if key[0] != batch_id:
                    continue
                stats.total += 1
                if claim.status is ClaimStatus.done:
                    stats.done += 1
                elif claim.status is ClaimStatus.failed:
                    stats.failed += 1
                elif claim.is_available(now):
                    stats.pending += 1
                else:
                    stats.claimed += 1
        return stats


#: Schema for the shared store. Mirrors the platform's existing claim table so
#: one database serves both, rather than each growing its own queue.
POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement_claim (
    batch_id     TEXT        NOT NULL,
    repo         TEXT        NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'pending',
    worker       TEXT        NOT NULL DEFAULT '',
    leased_until TIMESTAMPTZ,
    attempts     INTEGER     NOT NULL DEFAULT 0,
    detail       TEXT        NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (batch_id, repo)
);

CREATE INDEX IF NOT EXISTS engagement_claim_available
    ON engagement_claim (batch_id, status, leased_until);
"""

#: The claim itself. ``FOR UPDATE`` serializes the row and ``SKIP LOCKED`` lets
#: another worker step over a held one instead of queueing behind it — together
#: they are the entire multi-host mechanism, with no orchestrator above them.
_ACQUIRE_SQL = """
UPDATE engagement_claim SET
    status = 'claimed',
    worker = %(worker)s,
    attempts = attempts + 1,
    leased_until = now() + make_interval(secs => %(lease)s),
    updated_at = now()
WHERE (batch_id, repo) = (
    SELECT batch_id, repo FROM engagement_claim
    WHERE batch_id = %(batch)s
      AND attempts < %(max_attempts)s
      AND (status = 'pending' OR (status = 'claimed' AND leased_until <= now()))
    ORDER BY repo
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING batch_id, repo, status, worker, leased_until, attempts, detail;
"""


class PostgresClaimStore:
    """Shared store for several hosts. ``psycopg`` imported lazily."""

    def __init__(self, dsn: str, max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> None:
        self._dsn = dsn
        self.max_attempts = max_attempts

    def _connect(self) -> object:
        import psycopg  # lazy: optional extra

        return psycopg.connect(self._dsn, autocommit=True)

    def migrate(self) -> None:
        with self._connect() as conn:  # type: ignore[attr-defined]
            conn.execute(POSTGRES_SCHEMA)

    def seed(self, batch_id: str, repos: list[str]) -> int:
        added = 0
        with self._connect() as conn:  # type: ignore[attr-defined]
            for repo in repos:
                cursor = conn.execute(
                    "INSERT INTO engagement_claim (batch_id, repo) VALUES (%s, %s) "
                    "ON CONFLICT (batch_id, repo) DO NOTHING",
                    (batch_id, repo),
                )
                added += cursor.rowcount or 0
        return added

    def acquire(
        self, batch_id: str, worker: str, lease_seconds: int = DEFAULT_LEASE_SECONDS
    ) -> Claim | None:
        with self._connect() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                _ACQUIRE_SQL,
                {
                    "worker": worker,
                    "lease": lease_seconds,
                    "batch": batch_id,
                    "max_attempts": self.max_attempts,
                },
            ).fetchone()
        if row is None:
            return None
        return Claim(
            batch_id=row[0],
            repo=row[1],
            status=ClaimStatus(row[2]),
            worker=row[3],
            leased_until=row[4],
            attempts=row[5],
            detail=row[6],
        )

    def complete(self, claim: Claim) -> None:
        with self._connect() as conn:  # type: ignore[attr-defined]
            conn.execute(
                "UPDATE engagement_claim SET status='done', leased_until=NULL, "
                "updated_at=now() WHERE batch_id=%s AND repo=%s",
                (claim.batch_id, claim.repo),
            )

    def release(self, claim: Claim, detail: str = "") -> None:
        with self._connect() as conn:  # type: ignore[attr-defined]
            conn.execute(
                "UPDATE engagement_claim SET "
                "status = CASE WHEN attempts >= %s THEN 'failed' ELSE 'pending' END, "
                "worker='', leased_until=NULL, detail=%s, updated_at=now() "
                "WHERE batch_id=%s AND repo=%s",
                (self.max_attempts, detail, claim.batch_id, claim.repo),
            )

    def stats(self, batch_id: str) -> ClaimStats:
        with self._connect() as conn:  # type: ignore[attr-defined]
            rows = conn.execute(
                "SELECT status, count(*), "
                "count(*) FILTER (WHERE leased_until <= now()) "
                "FROM engagement_claim WHERE batch_id=%s GROUP BY status",
                (batch_id,),
            ).fetchall()
        stats = ClaimStats()
        for status, count, expired in rows:
            stats.total += count
            if status == "done":
                stats.done += count
            elif status == "failed":
                stats.failed += count
            elif status == "pending":
                stats.pending += count
            else:
                stats.pending += expired
                stats.claimed += count - expired
        return stats
