"""Bounding what one caller can make the control plane do.

Risk R25, open since the control plane was written: a valid token could call it
as fast as it liked. That mattered little while every route was a read against
a small file. It matters now — one route drafts a proof of concept and another
starts a scan, and both spend money.

## Per principal, not per address

A token is the thing authority is attached to, so it is the thing a limit
should follow. Limiting by source address instead would put every analyst
behind one office NAT into a shared bucket while doing nothing at all about a
credential used from many places.

## Two buckets, because two costs

Reading the queue and starting a run are not the same act, and one limit for
both is either too loose for the expensive one or absurd for the cheap one. So
spending routes carry their own, much smaller allowance, checked *in addition*
to the general one — an analyst who exhausts their drafting budget can still
read and adjudicate, which is the behaviour you want when the expensive path is
the one being abused.

## Deliberately in-process

No Redis, no shared state, no dependency. This bounds one process, which is
what a single-analyst console and a small deployment behind an ingress
actually need. A multi-replica deployment must still put a real limiter at the
ingress, and [DEPLOYMENT.md](../../docs/DEPLOYMENT.md) says so rather than this
module pretending otherwise: a per-process limit across four replicas is four
times the limit, and quietly.
"""

from __future__ import annotations

import time
from threading import Lock

from .contracts import StrictModel


class RateLimited(RuntimeError):
    """The caller has spent its allowance. Carries how long until it has more."""

    def __init__(self, retry_after: float) -> None:
        # Rounded up: telling a caller to retry in zero seconds when the bucket
        # is empty invites an immediate retry that also fails.
        self.retry_after = max(1, int(retry_after) + 1)
        super().__init__(f"rate limited; retry after {self.retry_after}s")


class RateLimits(StrictModel):
    """How much one principal may do per minute.

    Defaults are generous for a person and restrictive for a script: an analyst
    working a queue does not make two requests a second for a minute, and
    something that does is not working a queue.
    """

    #: Requests per minute across every route.
    requests_per_minute: int = 120
    #: Requests per minute against routes that spend money. Checked as well as
    #: the general limit, never instead of it.
    spending_per_minute: int = 6
    #: Burst allowance, as a multiple of the per-minute rate. A person clicking
    #: through a queue arrives in bursts; a steady trickle is not the shape of
    #: real use, and a limiter that only allowed one would be wrong about
    #: everybody.
    burst: float = 1.5


class _Bucket:
    """One token bucket. Refills continuously rather than on a fixed window.

    A fixed window lets a caller spend the whole allowance in the last second
    of one window and again in the first second of the next — twice the
    intended rate, at the worst possible moment.
    """

    __slots__ = ("_capacity", "_rate", "_tokens", "_updated")

    def __init__(self, per_minute: int, burst: float, now: float) -> None:
        self._rate = per_minute / 60.0
        self._capacity = max(1.0, per_minute * burst)
        self._tokens = self._capacity
        # Stamped with the caller's clock reading, not a fresh one. Sampling
        # again here puts `_updated` *after* the `now` the first `take` uses,
        # making elapsed negative and draining a token from a full bucket — so
        # the very first request from a new principal could be refused.
        self._updated = now

    def take(self, now: float) -> float:
        """Spend one token. Returns 0 on success, or seconds until one exists."""
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return 0.0
        return (1.0 - self._tokens) / self._rate


class RateLimiter:
    """Per-principal buckets, bounded in number so they cannot themselves leak.

    The map is capped: a stream of distinct subjects would otherwise grow it
    without limit, which turns a control against resource exhaustion into a
    means of it. When full, the least recently used entries are dropped —
    losing a bucket is a caller getting a fresh allowance, which is a far
    smaller problem than unbounded memory.
    """

    #: Distinct principals tracked at once. Well above any real analyst count,
    #: and low enough that the map cannot become the exhaustion vector.
    MAX_PRINCIPALS = 4096

    def __init__(self, limits: RateLimits | None = None) -> None:
        self._limits = limits or RateLimits()
        self._general: dict[str, _Bucket] = {}
        self._spending: dict[str, _Bucket] = {}
        self._seen: dict[str, float] = {}
        self._lock = Lock()

    def check(self, subject: str, spending: bool = False) -> None:
        """Raise :class:`RateLimited` when this principal has spent its allowance.

        Both buckets are consulted for a spending route, and the general bucket
        is charged either way: a request that costs money is also a request.
        """
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            self._seen[subject] = now
            wait = self._bucket(
                self._general, subject, self._limits.requests_per_minute, now
            ).take(now)
            if wait:
                raise RateLimited(wait)
            if spending:
                spend_wait = self._bucket(
                    self._spending, subject, self._limits.spending_per_minute, now
                ).take(now)
                if spend_wait:
                    raise RateLimited(spend_wait)

    def _bucket(
        self, buckets: dict[str, _Bucket], subject: str, per_minute: int, now: float
    ) -> _Bucket:
        bucket = buckets.get(subject)
        if bucket is None:
            bucket = _Bucket(per_minute, self._limits.burst, now)
            buckets[subject] = bucket
        return bucket

    def _evict(self, now: float) -> None:
        if len(self._seen) < self.MAX_PRINCIPALS:
            return
        oldest = sorted(self._seen.items(), key=lambda item: item[1])
        for subject, _ in oldest[: len(oldest) // 4 or 1]:
            self._seen.pop(subject, None)
            self._general.pop(subject, None)
            self._spending.pop(subject, None)
