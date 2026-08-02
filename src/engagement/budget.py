"""The spend governor that replaces the human backlog-approval gate.

In an attended run, a person looks at a recorded backlog and decides whether it
is worth paying for. That gate sits at the only point in the workflow where the
cost of the expensive phase is already known: the backlog has been recorded and
counted, but not one expert call has been made.

This module puts a policy at exactly that point, with exactly that information.
A run whose backlog exceeds the ceiling is not abandoned and not silently
truncated — it is processed in priority order up to the ceiling, and everything
left over is reported as ``unfunded``. Unreviewed is never reported as clean.

Consumption is refused *before* dispatch rather than measured after it, because
a ceiling that only notices overspend once it has happened is a report, not a
limit.
"""

from __future__ import annotations

from threading import Lock

from pydantic import Field, PrivateAttr

from .contracts import StrictModel


class BudgetExceeded(RuntimeError):
    """Raised instead of dispatching a call the budget cannot cover."""


class Budget(StrictModel):
    """Bounded by default. An unattended run that can spend without limit is a
    defect, not a default — there is nobody watching to stop it."""

    max_calls: int = 200
    max_total_tokens: int = 2_000_000

    def projection(self, scenarios: int, candidates: int) -> int:
        """Calls a full run of this backlog would cost.

        The cost model is one call per scenario plus one per candidate. The
        router call is already spent by the time a projection is worth making,
        so it is deliberately not counted here: this answers "what will the
        rest cost?", which is the question the gate exists to ask.
        """
        return max(0, scenarios) + max(0, candidates)

    def affordable(self, spent: int) -> int:
        """How many further calls remain under the ceiling."""
        return max(0, self.max_calls - spent)


class Ledger(StrictModel):
    """What has actually been spent, and what the ceiling allowed.

    Kept separate from :class:`Budget` so the limit stays a declared policy and
    the tally stays an observation; conflating them is how a ceiling quietly
    becomes whatever was spent.
    """

    budget: Budget = Field(default_factory=Budget)
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    #: Guards every read-modify-write below. Dispatch can run concurrently, and
    #: a ceiling that is only enforced under one thread is not a ceiling.
    _lock: Lock = PrivateAttr(default_factory=Lock)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def _breach(self, cost: int) -> str:
        """Which ceiling ``cost`` more calls would cross, if either."""
        if self.calls + cost > self.budget.max_calls:
            return f"call ceiling reached ({self.budget.max_calls}); refusing before dispatch"
        if self.total_tokens >= self.budget.max_total_tokens:
            return (
                f"token ceiling reached ({self.budget.max_total_tokens}); "
                "refusing before dispatch"
            )
        return ""

    def check(self, cost: int = 1) -> None:
        """Refuse now if the next ``cost`` calls would breach either ceiling."""
        with self._lock:
            breach = self._breach(cost)
        if breach:
            raise BudgetExceeded(breach)

    def reserve(self, cost: int = 1) -> None:
        """Claim ``cost`` calls against the ceiling, atomically.

        Separate from :meth:`record_usage` because checking and then counting
        are two operations, and concurrent dispatch can slip between them: two
        callers both pass a check at one call below the ceiling, and both
        dispatch. Counting at claim time is what keeps a ceiling a ceiling.
        """
        with self._lock:
            breach = self._breach(cost)
            if not breach:
                self.calls += cost
        if breach:
            raise BudgetExceeded(breach)

    def release(self, cost: int = 1) -> None:
        """Hand back a reservation whose dispatch never happened.

        A call that failed before the model produced anything is not spend, and
        counting it would let a run of transient failures exhaust a budget that
        was never used.
        """
        with self._lock:
            self.calls = max(0, self.calls - cost)

    def record_usage(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        """Add the tokens one dispatch actually reported. The call itself was
        already counted by :meth:`reserve`."""
        with self._lock:
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens

    def remaining_calls(self) -> int:
        with self._lock:
            return self.budget.affordable(self.calls)

    def can_afford(self, cost: int = 1) -> bool:
        with self._lock:
            return not self._breach(cost)
