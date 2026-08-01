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

from pydantic import Field

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

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def check(self, cost: int = 1) -> None:
        """Refuse now if the next ``cost`` calls would breach either ceiling."""
        if self.calls + cost > self.budget.max_calls:
            raise BudgetExceeded(
                f"call ceiling reached ({self.budget.max_calls}); refusing before dispatch"
            )
        if self.total_tokens >= self.budget.max_total_tokens:
            raise BudgetExceeded(
                f"token ceiling reached ({self.budget.max_total_tokens}); "
                "refusing before dispatch"
            )

    def record(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.calls += 1
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens

    def remaining_calls(self) -> int:
        return self.budget.affordable(self.calls)

    def can_afford(self, cost: int = 1) -> bool:
        try:
            self.check(cost)
        except BudgetExceeded:
            return False
        return True
