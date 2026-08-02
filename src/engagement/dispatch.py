"""One metered model call, in one place.

Every dispatch in this package does the same five things in the same order:
refuse if the budget cannot cover it, redact credential shapes, call the
provider, meter and record what it cost, and restore the redacted values in the
answer. That sequence *is* the security posture — a stage that dispatches
without it spends unmetered money, ships credentials to a vendor, and leaves no
trail.

It lived inside the driver while the driver was the only caller. The advisory
stages (chains, PoC drafting) are also model calls, and a second copy of the
sequence is exactly the kind of cross-file drift this repository has already
been bitten by: two dispatch paths agree on the day they are written and not
much longer. So the sequence moved here, and the driver became a caller like
any other.
"""

from __future__ import annotations

from hashlib import sha256

from .audit import AuditLog
from .budget import Ledger
from .caching import CacheReport, is_cacheable
from .providers import ModelProvider, ModelRequest
from .redaction import redact, restore


class Dispatcher:
    """The one path from a prompt to an answer.

    Redaction counts accumulate across calls because they are a *bound*: what
    was withheld from the model belongs in the run report, so a thin result is
    never mistaken for a clean one.
    """

    def __init__(
        self,
        provider: ModelProvider,
        ledger: Ledger,
        audit: AuditLog | None = None,
    ) -> None:
        self._provider = provider
        self._ledger = ledger
        self._audit = audit or AuditLog()
        self.redactions = 0
        #: Accumulated across calls for the same reason redactions are: what
        #: caching actually did is a property of the run, not of one dispatch.
        self.caching = CacheReport()

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def can_afford(self, cost: int = 1) -> bool:
        return self._ledger.can_afford(cost)

    def ask(
        self,
        phase: str,
        deployment: str,
        system: str,
        prompt: str,
        cache_prefix: str = "",
    ) -> str:
        """Dispatch one prompt. Raises ``BudgetExceeded`` before spending.

        The digest recorded is of the text *actually sent* — after redaction —
        because a digest of the unredacted prompt would identify a byte
        sequence that never left the process. The prefix is digested with it:
        it is part of what was sent, and a trail that omitted it could not
        answer what the model was actually shown.

        ``cache_prefix`` is redacted like everything else. It carries text
        recovered from the repository under review, and content being invariant
        across calls says nothing about whether it holds a credential.
        """
        self._ledger.check()
        redacted = redact(prompt)
        self.redactions += redacted.count

        prefix = ""
        if cache_prefix:
            if is_cacheable(cache_prefix, deployment):
                redacted_prefix = redact(cache_prefix)
                self.redactions += redacted_prefix.count
                redacted.restorations.update(redacted_prefix.restorations)
                prefix = redacted_prefix.text
                self.caching.offered += 1
            else:
                # Sent as an ordinary part of the system prompt rather than
                # dropped: the text is needed either way, and only the billing
                # was ever in question.
                self.caching.below_minimum += 1
                redacted_prefix = redact(cache_prefix)
                self.redactions += redacted_prefix.count
                redacted.restorations.update(redacted_prefix.restorations)
                system = f"{system}\n\n{redacted_prefix.text}"

        response = self._provider.complete(
            ModelRequest(
                deployment=deployment,
                system=system,
                user=redacted.text,
                cache_prefix=prefix,
            )
        )
        self._ledger.record(response.input_tokens, response.output_tokens)
        self.caching.read_tokens += response.cache_read_tokens
        self.caching.written_tokens += response.cache_write_tokens
        self._audit.dispatch(
            phase=phase,
            deployment=deployment,
            prompt_digest=sha256(
                (prefix + redacted.text).encode("utf-8")
            ).hexdigest(),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            redactions=redacted.count,
            calls_so_far=self._ledger.calls,
            cache_read_tokens=response.cache_read_tokens,
            cache_write_tokens=response.cache_write_tokens,
        )
        return restore(response.content, redacted.restorations)
