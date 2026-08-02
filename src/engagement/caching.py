"""Reusing the part of a prompt that does not change.

The scenario stage is the bulk of a run's spend: one call per scenario, and
every one of those prompts ends with the **expert manifest** — a 7–10 KB
playbook that is byte-identical for every scenario routed to the same expert.
Twelve manifests exist; a run with sixty scenarios sends one of them sixty
times and pays full price each time. Prompt caching bills a repeat of that
span at roughly a tenth of the input rate.

Two decisions shape this module, and both are about *not* breaking the prompt
to save money.

**Only the manifest moves.** The rendered prompt is a per-scenario header, then
an invariant instruction block, then the manifest. The instruction block is
larger and looks like the better prize — but it contains the sentence "answer
every required proof obligation listed above", and "above" is the header. Hoist
the instructions and that reference dangles. The manifest is appended last by
OpenHack's renderer, is referenced only as "read the expert manifest", and
carries no positional reference at all, so moving it ahead of the header
changes nothing about what the model is asked. A cheaper prompt that quietly
asks a different question is not a saving.

**A cache that never hits is reported, not assumed.** Caching is a pure cost
optimisation — a miss costs money and never correctness — which is exactly what
makes it dangerous: nothing fails when it silently stops working. The minimum
cacheable prefix is model-dependent and larger on some families than the
manifest itself, and any byte that changes in the prefix invalidates it. So the
run counts what was actually read from cache and says so, and a prefix below the
model's own floor is refused up front with the reason rather than sent to become
a write that is never read.
"""

from __future__ import annotations

from .contracts import StrictModel
from .models import bare_model_id

#: The heading OpenHack's renderer appends the expert manifest under. The split
#: is on the heading rather than a byte offset because the sections above it
#: vary in length per scenario, and a fixed offset would silently start cutting
#: mid-instruction the first time a template line was reworded.
MANIFEST_HEADING = "## Expert Manifest"

#: Minimum cacheable prefix, in tokens, per model family prefix. Below this the
#: API accepts the breakpoint and silently caches nothing — no error, no signal
#: — so the floor is checked here instead. Values are per published family; the
#: fallback is the highest of them, because guessing low means paying the write
#: premium for an entry that can never be read.
CACHE_MINIMUM_TOKENS: dict[str, int] = {
    "claude-opus-5": 512,
    "claude-fable": 512,
    "claude-mythos": 512,
    "claude-opus-4-8": 1024,
    "claude-sonnet-5": 1024,
    "claude-sonnet-4-6": 1024,
    "claude-sonnet-4-5": 1024,
    "claude-opus-4-7": 2048,
    "claude-opus-4-6": 4096,
    "claude-opus-4-5": 4096,
    "claude-haiku-4-5": 4096,
}

#: Used when the deployment alias matches no known family. Deliberately the
#: largest floor in the table: an unrecognised deployment is not evidence of a
#: small minimum, and over-estimating costs a missed discount while
#: under-estimating costs a write premium on every single call.
DEFAULT_MINIMUM_TOKENS = 4096

#: Characters per token, for the pre-dispatch floor check only. Deliberately
#: conservative — 4.0 is the usual English approximation, and 3.5 under-counts
#: tokens for prose, so a prefix this rejects is genuinely short rather than
#: merely borderline. Never used for billing: the ledger records the token
#: counts the provider actually reported.
CHARS_PER_TOKEN = 3.5


def minimum_tokens(deployment: str) -> int:
    """The smallest prefix this deployment will actually cache."""
    lowered = bare_model_id(deployment)
    for family, minimum in CACHE_MINIMUM_TOKENS.items():
        if lowered.startswith(family):
            return minimum
    return DEFAULT_MINIMUM_TOKENS


def split_manifest(prompt: str) -> tuple[str, str]:
    """Separate a rendered scenario prompt from the expert manifest it ends with.

    Returns ``(prompt_without_manifest, manifest)``. A prompt with no manifest
    section comes back unchanged with an empty manifest — that is the normal
    answer for the router and triage prompts, not an error, and the caller
    simply dispatches without a cache prefix.

    Splits on the *last* occurrence of the heading. A manifest that itself
    quoted the heading would otherwise take the split point with it and leave
    half the instructions in the cache prefix.
    """
    marker = prompt.rfind(f"\n{MANIFEST_HEADING}")
    if marker < 0:
        return prompt, ""
    return prompt[:marker].rstrip(), prompt[marker:].strip()


def is_cacheable(prefix: str, deployment: str) -> bool:
    """Whether this prefix is long enough for this deployment to cache it."""
    if not prefix.strip():
        return False
    return len(prefix) / CHARS_PER_TOKEN >= minimum_tokens(deployment)


class CacheReport(StrictModel):
    """What caching actually did, as opposed to what was requested.

    Kept as counts rather than a boolean because the failure this exists to
    catch is partial: a prefix that caches for the first expert and silently
    stops for the rest reads as "caching is on" under any yes/no check.
    """

    #: Calls dispatched carrying a cache breakpoint.
    offered: int = 0
    #: Calls whose prefix was below the deployment's floor, so none was sent.
    below_minimum: int = 0
    #: Tokens the provider served from cache, at roughly a tenth of the rate.
    read_tokens: int = 0
    #: Tokens written to cache, at a premium over the base rate.
    written_tokens: int = 0

    @property
    def hit(self) -> bool:
        return self.read_tokens > 0

    def warnings(self) -> list[str]:
        """What an operator needs told. Silence when there is nothing to say.

        The load-bearing case is ``offered`` without ``read_tokens``: every call
        paid the write premium and not one of them read the entry back. That is
        the shape of a silent invalidator — something in the prefix differing
        per call — and it is *more* expensive than not caching at all, which is
        why it is a warning rather than a quiet zero in a report.
        """
        out: list[str] = []
        if self.offered and not self.read_tokens:
            out.append(
                f"caching: {self.offered} call(s) offered a cache prefix and none "
                "was read back. Every one paid the write premium for an entry "
                "nothing reused — something in the prefix is changing per call, "
                "or the entries expired between calls"
            )
        if self.below_minimum:
            out.append(
                f"caching: {self.below_minimum} call(s) had a prefix below the "
                "deployment's minimum cacheable length and were sent uncached. "
                "The API would have accepted the breakpoint and cached nothing"
            )
        return out

    def describe(self) -> str:
        """One line for the run report."""
        if not self.offered:
            return "caching: not used"
        return (
            f"caching: {self.read_tokens} token(s) read from cache, "
            f"{self.written_tokens} written, across {self.offered} offered call(s)"
        )
