"""Keeping credentials out of model requests, without losing the findings.

Source under review reaches a third-party model verbatim unless something stops
it, and a repository with a committed ``.env``, a private key, or a hardcoded
token would send it. That is the leak this module closes.

The obvious implementation breaks something important. The workspace validates
every cited evidence snippet by re-reading the line from the checkout — so a
model shown ``password = [REDACTED]`` can only cite the redacted form, which
will not match the real line, and the finding is rejected. Redaction applied
naively therefore suppresses exactly the findings that matter most about
credentials: CWE-798 is one of the expert families.

So redaction here is **reversible**. Each occurrence gets a distinct
placeholder, the mapping is held for the duration of one dispatch, and the
model's answer is restored before it reaches the recorder. The secret never
leaves the host; the evidence chain stays intact.

That the secret remains in driver memory is not a weakening: it is already in
the checkout on the same disk, and the recorded artifacts already sit beside
the source they cite. The boundary being defended is the one to the provider.
"""

from __future__ import annotations

import re

from pydantic import Field

from .contracts import StrictModel

#: Credential shapes, most specific first. Deliberately conservative: a pattern
#: that fires on ordinary code costs a rejected citation, so the cost of a false
#: positive is real and the list stays narrow.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
    )),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    # An assigned secret keeps its key name: the *evidence* that a credential
    # exists is the finding, and only its value is withheld.
    #
    # The negative lookahead is load-bearing. This pattern runs last, so by the
    # time it sees ``api_key = "AKIA…"`` the specific rule above has already
    # replaced the value with a placeholder — and without the guard it would
    # redact *the placeholder*, nesting one mapping inside another. Restoration
    # unwinds a single level, so the nested form would survive into the answer
    # and the citation would be rejected.
    ("assigned-secret", re.compile(
        r"""(?i)\b(api[_-]?key|secret|token|passwd|password|credential)\b"""
        r"""(\s*[:=]\s*)(["']?)(?!\[REDACTED:)([^\s"',;)]{6,})(["']?)"""
    )),
]

_PLACEHOLDER = re.compile(r"\[REDACTED:[a-z-]+:(\d+)\]")


class Redacted(StrictModel):
    """Text safe to dispatch, and what it takes to undo that."""

    text: str
    #: placeholder -> the original text it replaced.
    restorations: dict[str, str] = Field(default_factory=dict)
    #: Kinds redacted, in order, for reporting. Never the values.
    kinds: list[str] = Field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.restorations)


def redact(text: str) -> Redacted:
    """Replace credential-shaped strings with restorable placeholders."""
    restorations: dict[str, str] = {}
    kinds: list[str] = []
    out = text

    for kind, pattern in PATTERNS:
        def _replace(match: re.Match[str], kind: str = kind) -> str:
            index = len(restorations)
            placeholder = f"[REDACTED:{kind}:{index}]"
            if kind == "assigned-secret":
                # keep the key name and the operator; withhold only the value
                secret = match.group(4)
                restorations[placeholder] = secret
                kinds.append(kind)
                name, operator, open_quote, close_quote = (
                    match.group(1), match.group(2), match.group(3), match.group(5)
                )
                return f"{name}{operator}{open_quote}{placeholder}{close_quote}"
            restorations[placeholder] = match.group(0)
            kinds.append(kind)
            return placeholder

        out = pattern.sub(_replace, out)

    return Redacted(text=out, restorations=restorations, kinds=kinds)


def restore(text: str, restorations: dict[str, str]) -> str:
    """Put the originals back before an answer reaches the recorder.

    Applied to the model's answer, so a snippet it cited from redacted material
    matches the checkout again. A placeholder the model mangled or invented
    simply does not match anything here and is left alone — the recorder then
    rejects that citation, which is the correct outcome for a snippet that was
    never in the source.
    """
    if not restorations:
        return text
    out = text
    for placeholder, original in restorations.items():
        out = out.replace(placeholder, original)
    return out


def contains_placeholder(text: str) -> bool:
    """True if any redaction marker survives — a sign restoration missed one."""
    return bool(_PLACEHOLDER.search(text))
