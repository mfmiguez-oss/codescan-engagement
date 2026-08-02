"""Properties of prompt caching.

Caching is a pure cost optimisation, which is what makes it worth testing
carefully: a mistake here never fails a run, it just quietly changes the prompt
or quietly stops saving money. So the tests that carry the weight are the ones
that check nothing was *lost* — that a hoisted manifest still reaches the model
on a surface that cannot cache it, that a prefix below the floor is still sent,
and that a cached span is redacted like every other byte that leaves.
"""

from __future__ import annotations

from engagement.audit import AuditLog, MemorySink
from engagement.budget import Budget, Ledger
from engagement.caching import (
    DEFAULT_MINIMUM_TOKENS,
    MANIFEST_HEADING,
    CacheReport,
    is_cacheable,
    minimum_tokens,
    split_manifest,
)
from engagement.contracts import Priority, RunRef
from engagement.dispatch import Dispatcher
from engagement.driver import Driver, Policy
from engagement.providers import (
    BedrockProvider,
    FakeProvider,
    FoundryProvider,
    ModelRequest,
)
from fakes import FakeWorkspace, scenarios

MANIFEST = f"{MANIFEST_HEADING}\n\n" + ("playbook line. " * 400)


def _prompt() -> str:
    return (
        "# Scenario S1\n\n- Expert: `injection`\n- Required proof obligations: two\n"
        "\n## Instructions\n\nAnswer every required proof obligation listed above.\n"
        f"\n\n{MANIFEST}"
    )


def _dispatcher(
    read: int = 0, write: int = 0, sink: MemorySink | None = None
) -> Dispatcher:
    return Dispatcher(
        FakeProvider(cache_read_tokens=read, cache_write_tokens=write),
        Ledger(budget=Budget(max_calls=50)),
        AuditLog(sink or MemorySink()),
    )


# -- splitting the prompt ----------------------------------------------------


def test_the_manifest_is_separated_from_the_scenario() -> None:
    body, manifest = split_manifest(_prompt())

    assert manifest.startswith(MANIFEST_HEADING)
    assert MANIFEST_HEADING not in body


def test_the_instruction_block_stays_with_the_header_it_refers_to() -> None:
    """The reason only the manifest is hoisted.

    The instructions say "listed above" about the scenario header. Hoisting
    them would leave that pointing at nothing, so the split must keep the
    header before the instructions in the same turn.
    """
    body, _ = split_manifest(_prompt())

    assert body.index("Required proof obligations") < body.index("listed above")


def test_a_prompt_with_no_manifest_is_returned_unchanged() -> None:
    """The router and triage prompts carry none; that is normal, not an error."""
    body, manifest = split_manifest("# Router\n\nPick the units.")

    assert manifest == ""
    assert body == "# Router\n\nPick the units."


def test_the_split_takes_the_last_heading_not_the_first() -> None:
    """A manifest that quoted the heading would otherwise take the split with
    it and leave half the instructions in the cache prefix."""
    quoted = (
        f"# Scenario\n\n## Instructions\n\nMention {MANIFEST_HEADING} in passing.\n"
        f"\n{MANIFEST_HEADING}\n\nthe real one"
    )
    body, manifest = split_manifest(quoted)

    assert manifest == f"{MANIFEST_HEADING}\n\nthe real one"
    assert "in passing" in body


# -- the floor ---------------------------------------------------------------


def test_each_family_has_its_own_minimum() -> None:
    assert minimum_tokens("claude-opus-5") == 512
    assert minimum_tokens("claude-sonnet-5") == 1024
    assert minimum_tokens("claude-haiku-4-5") == 4096


def test_a_platform_prefix_does_not_hide_the_family() -> None:
    """Same trap the sampling rule hit: Bedrock writes `anthropic.` in front."""
    assert minimum_tokens("anthropic.claude-opus-5") == 512
    assert minimum_tokens("us.anthropic.claude-sonnet-5") == 1024


def test_an_unknown_deployment_assumes_the_largest_floor() -> None:
    """Guessing low costs a write premium on every call for an entry that can
    never be read; guessing high costs only a missed discount."""
    assert minimum_tokens("some-private-alias") == DEFAULT_MINIMUM_TOKENS


def test_a_short_prefix_is_not_offered_for_caching() -> None:
    assert not is_cacheable("too short", "claude-opus-5")
    assert not is_cacheable("", "claude-opus-5")
    assert is_cacheable(MANIFEST, "claude-opus-5")


# -- nothing is lost ---------------------------------------------------------


def test_a_prefix_below_the_floor_is_still_sent_to_the_model() -> None:
    """The load-bearing test. The prefix is content the model needs; only its
    billing was ever in question, so a floor it fails must not drop it."""
    provider = FakeProvider()
    dispatcher = Dispatcher(
        provider, Ledger(budget=Budget(max_calls=5)), AuditLog(MemorySink())
    )

    dispatcher.ask("scenarios", "claude-haiku-4-5", "SYS", "body", cache_prefix="short")

    sent = provider.requests[0]
    assert sent.cache_prefix == "", "a prefix under the floor was cached anyway"
    assert "short" in sent.system, "the prefix was dropped instead of inlined"
    assert dispatcher.caching.below_minimum == 1


def test_a_surface_without_cache_control_still_receives_the_prefix() -> None:
    """A hoisted manifest that vanished on a non-Anthropic deployment would be
    a correctness bug wearing a cost optimisation's clothes."""
    foundry = FoundryProvider(resource="r", api_key="k")
    shape = foundry.build_request(
        ModelRequest(
            deployment="gpt-5-mini", system="SYS", user="body", cache_prefix=MANIFEST
        )
    )

    system = shape["body"]["messages"][0]["content"]
    assert MANIFEST_HEADING in system
    assert system.startswith("SYS")


def test_the_responses_surface_also_keeps_the_prefix() -> None:
    foundry = FoundryProvider(resource="r", api_key="k")
    shape = foundry.build_request(
        ModelRequest(
            deployment="gpt-5.3-codex",
            system="SYS",
            user="body",
            cache_prefix=MANIFEST,
        )
    )

    assert MANIFEST_HEADING in shape["body"]["instructions"]


# -- the wire shape ----------------------------------------------------------


def test_the_anthropic_surface_marks_a_breakpoint_on_the_last_block() -> None:
    foundry = FoundryProvider(resource="r", api_key="k")
    shape = foundry.build_request(
        ModelRequest(
            deployment="claude-opus-5",
            system="SYS",
            user="body",
            cache_prefix=MANIFEST,
        )
    )

    blocks = shape["body"]["system"]
    assert blocks[0]["text"] == "SYS"
    assert "cache_control" not in blocks[0], "the short block took the breakpoint"
    assert blocks[-1]["cache_control"] == {"type": "ephemeral"}


def test_without_a_prefix_the_system_field_keeps_its_plain_shape() -> None:
    """Caching must not change the request of a run that is not using it."""
    foundry = FoundryProvider(resource="r", api_key="k")
    shape = foundry.build_request(
        ModelRequest(deployment="claude-opus-5", system="SYS", user="body")
    )

    assert shape["body"]["system"] == "SYS"


def test_bedrock_expresses_the_breakpoint_as_a_cache_point() -> None:
    shape = BedrockProvider(region="us-east-1").build_request(
        ModelRequest(
            deployment="anthropic.claude-opus-5",
            system="SYS",
            user="body",
            cache_prefix=MANIFEST,
        )
    )

    assert shape["system"][-1] == {"cachePoint": {"type": "default"}}
    assert MANIFEST_HEADING in shape["system"][1]["text"]


# -- metering ----------------------------------------------------------------


def test_the_discount_reaches_the_ledger_and_the_trail() -> None:
    """The prerequisite for the whole feature: a meter that cannot see a
    discount reports a bill nobody was charged."""
    sink = MemorySink()
    dispatcher = _dispatcher(read=900, write=100, sink=sink)

    dispatcher.ask("scenarios", "claude-opus-5", "SYS", "body", cache_prefix=MANIFEST)

    assert dispatcher.caching.read_tokens == 900
    assert dispatcher.caching.written_tokens == 100
    call = next(e for e in sink.events if e.kind == "model_call")
    assert call.detail["cache_read_tokens"] == 900
    assert call.detail["cache_write_tokens"] == 100


def test_a_cache_offered_and_never_read_is_a_warning_not_a_zero() -> None:
    """This is the expensive failure: every call paid the write premium and
    nothing reused the entry — worse than not caching at all, and silent."""
    dispatcher = _dispatcher(read=0, write=500)
    for _ in range(3):
        dispatcher.ask(
            "scenarios", "claude-opus-5", "SYS", "body", cache_prefix=MANIFEST
        )

    warning = " ".join(dispatcher.caching.warnings())
    assert "none was read back" in warning
    assert "write premium" in warning


def test_a_working_cache_says_nothing() -> None:
    dispatcher = _dispatcher(read=900, write=0)
    dispatcher.ask("scenarios", "claude-opus-5", "SYS", "body", cache_prefix=MANIFEST)

    assert dispatcher.caching.warnings() == []


def test_a_run_that_never_offered_a_cache_is_not_warned_about() -> None:
    assert CacheReport().warnings() == []
    assert CacheReport().describe() == "caching: not used"


def test_the_prefix_is_redacted_like_everything_else_that_leaves() -> None:
    """Content being invariant across calls says nothing about whether it holds
    a credential, and a cached span leaves the process exactly like any other."""
    provider = FakeProvider()
    dispatcher = Dispatcher(
        provider, Ledger(budget=Budget(max_calls=5)), AuditLog(MemorySink())
    )
    secret = "AKIAIOSFODNN7EXAMPLE"

    dispatcher.ask(
        "scenarios",
        "claude-opus-5",
        "SYS",
        "body",
        cache_prefix=f"{MANIFEST}\naws_key = {secret}\n",
    )

    assert secret not in provider.requests[0].cache_prefix
    assert dispatcher.redactions >= 1


# -- the driver actually uses it ---------------------------------------------


def test_the_scenario_stage_hoists_the_manifest_out_of_the_prompt() -> None:
    """Cross-boundary check: the split existing is not the same as the stage
    calling it. The bulk of a run's spend is this one path."""
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.prompt_extra = f"\n\n{MANIFEST}"
    provider = FakeProvider(default="{}")
    Driver(
        workspace=workspace,
        provider=provider,
        ledger=Ledger(budget=Budget()),
        policy=Policy(model="claude-opus-5"),
    ).run(RunRef(target="acme", run_id="run-001"))

    scenario_calls = [r for r in provider.requests if r.cache_prefix]
    assert scenario_calls, "the manifest was never hoisted into a cache prefix"
    sent = scenario_calls[0]
    assert sent.cache_prefix.startswith(MANIFEST_HEADING)
    assert MANIFEST_HEADING not in sent.user, "the manifest was sent twice"


def test_a_run_reports_what_caching_did() -> None:
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.prompt_extra = f"\n\n{MANIFEST}"
    report = Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}", cache_read_tokens=700),
        ledger=Ledger(budget=Budget()),
        policy=Policy(model="claude-opus-5"),
    ).run(RunRef(target="acme", run_id="run-001"))

    assert report.cache_read_tokens == 700


def test_the_digest_covers_the_prefix_that_was_sent() -> None:
    """A trail that digested only the variable half could not answer what the
    model was actually shown."""
    sink_a, sink_b = MemorySink(), MemorySink()
    with_prefix = Dispatcher(
        FakeProvider(), Ledger(budget=Budget(max_calls=5)), AuditLog(sink_a)
    )
    without = Dispatcher(
        FakeProvider(), Ledger(budget=Budget(max_calls=5)), AuditLog(sink_b)
    )

    with_prefix.ask("scenarios", "claude-opus-5", "SYS", "body", cache_prefix=MANIFEST)
    without.ask("scenarios", "claude-opus-5", "SYS", "body")

    a = next(e for e in sink_a.events if e.kind == "model_call")
    b = next(e for e in sink_b.events if e.kind == "model_call")
    assert a.detail["prompt_sha256"] != b.detail["prompt_sha256"]
