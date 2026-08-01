"""Credentials never reach the provider, and findings about them survive."""

from __future__ import annotations

from engagement.budget import Ledger
from engagement.contracts import Priority, RunRef
from engagement.driver import Driver, Policy
from engagement.providers import FakeProvider
from engagement.redaction import contains_placeholder, redact, restore
from fakes import FakeWorkspace, scenarios

REF = RunRef(target="acme", run_id="run-001")

SECRETS = {
    "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
    "github-token": "ghp_" + "a" * 36,
    "slack-token": "xoxb-123456789012-abcdefghijkl",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
}


def test_every_credential_shape_is_withheld() -> None:
    for kind, secret in SECRETS.items():
        result = redact(f"const key = '{secret}';")
        assert secret not in result.text, f"{kind} survived redaction"
        assert result.count == 1


def test_a_private_key_block_is_withheld_whole() -> None:
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    )
    result = redact(f"key = '''{text}'''")
    assert "MIIEowIBAAKCAQEA" not in result.text
    assert result.count == 1


def test_an_assigned_secret_keeps_its_name_and_loses_its_value() -> None:
    """The evidence that a credential exists is the finding; only the value is
    withheld, so the model can still report the weakness."""
    result = redact('password = "hunter2-not-a-real-password"')
    assert "password" in result.text
    assert "hunter2" not in result.text
    assert result.count == 1


def test_redaction_is_reversible_so_evidence_still_validates() -> None:
    """The workspace re-reads every cited line from the checkout. A model that
    could only see a redacted line could never cite one, and the findings lost
    would be exactly the hardcoded-credential ones."""
    original = 'api_key = "AKIAIOSFODNN7EXAMPLE"'
    result = redact(original)
    assert original not in result.text

    # the model echoes what it was shown; restoration puts the truth back
    answer = f'{{"snippet": "{result.text}"}}'
    assert restore(answer, result.restorations) == f'{{"snippet": "{original}"}}'


def test_each_occurrence_gets_a_distinct_placeholder() -> None:
    """Shared placeholders would make restoration ambiguous and could put the
    wrong secret back on the wrong line."""
    result = redact('a = "AKIAIOSFODNN7EXAMPLE"\nb = "AKIAJOSFODNN7EXAMPLF"')
    assert result.count == 2
    assert len(set(result.restorations)) == 2


def test_ordinary_code_is_left_alone() -> None:
    """A pattern that fires on normal code costs a rejected citation, so the
    cost of a false positive is real."""
    code = "def login(user, conn):\n    return mysqli_query(conn, sql)\n"
    assert redact(code).count == 0


def test_a_mangled_placeholder_is_left_for_the_recorder_to_reject() -> None:
    """Restoring something the model invented would be worse than failing."""
    restored = restore('{"snippet": "[REDACTED:invented:99]"}', {"[REDACTED:jwt:0]": "x"})
    assert contains_placeholder(restored)


# -- through the driver -----------------------------------------------------


def test_no_secret_reaches_the_provider() -> None:
    """The property, end to end: what the provider actually received."""
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    secret = "AKIAIOSFODNN7EXAMPLE"
    workspace.prompt_extra = f'\naws_key = "{secret}"\n'

    provider = FakeProvider(default="{}")
    Driver(
        workspace=workspace,
        provider=provider,
        ledger=Ledger(),
        policy=Policy(model="m"),
    ).run(REF)

    assert provider.requests, "nothing was dispatched"
    for request in provider.requests:
        assert secret not in request.user, "a credential reached the provider"


def test_the_run_reports_what_it_withheld() -> None:
    """A bound like any other: a thin result must not read as a clean one."""
    workspace = FakeWorkspace(scenarios=scenarios(("S001", Priority.normal)))
    workspace.prompt_extra = '\ntoken = "ghp_' + "a" * 36 + '"\n'

    report = Driver(
        workspace=workspace,
        provider=FakeProvider(default="{}"),
        ledger=Ledger(),
        policy=Policy(model="m"),
    ).run(REF)

    assert report.redactions >= 1
    assert any("withheld from the model" in w for w in report.warnings)
