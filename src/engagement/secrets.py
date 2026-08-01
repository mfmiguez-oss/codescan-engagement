"""Where secrets come from, so they need not sit on disk.

An API key in a `.env` is readable by everything running as that user —
including this package, and including anything it executes. Gitignoring the file
keeps it out of history; it does not keep it out of reach.

This resolves a secret by *name* instead, from Azure Key Vault via managed
identity when the deployment configures one, and from the environment when it
does not. Local development is unchanged: configure nothing and the environment
is used exactly as before.

Three rules make the indirection worth having:

**Configured means required.** If a vault is configured and the fetch fails, that
is an error — never a quiet fall back to the environment. A deployment that
believes it is reading from a vault and is actually reading a stale `.env` has
the worst of both: the ceremony of a secret store and none of the rotation.

**The value is never logged, returned in an error, or written to an artifact.**
Failures name the vault and the secret's *name*, never its content, and
:class:`SecretRef` carries only the coordinates.

**Fetched once per run.** A vault call per model dispatch would be a rate limit
waiting to happen and would put the secret on the wire far more often than
necessary. The cache lives for the process and is never persisted.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import Field

from .contracts import StrictModel


class SecretError(RuntimeError):
    """A secret could not be resolved from the source that was configured."""


class SecretRef(StrictModel):
    """Where a secret lives — coordinates only, never the value."""

    #: Environment variable consulted when no vault is configured.
    env_var: str
    #: Vault name, without the ``https://`` or the domain suffix.
    vault: str = ""
    #: Secret name inside the vault. Defaults to the environment variable's
    #: name lowercased with underscores as hyphens, which is the Key Vault
    #: naming rule — so the common case needs no extra configuration.
    secret_name: str = ""

    @property
    def uses_vault(self) -> bool:
        return bool(self.vault.strip())

    @property
    def name_in_vault(self) -> str:
        return self.secret_name.strip() or self.env_var.lower().replace("_", "-")

    @property
    def vault_url(self) -> str:
        return f"https://{self.vault.strip()}.vault.azure.net"

    @property
    def vault_host(self) -> str:
        """The hostname the egress allowlist has to permit."""
        return f"{self.vault.strip()}.vault.azure.net" if self.uses_vault else ""


class SecretResolver:
    """Resolves secrets once per process, from a vault or the environment."""

    def __init__(self, env: Mapping[str, str], fetch: object | None = None) -> None:
        self._env = env
        self._cache: dict[str, str] = {}
        # Injectable purely so the gate can exercise the vault path without a
        # vault. Production passes nothing and the real client is imported lazily.
        self._fetch = fetch

    def resolve(self, ref: SecretRef) -> str:
        cache_key = f"{ref.vault}|{ref.name_in_vault}|{ref.env_var}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        value = self._from_vault(ref) if ref.uses_vault else self._env.get(ref.env_var, "")
        if not value:
            raise SecretError(
                f"{ref.env_var} is not set"
                if not ref.uses_vault
                else f"secret {ref.name_in_vault!r} in vault {ref.vault!r} is empty"
            )
        self._cache[cache_key] = value
        return value

    def _from_vault(self, ref: SecretRef) -> str:
        """Fetch from Key Vault. A failure here is fatal, never a fallback."""
        if self._fetch is not None:
            return str(self._fetch(ref))  # type: ignore[operator]
        try:
            from azure.identity import DefaultAzureCredential  # lazy: optional extra
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise SecretError(
                f"a vault is configured ({ref.vault}) but the 'keyvault' extra is "
                "not installed; run: pip install -e '.[keyvault]'"
            ) from exc
        try:
            client = SecretClient(
                vault_url=ref.vault_url, credential=DefaultAzureCredential()
            )
            secret = client.get_secret(ref.name_in_vault)
        except Exception as exc:  # noqa: BLE001 - any auth or transport failure
            # The message names the coordinates, never the value, and never
            # falls back: a run that thinks it read a vault and actually read a
            # stale environment variable is the failure this exists to prevent.
            raise SecretError(
                f"could not read {ref.name_in_vault!r} from vault {ref.vault!r} "
                f"({type(exc).__name__}: {exc}). The environment is NOT used as a "
                "fallback when a vault is configured"
            ) from exc
        return str(secret.value or "")


class SecretPlan(StrictModel):
    """Which secrets this run needs and where each comes from."""

    refs: list[SecretRef] = Field(default_factory=list)

    @property
    def vault_hosts(self) -> list[str]:
        """Hosts the egress allowlist must permit for this plan to work."""
        return sorted({ref.vault_host for ref in self.refs if ref.vault_host})

    def describe(self) -> list[str]:
        return [
            f"{ref.env_var} <- "
            + (f"vault {ref.vault}/{ref.name_in_vault}" if ref.uses_vault else "environment")
            for ref in self.refs
        ]


def build_plan(env: Mapping[str, str]) -> SecretPlan:
    """Work out where each secret comes from, without fetching any of them.

    Separated from resolution so the plan can be printed, and the vault host
    added to the egress allowlist, before a single secret is read.
    """
    vault = (env.get("ENGAGEMENT_KEY_VAULT") or "").strip()
    return SecretPlan(
        refs=[
            SecretRef(
                env_var="FOUNDRY_API_KEY",
                vault=vault,
                secret_name=(env.get("FOUNDRY_KEY_NAME") or "").strip(),
            ),
            SecretRef(
                env_var="SNYK_TOKEN",
                vault=vault,
                secret_name=(env.get("SNYK_KEY_NAME") or "").strip(),
            ),
        ]
    )


def resolve_optional(resolver: SecretResolver, ref: SecretRef) -> str:
    """Resolve a secret that a run can legitimately proceed without.

    Returns ``""`` rather than raising when the secret is simply absent — a run
    with no Snyk token is a normal run. A vault that is *configured and failing*
    still raises, because that is a broken deployment rather than an absent
    optional input.
    """
    try:
        return resolver.resolve(ref)
    except SecretError:
        if ref.uses_vault:
            raise
        return ""
