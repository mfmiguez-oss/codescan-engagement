"""Exploit intelligence and component inventory, from their sources.

Two feeds, both fetched deliberately rather than bundled, and both cached to
disk so the gate and every scan stay offline by default.

**KEV, from CISA.** The Known Exploited Vulnerabilities catalogue is the single
highest-signal input the score has: it is the difference between "someone
published a CVE" and "someone is using it". It is published by CISA at a stable
URL, and this fetches from there rather than from a copy — a hand-maintained KEV
file drifts, and a stale KEV file is a *suppression surface*: every CVE added
since the copy was taken scores as un-exploited, which is the one direction that
produces a falsely calm queue. So the catalogue's own `catalogVersion` and
`dateReleased` travel with the cache, and :func:`kev_age_days` lets the pipeline
report an old feed rather than trust it silently.

**Snyk, for the component inventory.** The lifecycle pass can only check
components it knows about, and a source-only review carries no dependency list —
which is exactly why an unmaintained package slips through. Snyk already knows
that list. This reads it two ways: from a saved export (offline, no credentials)
or from the API against an organisation (needs a token). Either way the output
is a plain inventory the lifecycle pass consumes, so no credential is required
to *use* the result.

Nothing here is imported at module load beyond the standard library; the HTTP
client is loaded inside the fetch functions, so the package still installs and
its gate still runs with no network stack present.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from .contracts import StrictModel

#: CISA's published catalogue. Stable, unauthenticated, and the authority — a
#: mirror is a copy of a thing that changes daily.
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

#: Beyond this, the catalogue is reported as stale. CISA adds entries most
#: weeks, so a fortnight-old copy is already missing exploited CVEs.
KEV_STALE_AFTER_DAYS = 14


class FeedError(RuntimeError):
    """A feed could not be fetched or parsed."""


class KevCatalogue(StrictModel):
    """The KEV catalogue, with the provenance needed to judge its age."""

    vulnerability_ids: list[str] = Field(default_factory=list)
    catalog_version: str = ""
    date_released: str = ""
    source: str = CISA_KEV_URL
    fetched_at: str = ""

    @property
    def ids(self) -> set[str]:
        return {vid.strip().upper() for vid in self.vulnerability_ids if vid.strip()}

    def age_days(self, as_of: date | None = None) -> int | None:
        """Days since CISA released this catalogue, if it says."""
        stamp = (self.date_released or "")[:10]
        if not stamp:
            return None
        try:
            released = date.fromisoformat(stamp)
        except ValueError:
            return None
        return max(0, ((as_of or datetime.now(UTC).date()) - released).days)

    def is_stale(self, as_of: date | None = None) -> bool:
        age = self.age_days(as_of)
        return age is not None and age > KEV_STALE_AFTER_DAYS


def parse_kev(payload: object, source: str = CISA_KEV_URL) -> KevCatalogue:
    """Read CISA's catalogue shape, or a bare list of ids.

    Both are accepted because the estate already has plain-list KEV files in
    fixtures, and refusing them would make adopting the real feed a breaking
    change rather than an upgrade.
    """
    if isinstance(payload, list):
        return KevCatalogue(
            vulnerability_ids=[str(item) for item in payload],
            source=source,
            fetched_at=datetime.now(UTC).isoformat(),
        )
    if not isinstance(payload, dict):
        raise FeedError("KEV feed is neither a catalogue object nor a list of ids")

    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise FeedError("KEV catalogue has no 'vulnerabilities' list")
    ids: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise FeedError(f"KEV vulnerabilities[{index}] is not an object")
        cve = str(entry.get("cveID", "")).strip()
        if not cve:
            raise FeedError(f"KEV vulnerabilities[{index}] has no cveID")
        ids.append(cve)
    return KevCatalogue(
        vulnerability_ids=ids,
        catalog_version=str(payload.get("catalogVersion", "")),
        date_released=str(payload.get("dateReleased", "")),
        source=source,
        fetched_at=datetime.now(UTC).isoformat(),
    )


def load_kev(path: Path) -> KevCatalogue:
    """Read a cached catalogue from disk. Never touches the network."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise FeedError(f"KEV feed unreadable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FeedError(f"KEV feed is not valid JSON: {exc}") from exc
    if isinstance(payload, dict) and "vulnerability_ids" in payload:
        return KevCatalogue.model_validate(payload)  # a cache this module wrote
    return parse_kev(payload, source=str(path))


def fetch_kev(url: str = CISA_KEV_URL, timeout: float = 60.0) -> KevCatalogue:
    """Fetch the catalogue from CISA. The only outbound call in this module."""
    import httpx  # lazy: optional extra, and never reached offline

    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - any transport failure is one error here
        raise FeedError(f"could not fetch the KEV catalogue from {url}: {exc}") from exc
    return parse_kev(payload, source=url)


def write_kev(catalogue: KevCatalogue, path: Path) -> Path:
    """Cache a catalogue where an offline run can read it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(catalogue.model_dump_json(indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Snyk: the component inventory the lifecycle pass needs
# ---------------------------------------------------------------------------


class Component(StrictModel):
    """One dependency, as the lifecycle pass wants it."""

    ecosystem: str = ""
    name: str
    version: str = ""

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


class Inventory(StrictModel):
    """What a source knew about a repository's dependencies."""

    components: list[Component] = Field(default_factory=list)
    source: str = ""
    warnings: list[str] = Field(default_factory=list)

    def tuples(self) -> list[tuple[str, str, str]]:
        return [component.as_tuple() for component in self.components]


#: Snyk package types mapped onto the ecosystem names the lifecycle feed uses.
_ECOSYSTEM = {
    "npm": "npm",
    "yarn": "npm",
    "pip": "pypi",
    "poetry": "pypi",
    "maven": "maven",
    "gradle": "maven",
    "nuget": "nuget",
    "composer": "packagist",
    "rubygems": "rubygems",
    "golangdep": "go",
    "gomodules": "go",
    "cocoapods": "cocoapods",
    "hex": "hex",
    "cargo": "cargo",
}


def _ecosystem_of(raw: object) -> str:
    return _ECOSYSTEM.get(str(raw or "").strip().lower(), str(raw or "").strip().lower())


def parse_snyk(payload: object, source: str = "snyk") -> Inventory:
    """Pull components out of a Snyk export or API response.

    Snyk's shapes differ between the CLI's `test --json`, the v1 issues API and
    a project listing, so this reads the union rather than one of them: any
    object carrying a package name and version contributes a component. Being
    permissive is right here — a component this misses is a component the
    lifecycle pass cannot check, and the cost of a spurious one is a lookup that
    finds nothing.
    """
    inventory = Inventory(source=source)
    seen: set[tuple[str, str, str]] = set()

    def add(name: object, version: object, ecosystem: object) -> None:
        cleaned = str(name or "").strip()
        if not cleaned:
            return
        component = Component(
            ecosystem=_ecosystem_of(ecosystem),
            name=cleaned,
            version=str(version or "").strip(),
        )
        key = component.as_tuple()
        if key not in seen:
            seen.add(key)
            inventory.components.append(component)

    def walk(node: object, inherited_type: object = "") -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, inherited_type)
            return
        if not isinstance(node, dict):
            return
        package_type = node.get("packageManager") or node.get("type") or inherited_type
        name = node.get("packageName") or node.get("name") or node.get("package")
        version = node.get("version") or node.get("packageVersion")
        if name and (version or node.get("packageName")):
            add(name, version, package_type)
        for key in ("vulnerabilities", "issues", "dependencies", "projects", "data"):
            if key in node:
                walk(node[key], package_type)

    walk(payload)
    if not inventory.components:
        inventory.warnings.append(
            "snyk: no components found in this export — the lifecycle pass will "
            "have nothing extra to check, which is not the same as a clean result"
        )
    return inventory


def load_snyk(path: Path) -> Inventory:
    """Read a saved Snyk export. Offline, no credentials."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise FeedError(f"Snyk export unreadable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FeedError(f"Snyk export is not valid JSON: {exc}") from exc
    return parse_snyk(payload, source=str(path))


def build_snyk_requests(org_id: str, api_url: str = "https://api.snyk.io") -> dict[str, Any]:
    """The exact calls a live Snyk pull would make — pure, asserted offline.

    The token travels in an ``Authorization`` header and never in the URL, so it
    cannot be captured by a proxy or access log that records the path. Returned
    rather than sent, so the request *shape* is testable without a credential.
    """
    root = api_url.rstrip("/")
    return {
        "projects": f"{root}/v1/org/{org_id}/projects",
        "issues": f"{root}/v1/org/{org_id}/project/{{project_id}}/aggregated-issues",
        "headers": {"authorization": "token <SNYK_TOKEN>", "content-type": "application/json"},
    }


def fetch_snyk(org_id: str, token: str, api_url: str = "https://api.snyk.io") -> Inventory:
    """Pull every project's dependencies for one Snyk organisation."""
    import httpx  # lazy: optional extra

    shape = build_snyk_requests(org_id, api_url)
    headers = {"authorization": f"token {token}", "content-type": "application/json"}
    inventory = Inventory(source=f"snyk:{org_id}")
    try:
        projects = httpx.get(shape["projects"], headers=headers, timeout=60.0)
        projects.raise_for_status()
        listing = projects.json()
    except Exception as exc:  # noqa: BLE001
        raise FeedError(f"could not list Snyk projects for org {org_id}: {exc}") from exc

    entries = listing.get("projects") if isinstance(listing, dict) else listing
    for project in entries if isinstance(entries, list) else []:
        if not isinstance(project, dict) or not project.get("id"):
            continue
        url = str(shape["issues"]).format(project_id=project["id"])
        try:
            issues = httpx.post(url, headers=headers, json={}, timeout=60.0)
            issues.raise_for_status()
            found = parse_snyk(issues.json(), source=f"snyk:{org_id}")
        except Exception as exc:  # noqa: BLE001 - one project must not sink the pull
            inventory.warnings.append(
                f"snyk: project {project.get('name', project['id'])} was not read ({exc}); "
                "its components are not covered by the lifecycle check"
            )
            continue
        known = {component.as_tuple() for component in inventory.components}
        inventory.components += [
            component for component in found.components if component.as_tuple() not in known
        ]
    return inventory
