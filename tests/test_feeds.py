"""Properties of the KEV catalogue and the Snyk inventory.

``test_a_stale_catalogue_is_detectable`` is the one that matters. A stale KEV
file is a suppression surface: every CVE CISA added since the copy was taken
scores as un-exploited, which is the one direction that produces a falsely calm
queue — and it does so silently, because nothing about an old file looks wrong.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from engagement.feeds import (
    CISA_KEV_URL,
    KEV_STALE_AFTER_DAYS,
    FeedError,
    build_snyk_requests,
    load_kev,
    load_snyk,
    parse_kev,
    parse_snyk,
    write_kev,
)

_CISA_SHAPE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.07.28",
    "dateReleased": "2026-07-28T14:00:00.0000Z",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2"},
        {"cveID": "CVE-2023-4863", "vendorProject": "Google", "product": "Chrome"},
    ],
}


# -- KEV ---------------------------------------------------------------------


def test_the_cisa_catalogue_shape_is_read() -> None:
    catalogue = parse_kev(_CISA_SHAPE)

    assert catalogue.ids == {"CVE-2021-44228", "CVE-2023-4863"}
    assert catalogue.catalog_version == "2026.07.28"
    assert catalogue.source == CISA_KEV_URL


def test_a_bare_list_of_ids_is_still_accepted() -> None:
    """Adopting the real feed must be an upgrade, not a breaking change."""
    catalogue = parse_kev(["CVE-2021-44228", "cve-2023-4863"])

    assert catalogue.ids == {"CVE-2021-44228", "CVE-2023-4863"}


def test_a_stale_catalogue_is_detectable() -> None:
    catalogue = parse_kev(_CISA_SHAPE)
    fresh = date(2026, 7, 30)
    stale = date(2026, 9, 1)

    assert catalogue.age_days(fresh) == 2
    assert not catalogue.is_stale(fresh)
    assert catalogue.is_stale(stale), (
        "an old KEV file scores every newly-exploited CVE as un-exploited"
    )


def test_the_staleness_threshold_is_days_not_months() -> None:
    """CISA adds entries most weeks."""
    assert KEV_STALE_AFTER_DAYS <= 30


def test_a_catalogue_with_no_release_date_reports_unknown_age() -> None:
    catalogue = parse_kev(["CVE-2021-44228"])

    assert catalogue.age_days() is None
    assert not catalogue.is_stale()


def test_an_entry_without_a_cve_id_is_an_error_not_a_skip() -> None:
    with pytest.raises(FeedError, match="no cveID"):
        parse_kev({"vulnerabilities": [{"vendorProject": "Apache"}]})


def test_a_catalogue_without_the_list_is_an_error() -> None:
    with pytest.raises(FeedError, match="no 'vulnerabilities' list"):
        parse_kev({"catalogVersion": "1"})


def test_a_cached_catalogue_round_trips_with_its_provenance(tmp_path: Path) -> None:
    written = write_kev(parse_kev(_CISA_SHAPE), tmp_path / "kev.json")
    reloaded = load_kev(written)

    assert reloaded.ids == {"CVE-2021-44228", "CVE-2023-4863"}
    assert reloaded.catalog_version == "2026.07.28"
    assert reloaded.date_released == _CISA_SHAPE["dateReleased"]


def test_a_raw_cisa_download_loads_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(_CISA_SHAPE), encoding="utf-8")

    assert load_kev(path).ids == {"CVE-2021-44228", "CVE-2023-4863"}


def test_an_unreadable_feed_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FeedError, match="unreadable"):
        load_kev(tmp_path / "absent.json")


# -- Snyk --------------------------------------------------------------------


def test_a_snyk_cli_export_yields_components() -> None:
    payload = {
        "packageManager": "npm",
        "vulnerabilities": [
            {"packageName": "lodash", "version": "4.17.15", "title": "Prototype Pollution"},
            {"packageName": "minimist", "version": "0.0.8"},
        ],
    }
    inventory = parse_snyk(payload)

    assert {(c.ecosystem, c.name, c.version) for c in inventory.components} == {
        ("npm", "lodash", "4.17.15"),
        ("npm", "minimist", "0.0.8"),
    }


def test_the_package_manager_is_mapped_to_the_lifecycle_ecosystem() -> None:
    """Snyk says 'pip'; the lifecycle feed says 'pypi'."""
    inventory = parse_snyk(
        {"packageManager": "pip", "vulnerabilities": [{"packageName": "django", "version": "3.2"}]}
    )

    assert inventory.components[0].ecosystem == "pypi"


def test_the_same_component_twice_is_one_entry() -> None:
    payload = {
        "packageManager": "npm",
        "vulnerabilities": [
            {"packageName": "lodash", "version": "4.17.15"},
            {"packageName": "lodash", "version": "4.17.15", "title": "another issue"},
        ],
    }

    assert len(parse_snyk(payload).components) == 1


def test_an_aggregated_issues_response_is_read() -> None:
    payload = {
        "issues": [
            {"pkgName": "log4j-core", "pkgVersions": ["2.14.1"], "name": "log4j-core",
             "version": "2.14.1", "type": "maven"},
        ]
    }

    assert parse_snyk(payload).components[0].name == "log4j-core"


def test_an_export_with_no_components_says_so() -> None:
    inventory = parse_snyk({"ok": True})

    assert inventory.components == []
    assert any("not the same as a clean result" in w for w in inventory.warnings)


def test_the_inventory_feeds_the_lifecycle_pass_directly(tmp_path: Path) -> None:
    """The blind spot only closes if this hands over in the expected shape."""
    path = tmp_path / "snyk.json"
    export = {
        "packageManager": "pip",
        "vulnerabilities": [{"packageName": "django", "version": "3.2.1"}],
    }
    path.write_text(json.dumps(export), encoding="utf-8")
    from datetime import date as _date

    from engagement.lifecycle import Cycle, LifecycleState, PackageLifecycle, assess

    package = PackageLifecycle(
        ecosystem="pypi", name="django", cycles=[Cycle(cycle="3.2", eol=_date(2024, 4, 1))]
    )
    report = assess(
        [], {package.key: package}, as_of=_date(2026, 8, 1), inventory=load_snyk(path).tuples()
    )

    assert report.assessments[0].state is LifecycleState.eol


def test_a_snyk_token_never_appears_in_a_url() -> None:
    """A token in a path is captured by every proxy and access log in between."""
    shape = build_snyk_requests("org-123")

    assert "org-123" in shape["projects"]
    for url in (shape["projects"], shape["issues"]):
        assert "token" not in url.lower()
    assert shape["headers"]["authorization"].startswith("token ")


def test_a_malformed_export_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(FeedError, match="not valid JSON"):
        load_snyk(path)
