"""Offline component matching: affected/unaffected/boundary/ambiguous/unknown."""

import pytest

from app import matching


def comp(product, version, source="runtime", **extra):
    return {"product": product, "version": version, "source": source,
            "evidence": f"{source} evidence", "observed_at": "2026-10-10T03:06:00+00:00", **extra}


def run(cve_db, *components):
    return matching.match_components(list(components), cve_db)["components"]


def by_cve(result):
    return {m["cve_id"]: m for m in result["matches"]}


def test_affected_version_is_version_match_not_confirmed(cve_db):
    [r] = run(cve_db, comp("jquery", "3.4.1"))
    m = by_cve(r)
    assert m["CVE-2020-11022"]["category"] == "version_match"
    assert "exploitability was not tested" in m["CVE-2020-11022"]["rationale"]
    assert "CVE-2019-11358" not in m           # 3.4.1 >= 3.4.0 (exclusive end)
    assert r["lookup_status"] == "matched"


@pytest.mark.parametrize("version,affected", [
    ("1.2.0", True),     # start inclusive boundary
    ("1.1.4", False),    # below start
    ("3.4.99", True),
    ("3.5.0", False),    # end exclusive boundary
    ("3.10.0", False),   # numeric > 3.5 (lexicographic compare would say affected)
])
def test_range_boundaries(cve_db, version, affected):
    [r] = run(cve_db, comp("jquery", version))
    assert ("CVE-2020-11022" in by_cve(r)) is affected


@pytest.mark.parametrize("version,affected", [
    ("3.6.0", False),    # start exclusive
    ("3.6.1", True),
    ("3.6.4", True),     # end inclusive
    ("3.6.5", False),
])
def test_exclusive_start_inclusive_end(cve_db, version, affected):
    [r] = run(cve_db, comp("jquery", version))
    assert ("CVE-2099-0001" in by_cve(r)) is affected


def test_unaffected_version_reports_no_match_in_available_data(cve_db):
    [r] = run(cve_db, comp("jquery", "3.7.1"))
    assert r["matches"] == []
    assert r["lookup_status"] == "no_match_in_available_data"
    assert r["not_affected_count"] >= 4


def test_rejected_records_are_skipped(cve_db):
    [r] = run(cve_db, comp("jquery", "3.7.1"))
    assert "CVE-2099-0002" not in by_cve(r)
    assert r["rejected_skipped"] == 1


def test_configuration_prerequisite_downgrades_to_potential(cve_db):
    [r] = run(cve_db, comp("jquery", "3.6.2"))
    m = by_cve(r)["CVE-2099-0003"]
    assert m["category"] == "potential"
    assert any("configuration prerequisite" in u for u in m["uncertainty"])


def test_unanalysed_nvd_record_is_potential(cve_db):
    [r] = run(cve_db, comp("jquery", "2.1.0"))
    assert by_cve(r)["CVE-2099-0005"]["category"] == "potential"


def test_ambiguous_identity_is_potential(cve_db):
    [r] = run(cve_db, comp("angular", "1.8.2", source="bundle"))
    assert r["identity"]["confidence"] == "ambiguous"
    m = by_cve(r)["CVE-2022-25844"]
    assert m["category"] == "potential"
    assert any("identity ambiguous" in u for u in m["uncertainty"])


def test_bundle_filename_is_medium_confidence_potential(cve_db):
    [r] = run(cve_db, comp("jquery", "3.4.1", source="bundle"))
    assert r["identity"]["confidence"] == "medium"
    assert {m["category"] for m in r["matches"]} == {"potential"}


def test_prerelease_is_potential(cve_db):
    [r] = run(cve_db, comp("jquery", "3.5.0-beta.1"))
    m = by_cve(r)["CVE-2020-11022"]       # pre-release precedes 3.5.0 -> in range
    assert m["category"] == "potential"
    assert any("pre-release" in u for u in m["uncertainty"])


def test_cpe_update_prerelease_exact_match(cve_db):
    [r] = run(cve_db, comp("express", "5.0.0-alpha.1", source="x-powered-by"))
    # Express header token is medium confidence, so the match is potential.
    assert "CVE-2024-29041" in by_cve(r)
    [r2] = run(cve_db, comp("express", "5.0.0", source="x-powered-by"))
    assert "CVE-2024-29041" not in by_cve(r2)          # final 5.0.0 not listed


def test_distribution_build_is_potential(cve_db):
    [r] = run(cve_db, comp("nginx", "1.18.0-6ubuntu14", source="server"))
    m = by_cve(r)["CVE-2021-23017"]
    assert m["category"] == "potential"
    assert any("back-ported" in u for u in m["uncertainty"])
    [r2] = run(cve_db, comp("nginx", "1.18.0", source="server",
                            distribution_hint="Ubuntu"))
    assert by_cve(r2)["CVE-2021-23017"]["category"] == "potential"
    [r3] = run(cve_db, comp("nginx", "1.18.0", source="server"))
    assert by_cve(r3)["CVE-2021-23017"]["category"] == "version_match"


def test_legacy_and_current_cpe_vendors_both_used(cve_db):
    [r] = run(cve_db, comp("nginx", "1.4.0", source="server"))
    assert {"CVE-2013-2028", "CVE-2021-23017"} <= set(by_cve(r))


def test_openssl_letter_versions(cve_db):
    [a] = run(cve_db, comp("openssl", "1.1.1k", source="server"))
    [b] = run(cve_db, comp("openssl", "1.1.1l", source="server"))
    assert "CVE-2021-3711" in by_cve(a) and "CVE-2021-3711" not in by_cve(b)


def test_unparseable_version_is_unknown(cve_db):
    [r] = run(cve_db, comp("jquery", "latest"))
    assert r["lookup_status"] == "version_unparseable" and r["matches"] == []
    assert any("unknown" in x for x in r["limitations"])


def test_missing_coverage_is_unknown_not_clean(cve_db):
    [r] = run(cve_db, comp("react", "16.4.0"))
    assert r["lookup_status"] == "coverage_missing"


def test_missing_database_is_unknown(tmp_path):
    [r] = matching.match_components([comp("jquery", "3.4.1")], tmp_path / "none.db")["components"]
    assert r["lookup_status"] == "db_missing" and r["matches"] == []


def test_unrecognized_component(cve_db):
    [r] = run(cve_db, comp("someframework", "1.0.0", source="bundle"))
    assert r["lookup_status"] == "unrecognized"


def test_stale_coverage_is_reported(cve_db, monkeypatch):
    monkeypatch.setenv("SAS_CVEDB_STALE_DAYS", "0")
    [r] = run(cve_db, comp("jquery", "3.4.1"))
    assert r["coverage"]["state"] == "stale"
    assert any("stale" in x for x in r["limitations"])
