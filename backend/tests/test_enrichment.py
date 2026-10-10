"""Finding statuses, remediation, enrichment persistence, exports."""

import asyncio
import csv
import io
import json

import pytest

from app import enrichment, findings, remediation, reports

JQ = {"product": "jquery", "version": "3.4.1", "header": "runtime", "source": "runtime",
      "evidence": "window.jQuery.fn.jquery", "observed_at": "2026-10-10T03:06:00+00:00",
      "distribution_hint": None}


def fake_fp(components=(JQ,), notes=()):
    calls = []

    async def fp(target):
        calls.append(target)
        return [dict(c) for c in components], list(notes)
    fp.calls = calls
    return fp


def run(scan_dir, cve_db, **kw):
    kw.setdefault("fingerprint_fn", fake_fp())
    return asyncio.run(enrichment.run("fixtureid", scan_dir, db_path=cve_db, **kw))


# -- finding statuses ---------------------------------------------------------

def test_evidence_categories_preserve_scanner_values(report):
    s = findings.summarize(report)
    cats = {i["finding_id"]: i for i in s["items"]}
    assert cats["v1"]["evidence_category"] == "confirmed"            # Confirmed + PoC
    assert cats["v2"]["evidence_category"] == "potential"
    assert cats["v4"]["evidence_category"] == "dismissed"
    assert cats["v5"]["evidence_category"] == "unknown"
    assert cats["v1"]["scanner_status"] == "Confirmed" and cats["v1"]["scanner_confidence"] == 0.95
    assert s["checks"] == {"passed": 1, "vulnerable": 1, "inconclusive": 1,
                           "skipped": 1, "failed": 1}


def test_confirmed_without_evidence_is_potential():
    c = findings.classify_vulnerability({"id": "x", "status": "Confirmed"})
    assert c["evidence_category"] == "potential" and c["scanner_status"] == "Confirmed"


def test_summary_view_no_longer_calls_everything_confirmed(report):
    v = reports.summary_view(report)
    # v1 has PoC evidence; v3 is scanner-"Confirmed" without evidence -> potential.
    assert v["stats"]["confirmed_findings"] == 1
    assert v["stats"]["potential_findings"] == 2
    assert v["stats"]["vulnerabilities"] == 5           # legacy total kept
    assert "1 confirmed security finding" in v["headline"]
    assert "2 potential findings needing validation" in v["headline"]
    assert "5 confirmed" not in v["headline"]
    assert v["findings"][0]["evidence_category"] == "confirmed"
    assert v["charts"]["severity"]["Low"] == 0           # dismissed v4 excluded
    nonzero = lambda d: {k: n for k, n in d.items() if n}  # noqa: E731
    assert nonzero(v["charts"]["severity_by_status"]["potential"]) == {"High": 1, "Medium": 1}
    assert nonzero(v["charts"]["severity_by_status"]["confirmed"]) == {"Critical": 1}
    v3 = next(f for f in v["findings"] if f["finding_id"] == "v3")
    assert v3["status"] == "Confirmed" and v3["evidence_category"] == "potential"


def test_headline_basic_level_without_findings():
    v = reports.summary_view({"summary": {}, "vulnerabilities": [], "endpoints": {}})
    assert "did not run" in v["headline"]


# -- remediation --------------------------------------------------------------

def test_remediation_never_invents_patch_versions(report, cve_db):
    data = run_sync_enrichment(report, cve_db)
    comp = next(r for r in data["remediation"] if r["kind"] == "component")
    assert comp["upgrade"]["verified"] is False and comp["upgrade"]["versions"] == []
    assert "3.5.0" in comp["upgrade"]["basis"] and "vendor advisory" in comp["upgrade"]["basis"]
    assert any("Mitigation" in w["note"] for w in comp["workarounds"])
    assert comp["verification"] and comp["uncertainty"]
    assert not any("javascript:" in u for u in comp["references"])
    beh = next(r for r in data["remediation"] if r.get("finding_id") == "v1")
    assert beh["actions"][0].startswith("Scanner recommendation:")
    assert any("owasp.org" in u for u in beh["references"])
    assert all("has been" not in a.lower() for a in beh["actions"])
    assert not any(r.get("finding_id") == "v4" for r in data["remediation"])  # dismissed


def test_remediation_verified_upgrade_only_when_documented():
    comp = {"component_id": "comp-1", "identity": {"display": "X"}, "observed_version": "1.0",
            "limitations": [], "matches": [{
                "cve_id": "CVE-2099-1", "category": "version_match", "uncertainty": [],
                "references": [], "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-1",
                "affected_ranges": [{"fixed_version": "1.2.0", "end_excluding": "1.2.0"}]}]}
    rem = remediation.for_component(comp)
    assert rem["upgrade"] == {"verified": True, "versions": ["1.2.0"],
                              "basis": rem["upgrade"]["basis"]}


def run_sync_enrichment(report, cve_db, tmp=None):
    import tempfile, shutil, pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    from tests.conftest import FIXTURES
    for f in FIXTURES.glob("scan_report_*"):
        shutil.copy(f, d / f.name)
    (d / "scan_report_20261010_030500.json").write_text(json.dumps(report))
    return asyncio.run(enrichment.run("x1", d, db_path=cve_db, fingerprint_fn=fake_fp()))


# -- enrichment pipeline --------------------------------------------------------

def test_behavioral_findings_never_get_cves(scan_dir, cve_db):
    data = run(scan_dir, cve_db)
    # CVE-2099-0004 shares CWE-639 with the BOLA finding v1 but must only be a
    # component match, never attached to the behavioural finding.
    beh = {i["finding_id"]: i for i in data["findings"]["items"]}
    assert all("cve" not in json.dumps(i).lower() for i in beh.values())
    matches = [m for c in data["cve_matching"]["components"] for m in c["matches"]]
    assert {m["cve_id"] for m in matches} >= {"CVE-2020-11022", "CVE-2099-0004"}
    assert all(m["component"] == "jQuery" for m in matches)


def test_counts_do_not_double_count(scan_dir, cve_db):
    data = run(scan_dir, cve_db)
    c = data["counts"]
    assert c["behavioral_confirmed"] == 1 and c["behavioral_potential"] == 2
    assert c["cve_version_matches"] >= 2
    assert c["checks_incomplete"] == 3


def test_enrichment_persists_and_reloads(scan_dir, cve_db):
    data = run(scan_dir, cve_db)
    assert data["status"] == "completed"
    reloaded = enrichment.load(scan_dir)
    assert reloaded["counts"] == data["counts"]
    assert reloaded["schema_version"] == 1
    assert reloaded["components_observed_at"]
    assert (scan_dir / enrichment.ENRICHED_HTML).exists()


def test_recheck_archives_previous_and_gets_new_timestamp(scan_dir, cve_db):
    first = run(scan_dir, cve_db)
    fp = fake_fp()
    second = run(scan_dir, cve_db, trigger="recheck", fingerprint_fn=fp)
    assert fp.calls == ["https://app.example.test/"]
    assert second["trigger"] == "recheck" and len(second["history"]) == 1
    assert list((scan_dir / "enrichment_history").glob("*.json"))
    assert second["started_at"] >= first["completed_at"]


def test_offline_rematch_does_not_contact_target(scan_dir, cve_db):
    run(scan_dir, cve_db)
    fp = fake_fp()
    data = run(scan_dir, cve_db, trigger="rematch", refingerprint=False, fingerprint_fn=fp)
    assert fp.calls == []
    assert "not contacted" in data["stages"]["fingerprint"]["source"]
    assert data["cve_matching"]["components"][0]["matches"]


def test_missing_database_is_partial_not_clean(scan_dir, tmp_path):
    data = asyncio.run(enrichment.run("x", scan_dir, db_path=tmp_path / "none.db",
                                      fingerprint_fn=fake_fp()))
    assert data["status"] == "partial"
    assert data["stages"]["cve_matching"]["status"] == "skipped"
    assert "unknown" in data["stages"]["cve_matching"]["reason"]
    assert data["cve_matching"]["components"][0]["lookup_status"] == "db_missing"


def test_fingerprint_failure_is_partial(scan_dir, cve_db):
    async def boom(target):
        raise RuntimeError("browser crashed")
    data = run(scan_dir, cve_db, fingerprint_fn=boom)
    assert data["status"] == "partial"
    assert data["stages"]["fingerprint"]["status"] == "failed"
    assert data["findings"]["counts"]["confirmed"] == 1      # rest still produced


def test_ai_failure_does_not_fail_enrichment(scan_dir, cve_db, monkeypatch):
    monkeypatch.setenv("SAS_AI_ENABLED", "1")
    monkeypatch.setenv("SAS_AI_API_KEY", "sk-ant-test-abcdefghijklmnop")

    async def broken(*a, **k):
        raise RuntimeError("provider exploded")
    monkeypatch.setattr("app.ai_analysis._call_anthropic", broken)
    data = run(scan_dir, cve_db)
    assert data["ai_analysis"]["status"] == "failed"
    assert data["status"] == "partial"
    assert data["remediation"]                                # deterministic fallback
    assert "sk-ant-test" not in json.dumps(data)


def test_interrupted_run_marked_failed(scan_dir):
    enrichment.save(scan_dir, {"schema_version": 1, "status": "running", "stages": {}})
    enrichment.mark_interrupted(scan_dir)
    assert enrichment.load(scan_dir)["status"] == "failed"


def test_old_documents_upgrade():
    assert enrichment.upgrade({"status": "completed"})["history"] == []


# -- exports --------------------------------------------------------------------

def test_csv_keeps_legacy_columns_and_adds_records(scan_dir, cve_db, report):
    data = run(scan_dir, cve_db)
    text = reports.export_csv(report, data)
    rows = list(csv.reader(io.StringIO(text)))
    header = rows[0]
    assert header[:11] == reports.LEGACY_CSV_COLUMNS
    assert header[11:] == reports.ADDITIVE_CSV_COLUMNS
    assert all(len(r) == len(header) for r in rows)
    types = [r[header.index("record_type")] for r in rows[1:]]
    assert types.count("behavioral_finding") == 5
    assert "component_cve_match" in types
    cve_rows = [r for r in rows[1:] if r[header.index("record_type")] == "component_cve_match"]
    assert all(r[header.index("status")].startswith(("Version match", "Potential", "Unknown"))
               for r in cve_rows)


def test_csv_formula_injection_neutralised(report):
    text = reports.export_csv(report, None)
    assert "'=HYPERLINK" in text and ",'-cmd" in text
    rows = list(csv.reader(io.StringIO(text)))
    for r in rows[1:]:
        for cell in r:
            assert not cell.startswith(("=", "+", "@", "-"))


def test_csv_without_enrichment_still_valid(report):
    rows = list(csv.reader(io.StringIO(reports.export_csv(report))))
    assert len(rows) == 6


def test_json_export_is_additive(report, scan_dir, cve_db):
    data = run(scan_dir, cve_db)
    out = reports.export_json(report, data)
    assert {k: out[k] for k in report} == report
    assert out["enrichment"]["schema_version"] == 1


def test_enriched_html_escapes_and_matches_ui_content(scan_dir, cve_db):
    evil = dict(JQ, evidence="<script>alert(1)</script>")
    data = run(scan_dir, cve_db, fingerprint_fn=fake_fp((evil,)))
    html = (scan_dir / enrichment.ENRICHED_HTML).read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "CVE-2020-11022" in html and "Version match" in html
    assert "Potential" in html and "Remediation" in html
    assert 'href="javascript:' not in html
    assert html.index("sas-enrichment") < html.lower().rindex("</body>")
    assert "Scanner report" in html                      # original content preserved
