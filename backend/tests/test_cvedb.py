"""Local CVE database: import, NVD pagination/rate limits/retries, atomic updates."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import cvedb
from app.nvd_client import NvdClient, NvdError, lastmod_windows


def _items(fixtures, name):
    return json.loads((fixtures / name).read_text())["vulnerabilities"]


def _paged_transport(items, calls, fail_at=None, status_seq=None):
    """Serve ``items`` in pages honouring startIndex/resultsPerPage."""
    seq = list(status_seq or [])

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if seq:
            code = seq.pop(0)
            if code != 200:
                return httpx.Response(code, headers={"retry-after": "1"})
        start = int(request.url.params["startIndex"])
        size = int(request.url.params["resultsPerPage"])
        if fail_at is not None and start >= fail_at:
            return httpx.Response(500)
        page = items[start:start + size]
        return httpx.Response(200, json={"totalResults": len(items), "startIndex": start,
                                         "resultsPerPage": size, "vulnerabilities": page})
    return httpx.MockTransport(handler)


def _client(transport, sleeps, key=None, page_size=2, retries=3):
    return NvdClient(api_key=key, http=httpx.Client(transport=transport),
                     sleep=sleeps.append, page_size=page_size, max_retries=retries)


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_import_populates_schema_and_references(cve_db):
    rows = cvedb.candidate_ranges("jquery", cve_db)
    ids = {r["cve_id"] for r in rows}
    assert {"CVE-2020-11022", "CVE-2019-11358", "CVE-2099-0003"} <= ids
    r = next(r for r in rows if r["cve_id"] == "CVE-2020-11022")
    assert r["start_incl"] == "1.2" and r["end_excl"] == "3.5.0"
    assert r["cvss_score"] == 6.1 and r["cvss_version"] == "3.1"
    assert r["cvss_vector"].startswith("CVSS:3.1/") and r["severity"] == "Medium"
    assert r["vuln_status"] == "Analyzed" and r["record_source"].startswith("import:")
    urls = [x["url"] for x in r["references"]]
    assert "javascript:alert(1)" not in urls            # unsafe URL dropped
    assert any("GHSA" in u for u in urls)
    cfg = next(r for r in rows if r["cve_id"] == "CVE-2099-0003")
    assert cfg["requires_config"] == 1 and "appliance_os" in cfg["config_note"]


def test_status_reports_coverage_and_staleness(cve_db):
    st = cvedb.status(cve_db)
    comps = {c["component"]: c["coverage"] for c in st["components"]}
    assert comps["jquery"] == "complete"
    assert comps["react"] == "missing"          # never imported
    assert st["state"] == "partial"
    future = lambda: datetime.now(timezone.utc) + timedelta(days=30)  # noqa: E731
    st2 = cvedb.status(cve_db, now=future)
    comps2 = {c["component"]: c["coverage"] for c in st2["components"]}
    assert comps2["jquery"] == "stale"


def test_missing_database_status(tmp_path):
    st = cvedb.status(tmp_path / "nope.sqlite3")
    assert st["state"] == "missing" and "populate" in st["message"]


def test_import_without_complete_flag_is_partial(tmp_path, fixtures):
    path = tmp_path / "db.sqlite3"
    cvedb.import_files([fixtures / "nvd_jquery.json"], path)
    cov = cvedb.coverage_for("jquery", path)
    assert cov["coverage"] == "partial"


def test_nvd_pagination_downloads_every_page(tmp_path, fixtures):
    items = _items(fixtures, "nvd_jquery.json")          # 7 items, page size 2 -> 4 pages
    calls, sleeps = [], []
    client = _client(_paged_transport(items, calls), sleeps)
    path = tmp_path / "db.sqlite3"
    res = cvedb.update_from_nvd(path, mode="full", pairs=[("jquery", "jquery")], client=client)
    assert res["status"] == "success"
    assert len(calls) == 4
    assert [int(c.url.params["startIndex"]) for c in calls] == [0, 2, 4, 6]
    assert calls[0].url.params["virtualMatchString"] == "cpe:2.3:a:jquery:jquery"
    assert len({r["cve_id"] for r in cvedb.candidate_ranges("jquery", path)}) == 7
    assert cvedb.coverage_for("jquery", path)["coverage"] == "complete"


def test_rate_limit_window_without_key(tmp_path, fixtures):
    items = _items(fixtures, "nvd_jquery.json") * 2       # many pages
    for i, it in enumerate(items):                         # unique ids
        it = json.loads(json.dumps(it)); it["cve"]["id"] = f"CVE-2098-{1000 + i}"; items[i] = it
    calls, sleeps = [], []
    client = _client(_paged_transport(items, calls), sleeps, page_size=2)
    cvedb.update_from_nvd(tmp_path / "db.sqlite3", mode="full",
                          pairs=[("jquery", "jquery")], client=client)
    assert len(calls) == 7
    # 4 requests per rolling 30 s without a key -> the client must have slept.
    assert sleeps and all(s > 0 for s in sleeps)


def test_api_key_sent_only_in_header(tmp_path, fixtures):
    calls, sleeps = [], []
    client = _client(_paged_transport(_items(fixtures, "nvd_nginx.json"), calls), sleeps,
                     key="nvd-test-key-123456")
    cvedb.update_from_nvd(tmp_path / "db.sqlite3", mode="full", pairs=[("f5", "nginx")],
                          client=client)
    assert calls[0].headers["apiKey"] == "nvd-test-key-123456"
    assert "nvd-test-key" not in str(calls[0].url)


def test_retries_transient_errors_then_succeeds(tmp_path, fixtures):
    calls, sleeps = [], []
    client = _client(_paged_transport(_items(fixtures, "nvd_nginx.json"), calls,
                                      status_seq=[503, 429]), sleeps)
    res = cvedb.update_from_nvd(tmp_path / "db.sqlite3", mode="full",
                                pairs=[("f5", "nginx")], client=client)
    assert res["status"] == "success"
    assert len(calls) == 3 and 1.0 in sleeps        # honoured Retry-After


def test_failed_update_preserves_previous_database(cve_db, fixtures):
    before = _digest(cve_db)
    calls, sleeps = [], []
    items = _items(fixtures, "nvd_jquery.json")
    client = _client(_paged_transport(items, calls, fail_at=4), sleeps, retries=1)
    with pytest.raises(NvdError):
        cvedb.update_from_nvd(cve_db, mode="full", pairs=[("jquery", "jquery")], client=client)
    assert _digest(cve_db) == before                      # byte-identical
    last = cvedb.read_lastrun(cve_db)
    assert last["status"] == "failed" and "unchanged" in last["note"]
    assert not list(cve_db.parent.glob("*.staging-*"))  # staged copy cleaned up
    assert "failed" in cvedb.status(cve_db)["message"]


def test_bad_request_is_not_retried(tmp_path):
    calls, sleeps = [], []
    t = httpx.MockTransport(lambda r: (calls.append(r), httpx.Response(400))[1])
    client = _client(t, sleeps)
    with pytest.raises(NvdError):
        cvedb.update_from_nvd(tmp_path / "db.sqlite3", mode="full",
                              pairs=[("jquery", "jquery")], client=client)
    assert len(calls) == 1
    assert not (tmp_path / "db.sqlite3").exists()


def test_incremental_update_uses_lastmod_window(cve_db, fixtures):
    calls, sleeps = [], []
    client = _client(_paged_transport([], calls), sleeps)
    res = cvedb.update_from_nvd(cve_db, mode="incremental", pairs=[("jquery", "jquery")],
                                client=client)
    assert res["products"][0]["mode"] == "incremental"
    p = calls[0].url.params
    assert "lastModStartDate" in p and "lastModEndDate" in p
    # Previously imported data is retained.
    assert cvedb.candidate_ranges("jquery", cve_db)


def test_incremental_applies_modified_records(cve_db, fixtures):
    item = json.loads(json.dumps(_items(fixtures, "nvd_jquery.json")[0]))
    item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 6.9
    calls, sleeps = [], []
    client = _client(_paged_transport([item], calls), sleeps)
    cvedb.update_from_nvd(cve_db, mode="incremental", pairs=[("jquery", "jquery")],
                          client=client)
    r = next(r for r in cvedb.candidate_ranges("jquery", cve_db) if r["cve_id"] == "CVE-2020-11022")
    assert r["cvss_score"] == 6.9
    assert sum(1 for x in cvedb.candidate_ranges("jquery", cve_db)
               if x["cve_id"] == "CVE-2020-11022") == 1          # replaced, not duplicated


def test_lastmod_windows_respect_120_days():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=300)
    wins = lastmod_windows(start, end)
    assert len(wins) == 3
    assert all(b - a <= timedelta(days=120) for a, b in wins)
    assert wins[0][0] == start and wins[-1][1] == end


def test_concurrent_update_refused(cve_db, fixtures):
    assert cvedb._update_lock.acquire(blocking=False)
    try:
        with pytest.raises(RuntimeError):
            cvedb.import_files([fixtures / "nvd_jquery.json"], cve_db)
    finally:
        cvedb._update_lock.release()


def test_cli_status_and_import(tmp_path, fixtures, capsys):
    from app import cvedb_cli
    db = tmp_path / "cli.sqlite3"
    assert cvedb_cli.main(["--db", str(db), "import", str(fixtures / "nvd_nginx.json"),
                           "--complete-for", "f5:nginx"]) == 0
    assert cvedb_cli.main(["--db", str(db), "status"]) == 0
    out = capsys.readouterr().out
    assert '"state"' in out
    assert cvedb_cli.main(["--db", str(db), "import", str(tmp_path / "missing.json")]) == 1
