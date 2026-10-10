"""End-to-end API behaviour through FastAPI's TestClient (no network)."""

import csv
import io
import json
import logging
import shutil
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app import auth, db, enrichment
from app.config import REPORTS_DIR
from tests.conftest import FIXTURES

PW = "CorrectHorse123!"


def make_user(role="user"):
    name = f"u{uuid.uuid4().hex[:8]}"
    db.create_user(name, auth.hash_password(PW), must_change=False, role=role)
    return name


def login(client, name, pw=PW):
    r = client.post("/api/login", json={"username": name, "password": pw})
    assert r.status_code == 200
    return client


@pytest.fixture
def app_client(monkeypatch, cve_db):
    monkeypatch.setenv("SAS_CVEDB_PATH", str(cve_db))
    from app.main import app

    async def fake_fp(target):
        return ([{"product": "jquery", "version": "3.4.1", "header": "runtime",
                  "source": "runtime", "evidence": "window.jQuery.fn.jquery",
                  "observed_at": "2026-10-10T03:06:00+00:00", "distribution_hint": None}], [])
    monkeypatch.setattr("app.cve.fingerprint", fake_fp)

    async def fake_run_scan(config):
        for f in FIXTURES.glob("scan_report_*"):
            shutil.copy(f, f"{config.output_dir}/{f.name}")
        return object()
    monkeypatch.setattr("app.scans.run_scan", fake_run_scan)
    with TestClient(app) as c:
        yield c


def new_client():
    from app.main import app
    return TestClient(app)


def seed_scan(owner: str) -> str:
    """A completed scan on disk owned by ``owner`` (as if from a past run)."""
    sid = uuid.uuid4().hex[:16]
    d = REPORTS_DIR / sid
    d.mkdir(parents=True)
    for f in FIXTURES.glob("scan_report_*"):
        shutil.copy(f, d / f.name)
    db.record_scan(sid, owner, "https://app.example.test/", "standard", "completed")
    return sid


def wait_enrichment(client, sid, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        data = client.get(f"/api/scan/{sid}/enrichment").json()
        if data.get("status") not in ("running", "pending", "not_run"):
            return data
        time.sleep(0.1)
    raise AssertionError(f"enrichment did not finish: {data}")


# -- existing behaviour preserved ----------------------------------------------

def test_login_roles_and_password_change_flow(app_client):
    name = f"m{uuid.uuid4().hex[:8]}"
    db.create_user(name, auth.hash_password(PW), must_change=True, role="user")
    login(app_client, name)
    assert app_client.get("/api/scans").status_code == 403       # must change first
    assert app_client.post("/api/change-password",
                           json={"new_password": "short"}).status_code == 400
    assert app_client.post("/api/change-password",
                           json={"new_password": "AnotherGood123"}).status_code == 200
    assert app_client.get("/api/scans").status_code == 200
    assert app_client.get("/api/users").status_code == 403       # not admin
    assert app_client.post("/api/login", json={"username": name, "password": "bad"}
                           ).status_code == 401


def test_unauthenticated_access_blocked(app_client):
    c = new_client()
    for path in ("/api/cvedb/status", "/api/ai/status", "/api/scans"):
        assert c.get(path).status_code == 401
    assert c.get("/", follow_redirects=False).status_code == 302


def test_admin_user_management_still_works(app_client):
    admin = make_user("admin")
    login(app_client, admin)
    r = app_client.post("/api/users", json={"username": f"n{uuid.uuid4().hex[:6]}",
                                            "role": "user"})
    assert r.status_code == 200 and r.json()["temporary_password"]


def test_level_authorization_gate_preserved(app_client):
    login(app_client, make_user())
    r = app_client.post("/api/scan", json={"target_url": "https://app.example.test",
                                           "level": "standard"})
    assert r.status_code == 403


# -- scan -> enrichment flow ---------------------------------------------------

def test_scan_completes_then_enrichment_runs_separately(app_client):
    user = make_user()
    login(app_client, user)
    r = app_client.post("/api/scan", json={"target_url": "https://app.example.test",
                                           "level": "basic"})
    assert r.status_code == 200
    sid = r.json()["scan_id"]
    # SSE still ends with the scanner's "done" event.
    with app_client.stream("GET", f"/api/scan/{sid}/stream") as s:
        events = [json.loads(line[6:]) for line in s.iter_lines() if line.startswith("data: ")]
    assert events[-1]["type"] == "done" and events[-1]["status"] == "completed"
    data = wait_enrichment(app_client, sid)
    assert data["status"] == "completed"
    assert data["counts"]["cve_version_matches"] >= 1
    hist = {s["id"]: s for s in app_client.get("/api/scans").json()["scans"]}
    assert hist[sid]["status"] == "completed"
    assert hist[sid]["enrichment_status"] == "completed"


def test_ai_failure_keeps_scan_successful(app_client, monkeypatch):
    monkeypatch.setenv("SAS_AI_ENABLED", "true")
    monkeypatch.setenv("SAS_AI_API_KEY", "sk-ant-api-test-zzzzzzzzzzzzzz")

    async def broken(*a, **k):
        from app.ai_analysis import AIError
        raise AIError("timeout", "AI provider did not respond within 45s.")
    monkeypatch.setattr("app.ai_analysis._call_anthropic", broken)
    login(app_client, make_user())
    sid = app_client.post("/api/scan", json={"target_url": "https://app.example.test",
                                             "level": "basic"}).json()["scan_id"]
    data = wait_enrichment(app_client, sid)
    assert data["ai_analysis"]["status"] == "failed"
    hist = {s["id"]: s for s in app_client.get("/api/scans").json()["scans"]}
    assert hist[sid]["status"] == "completed"
    assert app_client.get(f"/api/scan/{sid}/summary").status_code == 200
    assert "sk-ant-api-test" not in json.dumps(data)


# -- ownership / authorization on new endpoints ---------------------------------

def test_other_users_cannot_read_or_recheck_enrichment(app_client):
    owner, other = make_user(), make_user()
    sid = seed_scan(owner)
    c_other = login(new_client(), other)
    for method, path in (("get", f"/api/scan/{sid}/enrichment"),
                         ("post", f"/api/scan/{sid}/enrichment/recheck"),
                         ("get", f"/api/scan/{sid}/export.json"),
                         ("get", f"/api/scan/{sid}/export.csv"),
                         ("post", f"/api/scan/{sid}/cve-check")):
        assert getattr(c_other, method)(path).status_code == 404, path


def test_only_admin_can_update_cve_database(app_client, monkeypatch):
    monkeypatch.setattr("app.cvedb.update_from_nvd",
                        lambda *a, **k: {"status": "success", "products": []})
    login(app_client, make_user())
    assert app_client.post("/api/admin/cvedb/update", json={}).status_code == 403
    assert app_client.get("/api/admin/cvedb/update").status_code == 403
    admin = login(new_client(), make_user("admin"))
    assert admin.post("/api/admin/cvedb/update", json={"mode": "bogus"}).status_code == 400
    r = admin.post("/api/admin/cvedb/update", json={"mode": "incremental"})
    assert r.status_code == 202
    for _ in range(50):
        job = admin.get("/api/admin/cvedb/update").json()
        if not job["running"]:
            break
        time.sleep(0.05)
    assert job["result"]["status"] == "success" and job["error"] is None


def test_cvedb_and_ai_status_never_expose_keys(app_client, monkeypatch, caplog):
    monkeypatch.setenv("SAS_NVD_API_KEY", "nvd-secret-value-123456")
    monkeypatch.setenv("SAS_AI_ENABLED", "1")
    monkeypatch.setenv("SAS_AI_API_KEY", "sk-ant-secret-value-123456789")
    caplog.set_level(logging.INFO)
    login(app_client, make_user())
    st = app_client.get("/api/cvedb/status").json()
    ai = app_client.get("/api/ai/status").json()
    blob = json.dumps(st) + json.dumps(ai)
    assert "nvd-secret-value" not in blob and "sk-ant-secret" not in blob
    assert ai["key_configured"] is True and ai["ready"] is True
    # Logs: install the production filter on a capturing handler and log a key.
    from app.secrets_guard import SecretLogFilter, install_log_filter
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        install_log_filter()
        assert any(isinstance(f, SecretLogFilter) for f in handler.filters)
        logging.getLogger("sas.webapp").warning("leak test %s / %s",
                                                "sk-ant-secret-value-123456789",
                                                "nvd-secret-value-123456")
    finally:
        root.removeHandler(handler)
    text = stream.getvalue()
    assert "leak test" in text
    assert "sk-ant-secret-value" not in text and "nvd-secret-value" not in text


# -- persistence, reopen, exports ------------------------------------------------

def test_enrichment_survives_restart_and_reopen_does_not_rescan(app_client, monkeypatch):
    owner = make_user()
    sid = seed_scan(owner)
    asyncio_run_enrichment(sid)
    calls = []

    async def counting_fp(target):
        calls.append(target)
        return [], []
    monkeypatch.setattr("app.cve.fingerprint", counting_fp)
    # "Restart": a fresh client/app lifespan; in-memory state is irrelevant.
    with new_client() as c:
        login(c, owner)
        data = c.get(f"/api/scan/{sid}/enrichment").json()
        assert data["status"] == "completed" and data["counts"]["cve_version_matches"] >= 1
        assert c.get(f"/api/scan/{sid}/summary").status_code == 200
        assert c.get(f"/api/scan/{sid}/export.csv").status_code == 200
        assert c.get(f"/api/scan/{sid}/export.json").status_code == 200
    assert calls == []                       # reopening/exporting never fingerprints


def asyncio_run_enrichment(sid):
    import asyncio
    return asyncio.run(enrichment.run(sid, REPORTS_DIR / sid))


def test_recheck_endpoint_records_new_observation(app_client):
    owner = make_user()
    sid = seed_scan(owner)
    first = asyncio_run_enrichment(sid)
    login(app_client, owner)
    r = app_client.post(f"/api/scan/{sid}/enrichment/recheck", json={"refingerprint": False})
    assert r.status_code == 202
    time.sleep(0.05)
    data = wait_enrichment(app_client, sid)
    assert data["trigger"] == "rematch" and data["history"]
    assert data["started_at"] >= first["completed_at"]


def test_old_scan_without_enrichment_still_readable(app_client):
    owner = make_user()
    sid = seed_scan(owner)
    login(app_client, owner)
    assert app_client.get(f"/api/scan/{sid}/enrichment").json()["status"] == "not_run"
    assert app_client.get(f"/api/scan/{sid}/summary").status_code == 200
    assert app_client.get(f"/api/scan/{sid}/technical").status_code == 200
    rows = list(csv.reader(io.StringIO(app_client.get(f"/api/scan/{sid}/export.csv").text)))
    assert len(rows) == 6
    assert app_client.get(f"/api/scan/{sid}/export.json").json()["enrichment"] is None


def test_exports_consistent_with_enrichment(app_client):
    owner = make_user()
    sid = seed_scan(owner)
    data = asyncio_run_enrichment(sid)
    login(app_client, owner)
    j = app_client.get(f"/api/scan/{sid}/export.json").json()
    assert j["enrichment"]["counts"] == data["counts"]
    text = app_client.get(f"/api/scan/{sid}/export.csv").text
    rows = list(csv.DictReader(io.StringIO(text)))
    cve_rows = [r for r in rows if r["record_type"] == "component_cve_match"]
    n = sum(len(c["matches"]) for c in data["cve_matching"]["components"])
    assert len(cve_rows) == n
    assert sum(1 for r in rows if r["record_type"] == "behavioral_finding") == 5


def test_pdf_uses_enriched_html(app_client, monkeypatch):
    owner = make_user()
    sid = seed_scan(owner)
    asyncio_run_enrichment(sid)
    seen = {}

    async def fake_pdf(path):
        seen["path"] = path
        seen["html"] = path.read_text()
        return b"%PDF-1.4 fake"
    monkeypatch.setattr("app.reports.export_pdf", fake_pdf)
    login(app_client, owner)
    r = app_client.get(f"/api/scan/{sid}/export.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert seen["path"].name == enrichment.ENRICHED_HTML
    assert "sas-enrichment" in seen["html"] and "CVE-2020-11022" in seen["html"]


def test_pdf_falls_back_to_scanner_html_without_enrichment(app_client, monkeypatch):
    owner = make_user()
    sid = seed_scan(owner)
    seen = {}

    async def fake_pdf(path):
        seen["path"] = path
        return b"%PDF"
    monkeypatch.setattr("app.reports.export_pdf", fake_pdf)
    login(app_client, owner)
    assert app_client.get(f"/api/scan/{sid}/export.pdf").status_code == 200
    assert seen["path"].name.startswith("scan_report_")
