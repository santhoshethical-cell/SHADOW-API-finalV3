"""Shared test setup: isolated data dir, no real secrets, no network."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Must happen before any `app` import: config resolves DATA_DIR at import time.
_DATA = tempfile.mkdtemp(prefix="sas-test-")
os.environ["SAS_DATA_DIR"] = _DATA
os.environ["SAS_SECRET_KEY"] = "test-session-secret-not-real"
for _v in ("SAS_AI_ENABLED", "SAS_AI_PROVIDER", "SAS_AI_API_KEY", "SAS_AI_MODEL",
           "SAS_AI_TIMEOUT_SECONDS", "SAS_NVD_API_KEY", "SAS_CVEDB_PATH",
           "SAS_CVEDB_STALE_DAYS"):
    os.environ.pop(_v, None)

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
FIXTURES = Path(__file__).resolve().parent / "fixtures"

import pytest  # noqa: E402


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def cve_db(tmp_path) -> Path:
    """A CVE database populated from fixtures with complete coverage for the
    products the fixtures contain."""
    from app import cvedb
    path = tmp_path / "cvedb.sqlite3"
    cvedb.import_files(
        [FIXTURES / "nvd_jquery.json", FIXTURES / "nvd_nginx.json", FIXTURES / "nvd_misc.json"],
        path,
        complete_for=[("jquery", "jquery"), ("f5", "nginx"), ("nginx", "nginx"),
                      ("openjsf", "express"), ("expressjs", "express"),
                      ("openssl", "openssl"), ("angularjs", "angularjs"),
                      ("angularjs", "angular.js")])
    return path


@pytest.fixture
def scan_dir(tmp_path) -> Path:
    d = tmp_path / "scan"
    d.mkdir()
    for f in FIXTURES.glob("scan_report_*"):
        shutil.copy(f, d / f.name)
    return d


@pytest.fixture
def report(fixtures) -> dict:
    import json
    return json.loads((fixtures / "scan_report_20261010_030500.json").read_text())


@pytest.fixture(autouse=True)
def _clean_ai_env(monkeypatch):
    for v in ("SAS_AI_ENABLED", "SAS_AI_API_KEY", "SAS_AI_PROVIDER", "SAS_AI_MODEL",
              "SAS_NVD_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    yield


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_DATA, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    from app import db
    db.init_db()
    yield
