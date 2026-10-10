"""Persistent local CVE database (SQLite) with atomic, resumable-safe updates.

Layout: a dedicated SQLite file (default ``data/cvedb.sqlite3``), separate from
the users/scans database so that it can be replaced atomically.

Update model
------------
Every update (NVD download or file import) works on a *staged copy* of the
current database. Only after the whole run succeeds and ``PRAGMA
integrity_check`` passes is the staged file moved over the live one with
``os.replace`` (atomic on the same filesystem). Any exception — network,
pagination gap, rate limit exhaustion, malformed data — deletes the staged
copy and leaves the previous database untouched. The outcome of every run is
recorded separately in ``<db>.lastrun.json`` so failures are visible.

Coverage
--------
The database records, per CPE ``vendor:product``, whether its data is
*complete* (downloaded from NVD for that product), *imported* (from files of
unknown completeness) or absent. Matching reports components whose product has
no complete, fresh coverage as "unknown" — never as "no vulnerabilities".
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

from app.component_catalog import CATALOG, all_cpe_pairs

logger = logging.getLogger("sas.cvedb")

SCHEMA_VERSION = "1"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    published TEXT, last_modified TEXT,
    vuln_status TEXT,                  -- NVD record status (Analyzed, Modified, Rejected…)
    source_identifier TEXT,
    cvss_score REAL, cvss_version TEXT, cvss_vector TEXT,
    severity TEXT, cvss_source TEXT,
    cwe_ids TEXT NOT NULL DEFAULT '[]',
    record_source TEXT NOT NULL,       -- nvd-api | import:<file>
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS affected (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vendor TEXT NOT NULL, product TEXT NOT NULL,
    component_key TEXT,                -- catalog identity, NULL if not catalogued
    criteria TEXT NOT NULL,
    cpe_version TEXT, cpe_update TEXT, target_sw TEXT,
    start_incl TEXT, start_excl TEXT, end_incl TEXT, end_excl TEXT,
    fixed_version TEXT,                -- only when a source states it explicitly
    vulnerable INTEGER NOT NULL,
    requires_config INTEGER NOT NULL DEFAULT 0,
    config_note TEXT
);
CREATE INDEX IF NOT EXISTS ix_affected_component ON affected(component_key);
CREATE INDEX IF NOT EXISTS ix_affected_cve ON affected(cve_id);
CREATE TABLE IF NOT EXISTS refs (
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL, source TEXT, tags TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_refs_cve ON refs(cve_id);
CREATE TABLE IF NOT EXISTS coverage (
    vendor TEXT NOT NULL, product TEXT NOT NULL,
    status TEXT NOT NULL,              -- complete | imported
    last_success_at TEXT, total_results INTEGER, mode TEXT, note TEXT,
    PRIMARY KEY (vendor, product)
);
"""

_update_lock = threading.Lock()


def default_path() -> Path:
    from app.config import DATA_DIR
    return Path(os.environ.get("SAS_CVEDB_PATH", str(DATA_DIR / "cvedb.sqlite3")))


def stale_after() -> timedelta:
    try:
        days = float(os.environ.get("SAS_CVEDB_STALE_DAYS", "7"))
    except ValueError:
        days = 7.0
    return timedelta(days=max(0.0, days))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse_iso(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


_PAIR_TO_KEY = {pair: entry.key for entry in CATALOG.values() for pair in entry.cpes}


# --------------------------------------------------------------------------- #
# NVD record parsing
# --------------------------------------------------------------------------- #

def split_cpe(criteria: str) -> list[str]:
    """Split a CPE 2.3 formatted string honouring backslash escapes."""
    parts, cur, esc = [], [], False
    for ch in criteria:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


_SAFE_URL = re.compile(r"^https?://[^\s<>\"'`]+$", re.IGNORECASE)


def safe_reference_url(url: Any) -> Optional[str]:
    """Return ``url`` only if it is a plain http(s) URL without credentials."""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if len(url) > 2048 or not _SAFE_URL.match(url):
        return None
    from urllib.parse import urlparse
    p = urlparse(url)
    if not p.hostname or p.username or p.password:
        return None
    return url


def _pick_metric(metrics: dict) -> dict:
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {}) or {}
        sev = data.get("baseSeverity") or primary.get("baseSeverity") or ""
        return {"cvss_score": data.get("baseScore"), "cvss_version": data.get("version") or ver,
                "cvss_vector": data.get("vectorString"), "severity": str(sev).title() or None,
                "cvss_source": primary.get("source")}
    return {"cvss_score": None, "cvss_version": None, "cvss_vector": None,
            "severity": None, "cvss_source": None}


def parse_nvd_item(item: dict, record_source: str, fetched_at: str
                   ) -> tuple[dict, list[dict], list[dict]]:
    """Convert one NVD ``vulnerabilities[]`` item into table rows."""
    cve = item.get("cve") if "cve" in item else item
    if not isinstance(cve, dict) or not cve.get("id"):
        raise ValueError("NVD item without cve.id")
    cve_id = str(cve["id"]).strip()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError(f"invalid CVE id {cve_id!r}")
    desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    cwes = sorted({d.get("value") for w in cve.get("weaknesses", []) or []
                   for d in w.get("description", []) or []
                   if str(d.get("value", "")).startswith("CWE-")})
    row = {"cve_id": cve_id, "description": desc[:4000],
           "published": cve.get("published"), "last_modified": cve.get("lastModified"),
           "vuln_status": cve.get("vulnStatus"),
           "source_identifier": cve.get("sourceIdentifier"),
           "cwe_ids": json.dumps(cwes), "record_source": record_source,
           "fetched_at": fetched_at, **_pick_metric(cve.get("metrics", {}) or {})}

    affected: list[dict] = []
    for config in cve.get("configurations", []) or []:
        nodes = config.get("nodes", []) or []
        multi = str(config.get("operator", "")).upper() == "AND" and len(nodes) > 1
        others_note = None
        if multi:
            platform = [m.get("criteria", "") for n in nodes for m in n.get("cpeMatch", [])
                        if not m.get("vulnerable")]
            shown = ", ".join(":".join(split_cpe(c)[3:5]) for c in platform[:3])
            others_note = ("Only affected in combination with "
                           f"{shown or 'another configuration element'}"
                           f"{'…' if len(platform) > 3 else ''}.")
        for node in nodes:
            negate = bool(node.get("negate"))
            node_and = str(node.get("operator", "OR")).upper() == "AND"
            for m in node.get("cpeMatch", []) or []:
                parts = split_cpe(m.get("criteria", ""))
                if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
                    continue
                vendor, product = parts[3].lower(), parts[4].lower()
                requires = multi or negate or node_and
                note = others_note
                if negate:
                    note = "NVD marks this configuration node as negated."
                elif node_and and not note:
                    note = "Node requires all listed elements together."
                affected.append({
                    "cve_id": cve_id, "vendor": vendor, "product": product,
                    "component_key": _PAIR_TO_KEY.get((vendor, product)),
                    "criteria": m.get("criteria", ""),
                    "cpe_version": parts[5], "cpe_update": parts[6],
                    "target_sw": parts[10],
                    "start_incl": m.get("versionStartIncluding"),
                    "start_excl": m.get("versionStartExcluding"),
                    "end_incl": m.get("versionEndIncluding"),
                    "end_excl": m.get("versionEndExcluding"),
                    # NVD does not publish "fixed" versions; only explicit
                    # sources (e.g. curated imports) populate this field.
                    "fixed_version": m.get("fixedVersion"),
                    "vulnerable": 1 if m.get("vulnerable") else 0,
                    "requires_config": 1 if requires else 0,
                    "config_note": note,
                })
    refs = []
    for r in cve.get("references", []) or []:
        url = safe_reference_url(r.get("url"))
        if url:
            refs.append({"cve_id": cve_id, "url": url, "source": r.get("source"),
                         "tags": json.dumps(r.get("tags") or [])})
    return row, affected, refs


# --------------------------------------------------------------------------- #
# Connections and atomic staging
# --------------------------------------------------------------------------- #

def _open(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                 (SCHEMA_VERSION,))
    conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('created_at', ?)",
                 (_iso(utcnow()),))
    conn.commit()


@contextmanager
def staged_update(path: Path) -> Iterator[sqlite3.Connection]:
    """Yield a connection to a staged copy; atomically swap in on success."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.staging-{os.getpid()}-{threading.get_ident()}")
    if staged.exists():
        staged.unlink()
    if path.exists():
        src = _open(path)
        dst = sqlite3.connect(str(staged))
        try:
            src.backup(dst)           # consistent copy even if readers are active
        finally:
            dst.close()
            src.close()
    conn = _open(staged)
    try:
        _init(conn)
        yield conn
        conn.commit()
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise RuntimeError(f"staged CVE database failed integrity check: {ok}")
        conn.close()
        os.replace(staged, path)
    except BaseException:
        try:
            conn.close()
        finally:
            for leftover in (staged, Path(f"{staged}-journal"), Path(f"{staged}-wal")):
                if leftover.exists():
                    leftover.unlink()
        raise


def upsert_item(conn: sqlite3.Connection, item: dict, record_source: str,
                fetched_at: str) -> str:
    row, affected, refs = parse_nvd_item(item, record_source, fetched_at)
    conn.execute("DELETE FROM affected WHERE cve_id = ?", (row["cve_id"],))
    conn.execute("DELETE FROM refs WHERE cve_id = ?", (row["cve_id"],))
    cols = ", ".join(row)
    conn.execute(f"INSERT OR REPLACE INTO cves ({cols}) VALUES "
                 f"({', '.join('?' * len(row))})", tuple(row.values()))
    for a in affected:
        conn.execute(f"INSERT INTO affected ({', '.join(a)}) VALUES "
                     f"({', '.join('?' * len(a))})", tuple(a.values()))
    for r in refs:
        conn.execute("INSERT INTO refs (cve_id, url, source, tags) VALUES (?,?,?,?)",
                     (r["cve_id"], r["url"], r["source"], r["tags"]))
    return row["cve_id"]


def _set_meta(conn: sqlite3.Connection, **values: Any) -> None:
    for k, v in values.items():
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                     (k, None if v is None else str(v)))


def _lastrun_path(path: Path) -> Path:
    return Path(path).with_name(Path(path).name + ".lastrun.json")


def _write_lastrun(path: Path, record: dict) -> None:
    lp = _lastrun_path(path)
    tmp = lp.with_name(lp.name + ".tmp")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(tmp, lp)


# --------------------------------------------------------------------------- #
# Updates: NVD download and file import
# --------------------------------------------------------------------------- #

def update_from_nvd(
    path: Optional[Path] = None,
    *,
    mode: str = "incremental",
    pairs: Optional[Iterable[tuple[str, str]]] = None,
    client=None,
    now: Callable[[], datetime] = utcnow,
    progress: Optional[Callable[[str], None]] = None,
) -> dict:
    """Download CVEs for catalog products from NVD into the local database.

    ``full``: re-download everything for each product.
    ``incremental``: for products with complete coverage, fetch only records
    modified since the last successful update (with a 1-hour overlap);
    products without complete coverage get a full download.
    """
    from app.nvd_client import NvdClient, lastmod_windows, nvd_datetime

    path = Path(path or default_path())
    if mode not in ("full", "incremental"):
        raise ValueError("mode must be 'full' or 'incremental'")
    pairs = list(pairs or all_cpe_pairs())
    say = progress or (lambda msg: logger.info("%s", msg))
    started = now()
    if not _update_lock.acquire(blocking=False):
        raise RuntimeError("Another CVE database update is already running.")
    own_client = client is None
    if own_client:
        client = NvdClient(api_key=os.environ.get("SAS_NVD_API_KEY") or None)
    summary: dict[str, Any] = {"mode": mode, "started_at": _iso(started),
                               "products": [], "source": "nvd-api"}
    try:
        with staged_update(path) as conn:
            for vendor, product in pairs:
                cov = conn.execute("SELECT * FROM coverage WHERE vendor=? AND product=?",
                                   (vendor, product)).fetchone()
                last = _parse_iso(cov["last_success_at"]) if cov else None
                base = {"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}"}
                incremental = (mode == "incremental" and cov is not None
                               and cov["status"] == "complete" and last is not None)
                windows = ([dict(base, lastModStartDate=nvd_datetime(a),
                                 lastModEndDate=nvd_datetime(b))
                            for a, b in lastmod_windows(last - timedelta(hours=1), started)]
                           if incremental else [base])
                count = 0
                fetched_at = _iso(started)
                for params in windows:
                    for item in client.iter_items(
                            params, on_page=lambda seen, total: say(
                                f"{vendor}:{product}: {seen}/{total} records")):
                        upsert_item(conn, item, "nvd-api", fetched_at)
                        count += 1
                total_known = conn.execute(
                    "SELECT COUNT(DISTINCT cve_id) FROM affected WHERE vendor=? AND product=?",
                    (vendor, product)).fetchone()[0]
                conn.execute(
                    "INSERT OR REPLACE INTO coverage(vendor, product, status, "
                    "last_success_at, total_results, mode, note) VALUES (?,?,?,?,?,?,?)",
                    (vendor, product, "complete", _iso(started), total_known,
                     "incremental" if incremental else "full", None))
                summary["products"].append({"cpe": f"{vendor}:{product}",
                                            "mode": "incremental" if incremental else "full",
                                            "records_received": count})
                say(f"{vendor}:{product}: {count} record(s) received")
            _set_meta(conn, last_update_at=_iso(started), last_update_mode=mode,
                      last_update_source="nvd-api")
        summary.update(status="success", finished_at=_iso(now()),
                       requests=getattr(client, "requests_made", None))
        _write_lastrun(path, summary)
        return summary
    except Exception as exc:
        summary.update(status="failed", finished_at=_iso(now()),
                       error=_safe_error(exc),
                       note="The previous database was kept unchanged.")
        _write_lastrun(path, summary)
        raise
    finally:
        _update_lock.release()
        if own_client:
            client.close()


def import_files(
    files: Iterable[Path],
    path: Optional[Path] = None,
    *,
    complete_for: Iterable[tuple[str, str]] = (),
    now: Callable[[], datetime] = utcnow,
) -> dict:
    """Import NVD CVE API 2.0 JSON (API pages or ``{"vulnerabilities": []}``).

    Imported data has unknown completeness, so catalog products found in it are
    marked ``imported`` (partial) unless listed in ``complete_for``.
    """
    path = Path(path or default_path())
    started = now()
    complete = {(v.lower(), p.lower()) for v, p in complete_for}
    if not _update_lock.acquire(blocking=False):
        raise RuntimeError("Another CVE database update is already running.")
    summary: dict[str, Any] = {"mode": "import", "started_at": _iso(started),
                               "files": [], "source": "import"}
    try:
        with staged_update(path) as conn:
            seen_pairs: set[tuple[str, str]] = set()
            for f in files:
                f = Path(f)
                data = json.loads(f.read_text(encoding="utf-8"))
                items = data.get("vulnerabilities") if isinstance(data, dict) else data
                if not isinstance(items, list):
                    raise ValueError(f"{f.name}: no 'vulnerabilities' list found")
                n = 0
                for item in items:
                    cid = upsert_item(conn, item, f"import:{f.name}", _iso(started))
                    for r in conn.execute("SELECT DISTINCT vendor, product FROM affected "
                                          "WHERE cve_id=?", (cid,)):
                        seen_pairs.add((r["vendor"], r["product"]))
                    n += 1
                summary["files"].append({"file": f.name, "records": n})
            for vendor, product in (seen_pairs | complete):
                if (vendor, product) not in _PAIR_TO_KEY and (vendor, product) not in complete:
                    continue
                existing = conn.execute("SELECT status FROM coverage WHERE vendor=? AND "
                                        "product=?", (vendor, product)).fetchone()
                status = "complete" if (vendor, product) in complete else (
                    existing["status"] if existing and existing["status"] == "complete"
                    else "imported")
                total = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM affected "
                                     "WHERE vendor=? AND product=?",
                                     (vendor, product)).fetchone()[0]
                conn.execute(
                    "INSERT OR REPLACE INTO coverage(vendor, product, status, "
                    "last_success_at, total_results, mode, note) VALUES (?,?,?,?,?,?,?)",
                    (vendor, product, status, _iso(started), total, "import",
                     None if status == "complete" else
                     "Imported from file; completeness for this product is unknown."))
            _set_meta(conn, last_update_at=_iso(started), last_update_mode="import",
                      last_update_source="import")
        summary.update(status="success", finished_at=_iso(now()))
        _write_lastrun(path, summary)
        return summary
    except Exception as exc:
        summary.update(status="failed", finished_at=_iso(now()), error=_safe_error(exc),
                       note="The previous database was kept unchanged.")
        _write_lastrun(path, summary)
        raise
    finally:
        _update_lock.release()


def _safe_error(exc: BaseException) -> str:
    from app.secrets_guard import scrub
    return scrub(f"{type(exc).__name__}: {exc}")[:500]


# --------------------------------------------------------------------------- #
# Read side: status, coverage, candidate ranges
# --------------------------------------------------------------------------- #

def read_lastrun(path: Optional[Path] = None) -> Optional[dict]:
    lp = _lastrun_path(Path(path or default_path()))
    if not lp.exists():
        return None
    try:
        return json.loads(lp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def status(path: Optional[Path] = None, now: Callable[[], datetime] = utcnow) -> dict:
    """Human/API-facing description of database state and coverage."""
    path = Path(path or default_path())
    last_run = read_lastrun(path)
    base = {"state": "missing", "cve_count": 0, "last_update_at": None,
            "stale_after_days": stale_after().days, "components": [],
            "last_run": last_run, "message": ""}
    if not path.exists():
        base["message"] = ("No local CVE database yet. An administrator must "
                           "populate it before component CVE matching can run.")
        return base
    conn = _open(path)
    try:
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
        cve_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        cov = {(r["vendor"], r["product"]): dict(r) for r in conn.execute("SELECT * FROM coverage")}
    except sqlite3.DatabaseError as exc:
        base.update(state="failed", message=f"CVE database unreadable: {exc}")
        return base
    finally:
        conn.close()
    comps = [component_coverage(e.key, cov, now) for e in CATALOG.values()]
    states = {c["coverage"] for c in comps}
    if cve_count == 0 and not cov:
        state, msg = "missing", "The CVE database is empty."
    elif states == {"complete"}:
        state, msg = "ok", "All catalog components have complete coverage."
    elif "complete" in states or "partial" in states or "stale" in states:
        state = "stale" if "stale" in states and not ({"missing", "partial"} & states) else "partial"
        msg = ("Some components have stale data." if state == "stale" else
               "Some components have missing or partial coverage.")
    else:
        state, msg = "partial", "Coverage is incomplete."
    if last_run and last_run.get("status") == "failed":
        msg += " The most recent update failed; the previous data is still in use."
    base.update(state=state, cve_count=cve_count, message=msg,
                last_update_at=meta.get("last_update_at"),
                last_update_mode=meta.get("last_update_mode"),
                schema_version=meta.get("schema_version"), components=comps)
    return base


def component_coverage(key: str, cov: dict, now: Callable[[], datetime] = utcnow) -> dict:
    entry = CATALOG[key]
    rows = [cov.get(pair) for pair in entry.cpes]
    if all(r is None for r in rows):
        coverage = "missing"
    elif all(r is not None and r["status"] == "complete" for r in rows):
        coverage = "complete"
    else:
        coverage = "partial"
    times = [_parse_iso(r["last_success_at"]) for r in rows if r]
    oldest = min((t for t in times if t), default=None)
    if coverage == "complete" and oldest and now() - oldest > stale_after():
        coverage = "stale"
    return {"component": key, "display": entry.display,
            "cpes": [f"{v}:{p}" for v, p in entry.cpes], "coverage": coverage,
            "last_success_at": _iso(oldest) if oldest else None}


def coverage_for(key: str, path: Optional[Path] = None,
                 now: Callable[[], datetime] = utcnow) -> dict:
    path = Path(path or default_path())
    if not path.exists():
        return component_coverage(key, {}, now)
    conn = _open(path)
    try:
        cov = {(r["vendor"], r["product"]): dict(r) for r in conn.execute("SELECT * FROM coverage")}
    finally:
        conn.close()
    return component_coverage(key, cov, now)


def candidate_ranges(key: str, path: Optional[Path] = None) -> list[dict]:
    """All vulnerable affected-range rows for a catalog component, with CVE data."""
    path = Path(path or default_path())
    if not path.exists():
        return []
    conn = _open(path)
    try:
        rows = conn.execute(
            "SELECT a.*, c.description, c.published, c.last_modified, c.vuln_status, "
            "c.cvss_score, c.cvss_version, c.cvss_vector, c.severity, c.cvss_source, "
            "c.cwe_ids, c.record_source, c.fetched_at "
            "FROM affected a JOIN cves c ON c.cve_id = a.cve_id "
            "WHERE a.component_key = ? AND a.vulnerable = 1 ORDER BY a.cve_id",
            (key,)).fetchall()
        out = [dict(r) for r in rows]
        refs: dict[str, list[dict]] = {}
        ids = sorted({r["cve_id"] for r in out})
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            for r in conn.execute(f"SELECT * FROM refs WHERE cve_id IN "
                                  f"({','.join('?' * len(chunk))})", chunk):
                refs.setdefault(r["cve_id"], []).append(
                    {"url": r["url"], "source": r["source"], "tags": json.loads(r["tags"])})
        for r in out:
            r["references"] = refs.get(r["cve_id"], [])
            r["cwe_ids"] = json.loads(r["cwe_ids"] or "[]")
        return out
    finally:
        conn.close()
