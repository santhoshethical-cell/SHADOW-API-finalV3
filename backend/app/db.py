"""SQLite persistence for users and scan history (no ORM, stdlib only)."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Optional

from app.config import DB_PATH


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


_conn = _connect()


def init_db() -> None:
    _conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            target_url TEXT NOT NULL,
            level TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at REAL NOT NULL,
            finished_at REAL,
            summary_json TEXT
        );
        """
    )
    # Migration for databases created before roles existed.
    cols = {r["name"] for r in _conn.execute("PRAGMA table_info(users)")}
    if "role" not in cols:
        _conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL "
                      "DEFAULT 'user'")
        _conn.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    # Migration (additive): enrichment status per scan. Older rows get NULL,
    # which the UI shows as "not run" — existing reports stay readable.
    scan_cols = {r["name"] for r in _conn.execute("PRAGMA table_info(scans)")}
    if "enrichment_status" not in scan_cols:
        _conn.execute("ALTER TABLE scans ADD COLUMN enrichment_status TEXT")
    _conn.commit()


# -- users ----------------------------------------------------------------

def get_user(username: str) -> Optional[sqlite3.Row]:
    cur = _conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def create_user(username: str, password_hash: str, must_change: bool,
                role: str = "user") -> None:
    _conn.execute(
        "INSERT INTO users (username, password_hash, must_change_password, "
        "role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, 1 if must_change else 0, role, time.time()),
    )
    _conn.commit()


def list_users() -> list[dict[str, Any]]:
    rows = _conn.execute(
        "SELECT username, role, must_change_password, created_at "
        "FROM users ORDER BY role DESC, username"
    ).fetchall()
    return [dict(r) for r in rows]


def delete_user(username: str) -> None:
    _conn.execute("DELETE FROM users WHERE username = ?", (username,))
    _conn.commit()


def count_admins() -> int:
    return _conn.execute(
        "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]


def set_password(username: str, password_hash: str) -> None:
    _conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 "
        "WHERE username = ?",
        (password_hash, username),
    )
    _conn.commit()


def user_count() -> int:
    return _conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]


# -- scans ----------------------------------------------------------------

def record_scan(scan_id: str, username: str, target_url: str,
                level: str, status: str) -> None:
    _conn.execute(
        "INSERT OR REPLACE INTO scans (id, username, target_url, level, "
        "status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, username, target_url, level, status, time.time()),
    )
    _conn.commit()


def finish_scan(scan_id: str, status: str, summary: dict[str, Any]) -> None:
    _conn.execute(
        "UPDATE scans SET status = ?, finished_at = ?, summary_json = ? "
        "WHERE id = ?",
        (status, time.time(), json.dumps(summary), scan_id),
    )
    _conn.commit()


def list_scans(username: str, limit: int = 50) -> list[dict[str, Any]]:
    rows = _conn.execute(
        "SELECT id, target_url, level, status, created_at, finished_at, "
        "enrichment_status "
        "FROM scans WHERE username = ? ORDER BY created_at DESC LIMIT ?",
        (username, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def set_enrichment_status(scan_id: str, status: str) -> None:
    _conn.execute("UPDATE scans SET enrichment_status = ? WHERE id = ?",
                  (status, scan_id))
    _conn.commit()


def all_scan_ids() -> list[str]:
    return [r["id"] for r in _conn.execute("SELECT id FROM scans")]
