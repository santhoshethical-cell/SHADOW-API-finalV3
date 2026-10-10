"""Runtime configuration and shared paths for the web backend."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

# Persist data next to the project by default (works when run directly with
# python; override with SAS_DATA_DIR).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = Path(os.environ.get("SAS_DATA_DIR", str(_PROJECT_ROOT / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "webapp.db"
REPORTS_DIR = DATA_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

# Session signing secret: stable across restarts (persisted), random on first run.
_SECRET_FILE = DATA_DIR / "session_secret"


def _load_or_create_secret() -> str:
    env = os.environ.get("SAS_SECRET_KEY")
    if env:
        return env
    if _SECRET_FILE.exists():
        return _SECRET_FILE.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    _SECRET_FILE.write_text(value, encoding="utf-8")
    return value


SECRET_KEY = _load_or_create_secret()

# Bounded scan settings exposed per level (Basic / Standard / Advanced).
MAX_CONCURRENT_SCANS = int(os.environ.get("SAS_MAX_CONCURRENT_SCANS", "2"))
