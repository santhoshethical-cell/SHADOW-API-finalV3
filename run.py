#!/usr/bin/env python3
"""One-command launcher for the Shadow API Scanner web app (no Docker required).

On first run it creates a local virtual environment (.venv), installs the
dependencies (the web backend, the vendored scanner, and a Chromium build for
Playwright), then starts the server. Later runs skip setup and start straight
away.

Usage:
    python3 run.py            (Linux / macOS)
    python  run.py            (Windows)

Environment overrides: SAS_HOST (default 127.0.0.1), SAS_PORT (default 8000).

Other commands (run inside the project venv):
    python3 run.py cvedb status|update|import ...   manage the local CVE database
    python3 run.py test                              run the automated test suite

Configuration: if a ``.env`` file exists next to this script, its KEY=VALUE
lines are loaded into the environment before starting (variables already set
in the shell take precedence). ``.env`` is git-ignored; see ``.env.example``.
Running uvicorn directly does NOT read ``.env`` — export the variables instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
IS_WIN = os.name == "nt"
BIN = VENV / ("Scripts" if IS_WIN else "bin")
PY = BIN / ("python.exe" if IS_WIN else "python")
MARKER = VENV / ".deps-installed"
HOST = os.environ.get("SAS_HOST", "127.0.0.1")
PORT = os.environ.get("SAS_PORT", "8000")


def _run(*args: str) -> None:
    print("»", " ".join(str(a) for a in args), flush=True)
    subprocess.check_call([str(a) for a in args])


def load_dotenv(path: Path = ROOT / ".env") -> list[str]:
    """Minimal .env loader (KEY=VALUE, # comments, optional quotes).

    Never overrides variables already present in the environment and never
    prints values. Returns the names that were loaded."""
    loaded: list[str] = []
    if not path.exists():
        return loaded
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def ensure_venv() -> None:
    if PY.exists():
        return
    print("Creating virtual environment (.venv) …", flush=True)
    venv.EnvBuilder(with_pip=True).create(VENV)


def ensure_deps() -> None:
    if MARKER.exists():
        return
    print("\nFirst run: installing dependencies (this can take a few minutes) …\n",
          flush=True)
    _run(PY, "-m", "pip", "install", "--upgrade", "pip")
    _run(PY, "-m", "pip", "install", "-r", ROOT / "backend" / "requirements.txt")
    _run(PY, "-m", "pip", "install", "-r", ROOT / "backend" / "requirements-dev.txt")
    _run(PY, "-m", "pip", "install", ROOT / "scanner")
    _run(PY, "-m", "playwright", "install", "chromium")
    MARKER.write_text("ok")
    print("\nSetup complete.\n", flush=True)


def start() -> None:
    (ROOT / "data").mkdir(exist_ok=True)
    names = load_dotenv()
    if names:
        print(f"  Loaded {len(names)} setting(s) from .env: {', '.join(sorted(names))}")
    host = os.environ.get("SAS_HOST", HOST)
    port = os.environ.get("SAS_PORT", PORT)
    print(f"\n  Shadow API Scanner is starting on  http://{host}:{port}")
    print("  The one-time admin password is printed below on first start.")
    print("  Press Ctrl+C to stop.\n", flush=True)
    try:
        subprocess.check_call([
            str(PY), "-m", "uvicorn", "app.main:app",
            "--app-dir", str(ROOT / "backend"),
            "--host", host, "--port", str(port),
        ])
    except KeyboardInterrupt:
        print("\nStopped.")


def run_tool(args: list[str]) -> int:
    """Run a management command inside the venv with backend/ on the path."""
    load_dotenv()
    env = dict(os.environ, PYTHONPATH=str(ROOT / "backend"))
    if args and args[0] == "cvedb":
        cmd = [str(PY), "-m", "app.cvedb_cli", *args[1:]]
    else:  # test
        # Existing installs (set up before tests existed) may lack pytest.
        if subprocess.call([str(PY), "-c", "import pytest"],
                           stderr=subprocess.DEVNULL) != 0:
            _run(PY, "-m", "pip", "install", "-r", ROOT / "backend" / "requirements-dev.txt")
        cmd = [str(PY), "-m", "pytest", str(ROOT / "backend" / "tests"), *args[1:]]
    return subprocess.call(cmd, env=env, cwd=str(ROOT / "backend"))


if __name__ == "__main__":
    try:
        ensure_venv()
        ensure_deps()
        if len(sys.argv) > 1 and sys.argv[1] in ("cvedb", "test"):
            sys.exit(run_tool(sys.argv[1:]))
        start()
    except subprocess.CalledProcessError as exc:
        print(f"\nSetup/startup failed (exit {exc.returncode}). "
              "See the output above for the cause.", file=sys.stderr)
        sys.exit(exc.returncode)
