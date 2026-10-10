"""Scan job manager: runs the async scanner and streams progress events.

Real-time progress reuses the scanner's existing logging structure: a logging
handler attached to the ``shadow_api_scanner`` logger forwards each phase/finding
log line onto a per-scan thread-safe queue, which the SSE endpoint drains. No
scanner code is modified.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from shadow_api_scanner.cli import run_scan

from app import db
from app.config import REPORTS_DIR

_SCANNER_LOGGER = "shadow_api_scanner"


@dataclass
class ScanJob:
    id: str
    username: str
    target_url: str
    level: str
    status: str = "queued"          # queued|running|completed|failed
    events: "queue.Queue" = field(default_factory=queue.Queue)
    output_dir: Optional[Path] = None
    error: Optional[str] = None
    summary: dict[str, Any] = field(default_factory=dict)


class _QueueLogHandler(logging.Handler):
    """Forward scanner log records to a scan's event queue as progress lines."""

    def __init__(self, job: ScanJob):
        super().__init__(level=logging.INFO)
        self._job = job

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage().strip()
        except Exception:
            return
        if not msg or set(msg) <= {"=", "-"}:
            return
        phase = None
        upper = msg.upper()
        if "PHASE 1" in upper:
            phase = 1
        elif "PHASE 2" in upper:
            phase = 2
        elif "PHASE 3" in upper:
            phase = 3
        elif "PHASE 4" in upper:
            phase = 4
        self._job.events.put({
            "type": "progress",
            "phase": phase,
            "level": record.levelname.lower(),
            "message": msg,
            "ts": time.time(),
        })


class ScanManager:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        # Called with the completed job after the scan's "done" event has been
        # emitted. Used to start post-scan enrichment; failures there never
        # change the scan's status.
        self.on_completed: Optional[Callable[[ScanJob], None]] = None

    def get(self, scan_id: str) -> Optional[ScanJob]:
        return self._jobs.get(scan_id)

    def create(self, username: str, target_url: str, level: str) -> ScanJob:
        scan_id = uuid.uuid4().hex[:16]
        job = ScanJob(id=scan_id, username=username,
                      target_url=target_url, level=level)
        job.output_dir = REPORTS_DIR / scan_id
        job.output_dir.mkdir(parents=True, exist_ok=True)
        self._jobs[scan_id] = job
        db.record_scan(scan_id, username, target_url, level, "queued")
        return job

    async def run(self, job: ScanJob, config, secret_env: dict | None = None) -> None:
        job.status = "running"
        db.record_scan(job.id, job.username, job.target_url, job.level,
                       "running")
        job.events.put({"type": "status", "status": "running",
                        "message": f"Scan started ({job.level})", "ts": time.time()})
        handler = _QueueLogHandler(job)
        scanner_logger = logging.getLogger(_SCANNER_LOGGER)
        scanner_logger.addHandler(handler)
        prev_level = scanner_logger.level
        if prev_level > logging.INFO or prev_level == logging.NOTSET:
            scanner_logger.setLevel(logging.INFO)
        # Credentials from the advanced options live in the process environment
        # only for the duration of this scan (never written to disk); the config
        # files reference these unique names. Always cleared in the finally block.
        secret_env = secret_env or {}
        for name, value in secret_env.items():
            os.environ[name] = value
        try:
            result = await run_scan(config)
            summary = self._summarize(job, result)
            job.summary = summary
            job.status = "completed"
            db.finish_scan(job.id, "completed", summary)
            job.events.put({"type": "done", "status": "completed",
                            "summary": summary, "ts": time.time()})
            if self.on_completed is not None:
                try:
                    self.on_completed(job)
                except Exception:  # enrichment must never fail the scan
                    logging.getLogger("sas.webapp").exception(
                        "Could not start enrichment for scan %s", job.id)
        except Exception as exc:  # surface a clean error to the UI
            job.status = "failed"
            job.error = str(exc)
            db.finish_scan(job.id, "failed", {"error": str(exc)})
            job.events.put({"type": "error", "status": "failed",
                            "message": str(exc), "ts": time.time()})
        finally:
            scanner_logger.removeHandler(handler)
            for name in secret_env:
                os.environ.pop(name, None)

    def _report_paths(self, job: ScanJob) -> tuple[Optional[Path], Optional[Path]]:
        if not job.output_dir:
            return None, None
        jsons = sorted(job.output_dir.glob("scan_report_*.json"))
        htmls = sorted(job.output_dir.glob("scan_report_*.html"))
        return (jsons[-1] if jsons else None, htmls[-1] if htmls else None)

    def _summarize(self, job: ScanJob, result) -> dict[str, Any]:
        json_path, html_path = self._report_paths(job)
        data: dict[str, Any] = {}
        if json_path and json_path.exists():
            data = json.loads(json_path.read_text(encoding="utf-8"))
        return {
            "scan_id": job.id,
            "target_url": job.target_url,
            "level": job.level,
            "has_report": bool(json_path),
        }


manager = ScanManager()
