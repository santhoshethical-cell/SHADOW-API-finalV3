"""Keep server-side secrets out of logs, errors, API responses and reports.

Secrets are read from environment variables only. ``scrub`` replaces any
configured secret value (and common API-key shapes) found in a string, and
``SecretLogFilter`` applies it to every log record handled by the root logger,
so even a library that logs a request header cannot leak a key.
"""

from __future__ import annotations

import logging
import os
import re

SECRET_ENV_VARS = ("SAS_AI_API_KEY", "SAS_NVD_API_KEY", "SAS_SECRET_KEY")
_KEY_SHAPES = re.compile(
    r"(sk-ant-[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9]{20,}|"
    r"(?i:x-api-key|apikey|authorization)\s*[:=]\s*\S+)")


def _secret_values() -> list[str]:
    vals = []
    for name in SECRET_ENV_VARS:
        v = os.environ.get(name) or ""
        if len(v) >= 6:
            vals.append(v)
    return vals


def scrub(text: str) -> str:
    if not text:
        return text
    out = str(text)
    for v in _secret_values():
        out = out.replace(v, "[REDACTED-SECRET]")
    return _KEY_SHAPES.sub("[REDACTED-SECRET]", out)


class SecretLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        clean = scrub(msg)
        if clean != msg:
            record.msg, record.args = clean, ()
        return True


def install_log_filter() -> None:
    """Attach the filter to the root logger's handlers (idempotent)."""
    targets: list = []
    for name in ("", "uvicorn", "uvicorn.access", "uvicorn.error", "sas.webapp"):
        lg = logging.getLogger(name)
        targets.extend(lg.handlers or ([lg] if name == "" else []))
    for h in targets:
        if not any(isinstance(f, SecretLogFilter) for f in h.filters):
            h.addFilter(SecretLogFilter())
