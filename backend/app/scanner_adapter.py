"""Adapter over the validated scanner library. No scanning logic is reimplemented.

Maps the three web "levels" onto the existing ScanConfig, applies the advanced
options collected by the UI, and enforces the authorized-host safety gate on the
server side so it cannot be bypassed from the browser.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from shadow_api_scanner.core.config import ScanConfig
from app.scan_options import materialize, OptionsError

LEVELS = ("basic", "standard", "advanced")

LEVEL_LABELS = {
    "basic": "Basic — shadow-API discovery only (Phase 1 + 2)",
    "standard": "Standard — discovery + security validation (Phase 3)",
    "advanced": "Advanced — full pipeline, most thorough",
}


class AuthorizationRequired(ValueError):
    """Raised when a security-testing level is requested without confirmation."""


def normalize_target(url: str) -> str:
    candidate = (url or "").strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http(s) URL with a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URL-embedded credentials are not accepted.")
    return candidate


def build_config(
    target_url: str,
    level: str,
    authorized_confirmed: bool,
    output_dir: str,
    options: Optional[dict] = None,
    scan_id: str = "",
) -> tuple[ScanConfig, dict]:
    """Build a ScanConfig from level + advanced options.

    Returns (config, secret_env). ``secret_env`` maps unique per-scan
    environment-variable names to the credential values the operator entered;
    ScanManager sets these in the process environment only for this scan and
    clears them afterwards. No secret is ever written to disk.
    """
    level = (level or "").lower()
    if level not in LEVELS:
        raise ValueError(f"Unknown level '{level}'.")
    target_url = normalize_target(target_url)
    host = urlparse(target_url).hostname or ""

    # Basic = discovery only. Standard/Advanced require explicit authorization
    # confirmation for the exact target host — the same gate as the CLI's
    # --authorized-host, enforced here and not overridable from the UI.
    security = level in ("standard", "advanced")
    if security and not authorized_confirmed:
        raise AuthorizationRequired(
            "Security validation requires you to confirm you are authorized "
            "to test this target."
        )

    config = ScanConfig(
        target_url=target_url,
        output_dir=output_dir,
        enable_security_testing=security,
        enable_active_testing=(level == "advanced"),
        security_authorized_hosts=[host] if security else [],
        report_formats=["json", "html"],
        verbose=False,
    )
    if level == "advanced":
        config.max_security_requests = 400

    overrides, secret_env = materialize(
        options,
        scan_id=scan_id,
        job_dir=Path(output_dir),
        target_url=target_url,
        security_enabled=security,
    )
    _apply_overrides(config, overrides)
    return config, secret_env


def _apply_overrides(config: ScanConfig, overrides: dict[str, Any]) -> None:
    """Apply materialized option overrides onto the ScanConfig instance."""
    extra_hosts = overrides.pop("security_authorized_hosts_extra", None)
    for key, value in overrides.items():
        if hasattr(config, key):
            setattr(config, key, value)
    # Extra authorized hosts extend (never replace) the confirmed target host,
    # so validators may reach approved sibling hosts without weakening the gate.
    if extra_hosts and config.enable_security_testing:
        merged = list(dict.fromkeys(config.security_authorized_hosts + list(extra_hosts)))
        config.security_authorized_hosts = merged
