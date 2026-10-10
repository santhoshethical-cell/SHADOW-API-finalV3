"""
Global configuration and constants for Shadow API Scanner.

Centralizes all tunable settings, OWASP category definitions,
severity mappings, and default scan parameters.
"""

import platform
import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


# --------------------------------------------------------------
# OWASP API Security Top 10 (2023) Categories
# --------------------------------------------------------------

OWASP_CATEGORIES = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization (BOLA)",
        "severity": "Critical",
        "description": "APIs exposing endpoints that handle object identifiers, "
                       "creating a wide attack surface for object-level access control.",
        "base_score": 9.0,
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "severity": "Critical",
        "description": "Authentication mechanisms implemented incorrectly, "
                       "allowing attackers to compromise authentication tokens.",
        "base_score": 9.0,
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "severity": "High",
        "description": "Lack of or improper authorization validation at the "
                       "object property level.",
        "base_score": 7.5,
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "severity": "High",
        "description": "API requests consume resources such as network bandwidth, "
                       "CPU, memory, and storage without any restrictions.",
        "base_score": 7.0,
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "severity": "Critical",
        "description": "Complex access control policies with different hierarchies, "
                       "groups, and roles creating authorization flaws.",
        "base_score": 8.5,
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "severity": "High",
        "description": "APIs exposing business flows without compensating for "
                       "the risk of automated access.",
        "base_score": 7.0,
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery (SSRF)",
        "severity": "High",
        "description": "SSRF flaws occur when an API fetches a remote resource "
                       "without validating the user-supplied URI.",
        "base_score": 8.0,
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "severity": "Medium",
        "description": "APIs and supporting systems typically contain complex "
                       "configurations that can be misconfigured.",
        "base_score": 6.5,
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "severity": "Medium",
        "description": "APIs tend to expose more endpoints than traditional web "
                       "applications, making proper documentation important.",
        "base_score": 6.0,
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "severity": "Medium",
        "description": "Developers tend to trust data received from third-party "
                       "APIs without proper validation.",
        "base_score": 6.0,
    },
}

# --------------------------------------------------------------
# Severity -> Numeric Ranges
# --------------------------------------------------------------

SEVERITY_LEVELS = {
    "Critical": {"min": 9.0, "max": 10.0, "color": "#DC2626"},
    "High": {"min": 7.0, "max": 8.9, "color": "#EA580C"},
    "Medium": {"min": 4.0, "max": 6.9, "color": "#CA8A04"},
    "Low": {"min": 0.1, "max": 3.9, "color": "#16A34A"},
    "Info": {"min": 0.0, "max": 0.0, "color": "#2563EB"},
}

# --------------------------------------------------------------
# Sensitive Data Patterns (for response analysis)
# --------------------------------------------------------------

SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "password_field": r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "phone": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "internal_ip": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "stack_trace": r"(?i)(traceback|stack\s*trace|exception|error\s+at\s+line)",
    "sql_error": r"(?i)(sql\s*syntax|mysql|postgresql|sqlite|ora-\d+|unclosed\s+quotation)",
}


# --------------------------------------------------------------
# Scan Configuration Dataclass
# --------------------------------------------------------------

@dataclass
class ScanConfig:
    """Configuration for a single scan run."""

    target_url: str
    output_dir: str = "reports"
    openapi_spec_url: Optional[str] = None
    openapi_spec_file: Optional[str] = None

    # Phase 1 settings
    max_js_files: int = 200
    max_discovery_concurrency: int = 10
    js_download_timeout: int = 30  # seconds per file
    crawl_depth: int = 3
    max_template_expansions: int = 25

    # Phase 2 settings
    browser_timeout: int = 60  # seconds for dynamic monitoring
    browser_headless: bool = True
    wait_after_load: int = 10  # seconds to wait after page load for XHR
    interaction_wait: int = 0
    browser_storage_state: Optional[str] = None

    # Phase 3 settings
    request_timeout: float = 15.0  # seconds per request
    rate_limit_delay: float = 0.5  # seconds between requests
    max_security_requests: int = 250
    max_security_response_bytes: int = 1024 * 1024
    max_redirects: int = 5
    verify_tls: bool = True
    enable_security_testing: bool = True
    enable_active_testing: bool = False
    bola_config_file: Optional[str] = None
    auth_validation_config_file: Optional[str] = None
    parameter_validation_config_file: Optional[str] = None
    injection_validation_config_file: Optional[str] = None
    access_validation_config_file: Optional[str] = None
    security_authorized_hosts: list[str] = field(default_factory=list)
    sensitive_field_patterns: list[str] = field(default_factory=list)
    rate_limit_probe_requests: int = 5
    rate_limit_probe_delay: float = 0.25
    rate_limit_probe_concurrency: int = 1
    rate_limit_probe_timeout: float = 5.0

    # Phase 4 settings
    report_formats: list = field(default_factory=lambda: ["json", "html"])
    include_poc: bool = True  # include proof-of-concept in report

    # General
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    verbose: bool = False
    auth_token: Optional[str] = None
    auth_header: str = "Authorization"
    cookie: Optional[str] = None
    # Mode A programmatic session acquisition (API login before Phase 1).
    login_config_file: Optional[str] = None
    custom_headers: dict = field(default_factory=dict)
    har_files: list[str] = field(default_factory=list)
    traffic_log_files: list[str] = field(default_factory=list)
    api_inventory_file: Optional[str] = None
    save_baseline: Optional[str] = None
    compare_baseline: Optional[str] = None
    auto_evidence: bool = True
    auto_history: bool = True
    ground_truth_file: Optional[str] = None

    # Zero-configuration browser exploration
    browser_max_pages: int = 25
    browser_crawl_depth: int = 2
    browser_max_interactions: int = 10
    browser_max_response_bytes: int = 65536

    def __post_init__(self) -> None:
        if not 1 <= self.max_discovery_concurrency <= 20:
            raise ValueError(
                "max_discovery_concurrency must be between 1 and 20"
            )

    @property
    def is_windows(self) -> bool:
        return platform.system() == "Windows"

    @property
    def is_linux(self) -> bool:
        return platform.system() == "Linux"

    def get_headers(self) -> dict:
        """Build default request headers."""
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.auth_token:
            headers[self.auth_header] = self.auth_token
        if self.cookie:
            headers["Cookie"] = self.cookie
        headers.update(self.custom_headers)
        return headers

    def security_scope_error(self, url: Optional[str] = None) -> str | None:
        """Return why active security validation is not explicitly scoped."""
        hosts = {
            str(host).strip().lower()
            for host in self.security_authorized_hosts
            if str(host).strip()
        }
        if not hosts:
            return "no exact security-validation host allow-list was supplied"
        invalid_hosts = []
        for host in hosts:
            if "*" in host or "/" in host:
                invalid_hosts.append(host)
                continue
            if ":" in host:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    invalid_hosts.append(host)
        if invalid_hosts:
            return (
                "security-validation hosts must be exact hostnames or IP "
                "addresses without wildcards, schemes, paths, or ports"
            )
        parsed = urlparse(url or self.target_url)
        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in hosts:
            return f"host {hostname or '<missing>'} is not explicitly authorized"
        return None

    def is_security_target_authorized(self, url: Optional[str] = None) -> bool:
        """Return whether an exact host allow-list authorizes validation."""
        return self.security_scope_error(url) is None
