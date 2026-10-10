"""Low-severity information disclosure via verbose response headers.

Servers that advertise their exact software and version (``Server: nginx/1.18.0``,
``X-Powered-By: Express``, ``X-AspNet-Version: 4.0.30319`` …) hand an attacker a
free fingerprint for targeted exploits. This is a classic low-severity
misconfiguration (OWASP API8 Security Misconfiguration; CWE-200 Exposure of
Sensitive Information). It is detected passively from headers the server already
returns, and scored with a low per-instance base so it lands in the CVSS "Low"
band rather than at the API8 category ceiling.
"""

from __future__ import annotations

import re

from shadow_api_scanner.core.config import OWASP_CATEGORIES, ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint,
    RiskLevel,
    ValidationOutcome,
    ValidationResult,
    Vulnerability,
    VulnStatus,
)
from shadow_api_scanner.utils.http_client import AsyncHTTPClient


OWASP_MISCONFIG_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa8-security-misconfiguration/"
)
# Headers whose value fingerprints the stack; `server` only counts when it
# carries a version token (a bare "nginx" is negligible).
VERSION_HEADERS = (
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-generator", "x-version", "x-drupal-dynamic-cache",
)
_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+)+|/\d")
_LOW_BASE = 3.0  # per-instance base -> CVSS "Low" band


class InfoDisclosureConfigError(ValueError):
    """Raised when the information-disclosure assessment cannot run safely."""


class InfoDisclosureValidator:
    """Flag verbose version/tech banners as a low-severity misconfiguration."""

    name = "information_disclosure"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client
        scope_error = self.config.security_scope_error()
        if scope_error:
            raise InfoDisclosureConfigError(scope_error)

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []

        # Group authorized endpoints by host; a version banner is a host-level
        # property, so we report at most one finding per host.
        by_host: dict[str, list[APIEndpoint]] = {}
        for endpoint in endpoints:
            if not self.config.is_security_target_authorized(endpoint.url):
                continue
            by_host.setdefault(self._host(endpoint.url), []).append(endpoint)

        for host, host_endpoints in by_host.items():
            anchor = host_endpoints[0]
            # Probe the origin root plus a few endpoints — a single request can
            # miss the banner (405/redirect/param-only), so don't conclude
            # "clean" from one probe.
            probe_urls = self._probe_urls(host_endpoints)
            disclosed: dict = {}
            probed = 0
            for url in probe_urls:
                headers = await self._response_headers(url)
                if headers is None:
                    continue
                probed += 1
                disclosed = self._extract(headers)
                if disclosed:
                    break

            if probed == 0:
                continue  # host unreachable; nothing to assert
            if not disclosed:
                results.append(self._result(
                    anchor, ValidationOutcome.PROTECTED, 0.8,
                    "No version or technology banner was exposed across the "
                    "sampled endpoints", {},
                ))
                continue

            reason = (
                "Response headers advertise software/version: "
                + "; ".join(f"{k}: {v}" for k, v in disclosed.items())
            )
            results.append(self._result(
                anchor, ValidationOutcome.VULNERABLE, 1.0, reason,
                {"disclosed_headers": disclosed},
            ))
            vulnerabilities.append(self._vulnerability(anchor, disclosed, reason))
        return results, vulnerabilities

    def _probe_urls(self, host_endpoints: list[APIEndpoint]) -> list[str]:
        from urllib.parse import urlparse
        parsed = urlparse(host_endpoints[0].url)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        urls = [root]
        for endpoint in host_endpoints[:5]:
            if endpoint.url not in urls:
                urls.append(endpoint.url)
        return urls

    async def _response_headers(self, url: str) -> dict | None:
        try:
            captured = await self.client.request("GET", url, retries=0)
        except Exception:
            return None
        return {
            str(k).lower(): str(v)
            for k, v in captured.response_headers.items()
        }

    def _extract(self, headers: dict) -> dict:
        disclosed: dict[str, str] = {}
        server = headers.get("server", "")
        if server and _VERSION_TOKEN.search(server):
            disclosed["Server"] = server
        for name in VERSION_HEADERS:
            value = headers.get(name)
            if value and value.strip():
                disclosed[name.title()] = value
        return disclosed

    def _vulnerability(
        self, endpoint: APIEndpoint, disclosed: dict, reason: str
    ) -> Vulnerability:
        category = OWASP_CATEGORIES["API8"]
        return Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API8",
            owasp_name=category["name"],
            title="Verbose version / technology disclosure in headers",
            description=(
                "The server discloses its software and/or version through "
                "response headers (" + ", ".join(disclosed) + "). This is a "
                "low-severity security misconfiguration: it does not grant "
                "access by itself, but hands an attacker a precise fingerprint "
                "for selecting version-specific exploits. Remove or genericise "
                "the offending headers."
            ),
            severity=RiskLevel.LOW,
            status=VulnStatus.CONFIRMED,   # the banner is directly observed
            confidence=1.0,
            base_score_override=_LOW_BASE,
            poc_request=f"GET {endpoint.url}",
            poc_evidence=reason,
            affected_methods=[],
            remediation=(
                "Suppress or genericise version banners (Server, X-Powered-By, "
                "X-AspNet-Version, etc.) at the app/proxy layer."
            ),
            cwe_id="CWE-200",
            references=[OWASP_MISCONFIG_REFERENCE],
        )

    def _result(
        self,
        endpoint: APIEndpoint,
        outcome: ValidationOutcome,
        confidence: float,
        reason: str,
        evidence: dict,
    ) -> ValidationResult:
        return ValidationResult(
            endpoint_id=endpoint.id,
            endpoint=endpoint.url,
            method=endpoint.method.upper(),
            validator=self.name,
            vulnerability_category="API8:2023 Security Misconfiguration",
            result=outcome,
            severity=(
                RiskLevel.LOW
                if outcome == ValidationOutcome.VULNERABLE
                else RiskLevel.INFO
            ),
            confidence=confidence,
            evidence={"reason": reason, **evidence},
            remediation="Genericise version/technology response headers.",
            references=[OWASP_MISCONFIG_REFERENCE],
        )

    @staticmethod
    def _host(url: str) -> str:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
