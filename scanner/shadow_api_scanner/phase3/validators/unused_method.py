"""Non-destructive detection of undocumented / unused HTTP methods.

Many APIs expose more HTTP methods on an endpoint than the front-end client
ever uses. A price endpoint whose client only issues ``GET`` may still accept
``PATCH``; an object endpoint may still accept ``DELETE``. These unused,
undocumented operations enlarge the attack surface and frequently miss the
authorization checks applied to the documented operations, which is the root
cause behind Broken Function Level Authorization (API5) and mass-assignment /
Broken Object Property Level Authorization (API3).

This validator is strictly passive: it issues a single read-only ``OPTIONS``
request per route and reads the server's own ``Allow`` header. It never
exercises the extra method, so it reports the exposure as *potential* — a
confirmed exploit requires the authorized active mass-assignment path.
"""

from __future__ import annotations

from shadow_api_scanner.core.config import OWASP_CATEGORIES, ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint,
    RiskLevel,
    ValidationOutcome,
    ValidationResult,
    Vulnerability,
    VulnStatus,
)
from shadow_api_scanner.utils.helpers import normalize_url
from shadow_api_scanner.utils.http_client import AsyncHTTPClient


STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
OWASP_INVENTORY_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa9-improper-inventory-management/"
)


class MethodEnumerationConfigError(ValueError):
    """Raised when the unused-method assessment cannot run safely."""


class UnusedMethodValidator:
    """Flag state-changing methods the server advertises but the app never uses."""

    name = "unused_method_exposure"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client
        scope_error = self.config.security_scope_error()
        if scope_error:
            raise MethodEnumerationConfigError(scope_error)

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []

        # Methods the application is actually observed using, per logical route.
        # Sibling operations (e.g. a documented GET and a documented POST) are
        # separate representatives, so their methods are all collected here and
        # will not be mis-reported as "unused".
        used_by_route: dict[str, set[str]] = {}
        for endpoint in endpoints:
            key = self._route_key(endpoint)
            used_by_route.setdefault(key, set()).add(endpoint.method.upper())

        # One OPTIONS probe per concrete route, not per observation.
        seen_routes: set[str] = set()
        for endpoint in endpoints:
            key = self._route_key(endpoint)
            if key in seen_routes:
                continue
            seen_routes.add(key)

            if not self.config.is_security_target_authorized(endpoint.url):
                results.append(self._result(
                    endpoint, ValidationOutcome.SKIPPED, 1.0,
                    "Endpoint is outside the exact security allow-list",
                    {},
                ))
                continue

            result, vulnerability = await self._assess(
                endpoint, used_by_route.get(key, {endpoint.method.upper()})
            )
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)
        return results, vulnerabilities

    async def _assess(
        self,
        endpoint: APIEndpoint,
        used_methods: set[str],
    ) -> tuple[ValidationResult, Vulnerability | None]:
        advertised, options_status = await self._advertised_methods(endpoint)

        if advertised is None:
            return self._result(
                endpoint, ValidationOutcome.INCONCLUSIVE, 0.6,
                "The server did not return an Allow header for OPTIONS; the "
                "supported method set could not be enumerated non-destructively",
                {"options_status": options_status, "used_methods": sorted(used_methods)},
            ), None

        unused = sorted(
            method for method in advertised
            if method in STATE_CHANGING_METHODS and method not in used_methods
        )
        evidence = {
            "options_status": options_status,
            "advertised_methods": sorted(advertised),
            "used_methods": sorted(used_methods),
            "unused_state_changing_methods": unused,
        }

        if not unused:
            return self._result(
                endpoint, ValidationOutcome.PROTECTED, 0.75,
                "Every state-changing method the server advertises is already "
                "used by the application; no undocumented method was exposed",
                evidence,
            ), None

        reason = (
            f"Server advertised 'Allow: {', '.join(sorted(advertised))}' but the "
            f"application only uses {sorted(used_methods)}. The unused "
            f"state-changing method(s) {unused} are undocumented and expand the "
            "attack surface."
        )
        result = self._result(
            endpoint, ValidationOutcome.VULNERABLE, 0.85, reason, evidence,
        )
        return result, self._vulnerability(endpoint, advertised, used_methods, unused, options_status)

    async def _advertised_methods(
        self, endpoint: APIEndpoint
    ) -> tuple[set[str] | None, int | None]:
        """Return the server-advertised method set via a read-only OPTIONS probe."""
        try:
            captured = await self.client.request(
                "OPTIONS", endpoint.url, retries=0,
            )
        except Exception:
            return None, None
        headers = {
            str(key).lower(): str(value)
            for key, value in captured.response_headers.items()
        }
        allow = headers.get("allow", "")
        if not allow.strip():
            return None, captured.status_code
        methods = {
            token.strip().upper()
            for token in allow.split(",")
            if token.strip()
        }
        return methods, captured.status_code

    def _vulnerability(
        self,
        endpoint: APIEndpoint,
        advertised: set[str],
        used_methods: set[str],
        unused: list[str],
        options_status: int | None,
    ) -> Vulnerability:
        category = OWASP_CATEGORIES["API9"]
        severity = RiskLevel.HIGH if "DELETE" in unused else RiskLevel.MEDIUM
        allow_value = ", ".join(sorted(advertised))
        return Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API9",
            owasp_name=category["name"],
            title=(
                f"Undocumented state-changing method exposed "
                f"({', '.join(unused)})"
            ),
            description=(
                "The endpoint advertises HTTP method(s) that the application "
                f"client never uses. The server's own OPTIONS response allows "
                f"[{allow_value}], while the application only uses "
                f"{sorted(used_methods)}. The additional state-changing "
                f"method(s) {unused} are undocumented and unused by the "
                "front-end, so they are easily overlooked and frequently miss "
                "the authorization enforced on the documented operations. This "
                "is the root cause behind Broken Function Level Authorization "
                "(API5) and mass-assignment / Broken Object Property Level "
                "Authorization (API3). Detected non-destructively via OPTIONS; "
                "the method was not exercised, so exploitability is potential "
                "until an authorized active test confirms it."
            ),
            severity=severity,
            status=VulnStatus.POTENTIAL,
            risk_score=category["base_score"],
            confidence=0.85,
            poc_request=f"OPTIONS {endpoint.url}",
            poc_response=f"Allow: {allow_value}",
            poc_status_code=options_status,
            poc_evidence=(
                f"OPTIONS returned 'Allow: {allow_value}'. The application only "
                f"uses {sorted(used_methods)}; {unused} is undocumented and unused."
            ),
            affected_methods=unused,
            affected_operation_status_code=options_status,
            remediation=(
                "Restrict each endpoint to the methods the application actually "
                "uses (return 405 for the rest), or explicitly document the "
                "additional operations and enforce the same authentication and "
                "object/function-level authorization on them. Confirm each "
                "advertised state-changing method rejects unauthorized callers."
            ),
            cwe_id="CWE-16",
            references=[OWASP_INVENTORY_REFERENCE],
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
            vulnerability_category="API9:2023 Improper Inventory Management",
            result=outcome,
            severity=(
                RiskLevel.MEDIUM
                if outcome == ValidationOutcome.VULNERABLE
                else RiskLevel.INFO
            ),
            confidence=confidence,
            evidence={"reason": reason, **evidence},
            remediation=(
                "Expose only the HTTP methods each endpoint needs and apply the "
                "same authorization to every method it accepts."
            ),
            references=[OWASP_INVENTORY_REFERENCE],
        )

    @staticmethod
    def _route_key(endpoint: APIEndpoint) -> str:
        return endpoint.route_pattern or normalize_url(endpoint.url)
