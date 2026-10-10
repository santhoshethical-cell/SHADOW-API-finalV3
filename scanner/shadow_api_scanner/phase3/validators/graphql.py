"""GraphQL-aware validator: introspection exposure and schema-suggestion leakage.

The other Phase 3 validators reason about REST semantics (a URL and an HTTP
method). GraphQL puts the operation in the request body, so a dedicated,
read-only validator is needed. This one performs two non-destructive probes
against endpoints typed as GraphQL:

1. **Introspection exposure** — a minimal introspection query. If the server
   returns its schema, introspection is enabled, which discloses the full API
   shape (a common production misconfiguration).
2. **Schema-suggestion leakage** — a query for a non-existent field. If the
   error suggests the real field name ("Did you mean ...?"), the schema leaks
   even when introspection is disabled.

Both probes are single, read-only POST requests carrying no state-changing
mutation, so the validator runs in the passive tier.
"""

from __future__ import annotations

import json as json_mod
from typing import Any, Optional
from urllib.parse import urlparse

from shadow_api_scanner.core.config import OWASP_CATEGORIES, ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint,
    EndpointType,
    RiskLevel,
    ValidationOutcome,
    ValidationResult,
    Vulnerability,
    VulnStatus,
)
from shadow_api_scanner.utils.http_client import AsyncHTTPClient, CapturedRequest

OWASP_MISCONFIG_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa8-security-misconfiguration/"
)

INTROSPECTION_QUERY = "query ShadowScanIntrospect{__schema{queryType{name}}}"
INVALID_FIELD_QUERY = "query ShadowScanProbe{shadowScanNonexistentField_zzz}"


class GraphQLConfigError(ValueError):
    """Raised when the GraphQL validator cannot run safely."""


class GraphQLValidator:
    """Read-only GraphQL security checks (introspection, schema leakage)."""

    name = "graphql_introspection_exposure"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client

    @staticmethod
    def _is_graphql(endpoint: APIEndpoint) -> bool:
        if endpoint.endpoint_type == EndpointType.GRAPHQL:
            return True
        path = urlparse(endpoint.url).path.lower()
        return path.endswith("/graphql") or path.endswith("/graphiql")

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []
        seen: set[str] = set()
        for endpoint in endpoints:
            if not self._is_graphql(endpoint):
                continue  # REST endpoints are handled by the other validators
            # One assessment per transport URL (method is always POST here).
            key = urlparse(endpoint.url)._replace(query="").geturl()
            if key in seen:
                continue
            seen.add(key)
            if not self.config.is_security_target_authorized(endpoint.url):
                results.append(self._result(
                    endpoint, ValidationOutcome.SKIPPED, 1.0,
                    "Endpoint is outside the exact security allow-list", {}))
                continue
            result, vulnerability = await self._assess(endpoint)
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)
        return results, vulnerabilities

    async def _assess(
        self,
        endpoint: APIEndpoint,
    ) -> tuple[ValidationResult, Vulnerability | None]:
        target = urlparse(endpoint.url)._replace(query="").geturl()
        introspection = await self._graphql_post(target, INTROSPECTION_QUERY)
        if introspection.status_code == 0:
            return self._result(
                endpoint, ValidationOutcome.ERROR, 1.0,
                "Introspection probe failed at the transport layer", {}), None

        intro_state, intro_body = self._introspection_state(introspection)
        # Secondary, weaker signal only when introspection is not confirmed on.
        suggestion_leak = False
        if intro_state != "enabled":
            probe = await self._graphql_post(target, INVALID_FIELD_QUERY)
            suggestion_leak = self._has_field_suggestion(probe)

        evidence = {
            "transport": target,
            "introspection": intro_state,
            "introspection_status_code": introspection.status_code,
            "schema_suggestion_leak": suggestion_leak,
        }

        if intro_state == "enabled":
            outcome = ValidationOutcome.VULNERABLE
            confidence = 0.95
            reason = (
                "GraphQL introspection is enabled; the full schema "
                "(queryType) was returned to an unauthenticated caller"
            )
        elif intro_state == "disabled":
            if suggestion_leak:
                outcome = ValidationOutcome.INCONCLUSIVE
                confidence = 0.7
                reason = (
                    "Introspection is disabled, but error messages suggest "
                    "real field names (schema-suggestion leakage) — review"
                )
            else:
                outcome = ValidationOutcome.PROTECTED
                confidence = 0.9
                reason = "GraphQL introspection is disabled"
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            confidence = 0.6
            reason = (
                "Introspection response was inconclusive; could not confirm "
                "whether the schema is exposed"
            )

        result = self._result(endpoint, outcome, confidence, reason, evidence)
        if outcome != ValidationOutcome.VULNERABLE:
            return result, None

        category = OWASP_CATEGORIES["API8"]
        vulnerability = Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API8",
            owasp_name=category["name"],
            title="GraphQL introspection exposed",
            description=(
                "The GraphQL endpoint answers introspection queries, "
                "disclosing its complete schema (types, fields, and "
                "arguments) to any caller. This greatly lowers the effort to "
                "map and attack the API and is a security misconfiguration in "
                "a production-facing service."
            ),
            severity=RiskLevel.MEDIUM,
            status=VulnStatus.CONFIRMED,
            risk_score=category["base_score"],
            confidence=confidence,
            poc_request=(
                f"POST {target}  "
                f'{{"query":"{INTROSPECTION_QUERY}"}}'
            ),
            poc_status_code=introspection.status_code,
            poc_evidence=reason,
            affected_methods=["POST"],
            affected_operation_status_code=introspection.status_code,
            remediation=(
                "Disable GraphQL introspection in production (or restrict it to "
                "authenticated administrators), and disable verbose field "
                "suggestions in error messages."
            ),
            cwe_id="CWE-200",
            references=[OWASP_MISCONFIG_REFERENCE],
        )
        return result, vulnerability

    async def _graphql_post(self, url: str, query: str) -> CapturedRequest:
        return await self.client.request(
            "POST",
            url,
            json_body={"query": query},
            retries=0,
        )

    @staticmethod
    def _parse(captured: CapturedRequest) -> Optional[dict]:
        body = captured.response_body or ""
        try:
            parsed = json_mod.loads(body)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _introspection_state(
        self, captured: CapturedRequest
    ) -> tuple[str, Optional[dict]]:
        """Return one of 'enabled' | 'disabled' | 'inconclusive'."""
        parsed = self._parse(captured)
        if parsed is None:
            return "inconclusive", None
        data = parsed.get("data")
        if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
            schema = data["__schema"]
            if isinstance(schema.get("queryType"), dict):
                return "enabled", parsed
        # No schema returned — look at errors to distinguish disabled vs noise.
        errors = parsed.get("errors")
        blob = json_mod.dumps(errors).lower() if errors else ""
        disabled_markers = (
            "introspection is disabled",
            "introspection is not allowed",
            "introspection query",
            "graphql introspection",
            "introspectionquery",
            "field \"__schema\"",
            "cannot query field \"__schema\"",
        )
        if any(marker in blob for marker in disabled_markers):
            return "disabled", parsed
        if errors:
            return "disabled", parsed
        return "inconclusive", parsed

    def _has_field_suggestion(self, captured: CapturedRequest) -> bool:
        parsed = self._parse(captured)
        if parsed is None:
            return False
        errors = parsed.get("errors")
        if not errors:
            return False
        blob = json_mod.dumps(errors).lower()
        return "did you mean" in blob

    def _result(
        self,
        endpoint: APIEndpoint,
        outcome: ValidationOutcome,
        confidence: float,
        reason: str,
        evidence: dict[str, Any],
    ) -> ValidationResult:
        return ValidationResult(
            endpoint_id=endpoint.id,
            endpoint=endpoint.url,
            method="POST",
            validator=self.name,
            vulnerability_category="API8:2023 Security Misconfiguration",
            result=outcome,
            severity=(
                RiskLevel.MEDIUM
                if outcome == ValidationOutcome.VULNERABLE
                else RiskLevel.INFO
            ),
            confidence=confidence,
            evidence={"reason": reason, **evidence},
            remediation=(
                "Disable introspection and verbose field suggestions in "
                "production GraphQL endpoints."
            ),
            references=[OWASP_MISCONFIG_REFERENCE],
        )
