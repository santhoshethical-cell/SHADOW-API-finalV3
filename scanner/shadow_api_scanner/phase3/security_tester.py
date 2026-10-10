"""
Phase 3: Security Tester Orchestrator

Coordinates controlled security validators across discovered API operations.
"""

from __future__ import annotations

import logging

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint,
    DocumentationStatus,
    EndpointSource,
    ScanResult,
    Vulnerability,
    VulnStatus,
)
from shadow_api_scanner.phase3.validation_orchestrator import (
    ValidationOrchestrator,
)
from shadow_api_scanner.phase2.route_clusterer import RouteClusterer
from shadow_api_scanner.utils.http_client import AsyncHTTPClient

logger = logging.getLogger("shadow_api_scanner")


class SecurityTester:
    """
    Phase 3 orchestrator for controlled security validators.

    Runs the controlled validator registry and collects its standardized
    results and evidence-backed vulnerability findings.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(
        self, endpoints: list[APIEndpoint], result: ScanResult
    ) -> list[Vulnerability]:
        """
        Execute Phase 3 security testing.

        Args:
            endpoints: Endpoints to test (typically shadow endpoints)
            result: ScanResult to populate

        Returns:
            List of discovered vulnerabilities
        """
        logger.info("=" * 60)
        logger.info("PHASE 3: Controlled Security Validation")
        logger.info("=" * 60)

        if not endpoints:
            logger.info("  No endpoints to test.")
            return []

        authorized_endpoints = [
            endpoint
            for endpoint in endpoints
            if self.config.is_security_target_authorized(endpoint.url)
        ]
        if len(authorized_endpoints) != len(endpoints):
            skipped = len(endpoints) - len(authorized_endpoints)
            message = (
                f"Skipped {skipped} endpoint(s) outside the exact security "
                "validation host allow-list"
            )
            logger.warning("  %s", message)
            result.warnings.append(message)
        if not authorized_endpoints:
            logger.warning(
                "  No endpoints are explicitly authorized for security "
                "validation."
            )
            return []

        representatives = self._select_representatives(authorized_endpoints)
        if len(representatives) < len(authorized_endpoints):
            logger.info(
                "  Collapsed %s endpoint observations into %s route "
                "representatives for testing.",
                len(authorized_endpoints),
                len(representatives),
            )
        logger.info(f"  Testing {len(representatives)} route representatives...")

        async with AsyncHTTPClient(self.config) as client:
            validation_batch = await ValidationOrchestrator(
                self.config,
                client,
            ).run(representatives)
            result.validation_results.extend(validation_batch.results)
            all_vulns = list(validation_batch.vulnerabilities)
            result.errors.extend(validation_batch.errors)

            result.tests_executed = client.total_requests

        self._materialize_operations(all_vulns, result)
        result.vulnerabilities = all_vulns

        # Summary
        logger.info(f"\nPhase 3 Results:")
        logger.info(f"  Total requests sent: {result.tests_executed}")
        logger.info(f"  Vulnerabilities found: {len(all_vulns)}")

        severity_counts = {}
        for v in all_vulns:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
        for sev, count in sorted(severity_counts.items()):
            logger.info(f"    {sev}: {count}")

        return all_vulns

    @staticmethod
    def _select_representatives(
        endpoints: list[APIEndpoint],
    ) -> list[APIEndpoint]:
        """Return one concrete endpoint per logical API route."""
        return RouteClusterer().cluster(endpoints)

    @staticmethod
    def _materialize_operations(
        vulnerabilities: list[Vulnerability],
        result: ScanResult,
    ) -> None:
        """Attach findings to the exact method-route operation they affect."""
        endpoints_by_id = {
            endpoint.id: endpoint for endpoint in result.all_endpoints
        }
        operations = {
            SecurityTester._operation_key(endpoint): endpoint
            for endpoint in result.all_endpoints
        }
        candidate_ids = {
            endpoint.id for endpoint in result.candidate_endpoints
        }
        for endpoint in result.candidate_endpoints:
            endpoints_by_id[endpoint.id] = endpoint
            operations.setdefault(
                SecurityTester._operation_key(endpoint),
                endpoint,
            )

        for vulnerability in vulnerabilities:
            if not vulnerability.affected_methods:
                continue
            parent = endpoints_by_id.get(vulnerability.endpoint_id)
            if parent is None:
                continue

            for method in vulnerability.affected_methods:
                normalized_method = method.upper()
                key = (
                    normalized_method,
                    parent.inventory_url,
                )
                operation = operations.get(key)
                evidence = []
                if (
                    "advertised" in vulnerability.title.lower()
                    or "allow:" in (vulnerability.poc_evidence or "").lower()
                ):
                    evidence.append("advertised")
                operation_status = (
                    vulnerability.affected_operation_status_code
                )
                live_operation = SecurityTester._confirms_live_operation(
                    vulnerability,
                    operation_status,
                )
                if (
                    operation_status not in (None, 0)
                    or vulnerability.status == VulnStatus.CONFIRMED
                ):
                    evidence.append("tested")
                if vulnerability.status == VulnStatus.CONFIRMED:
                    evidence.append("confirmed")
                if live_operation:
                    evidence.append("responsive")

                if operation is None:
                    if not live_operation:
                        documentation_status = DocumentationStatus.UNKNOWN
                        documentation_reason = (
                            "Server metadata advertised the operation, but "
                            "security validation did not confirm it live"
                        )
                        is_shadow = False
                    elif result.authoritative_baseline_found:
                        documentation_status = DocumentationStatus.SHADOW
                        documentation_reason = (
                            "Security validation discovered an operation "
                            "missing from the authoritative baseline"
                        )
                        is_shadow = True
                    else:
                        documentation_status = DocumentationStatus.UNKNOWN
                        documentation_reason = (
                            "Security validation discovered an operation, "
                            "but no authoritative baseline was available"
                        )
                        is_shadow = False

                    operation = APIEndpoint(
                        url=parent.url,
                        method=normalized_method,
                        endpoint_type=parent.endpoint_type,
                        source=EndpointSource.SECURITY_VALIDATION,
                        is_shadow=is_shadow,
                        documentation_status=documentation_status,
                        documentation_reason=documentation_reason,
                        status_code=operation_status,
                        confidence=(
                            1.0
                            if vulnerability.status == VulnStatus.CONFIRMED
                            else 0.75
                        ),
                        owner=parent.owner,
                        lifecycle=parent.lifecycle,
                        inventory_source=parent.inventory_source,
                        route_pattern=parent.route_pattern,
                        observed_urls=[parent.url],
                        observed_sources=[
                            EndpointSource.SECURITY_VALIDATION.value
                        ],
                        operation_evidence=list(dict.fromkeys(evidence)),
                        parent_endpoint_id=parent.id,
                    )
                    if live_operation:
                        result.all_endpoints.append(operation)
                        result.security_operations_discovered += 1
                    else:
                        result.candidate_endpoints.append(operation)
                        candidate_ids.add(operation.id)
                    endpoints_by_id[operation.id] = operation
                    operations[key] = operation
                    result.raw_endpoints_discovered += 1
                else:
                    operation.operation_evidence = list(dict.fromkeys(
                        operation.operation_evidence + evidence
                    ))
                    if operation_status not in (None, 0):
                        operation.status_code = operation_status
                    if live_operation and operation.id in candidate_ids:
                        result.candidate_endpoints = [
                            candidate
                            for candidate in result.candidate_endpoints
                            if candidate.id != operation.id
                        ]
                        candidate_ids.remove(operation.id)
                        operation.source = EndpointSource.SECURITY_VALIDATION
                        if result.authoritative_baseline_found:
                            operation.documentation_status = (
                                DocumentationStatus.SHADOW
                            )
                            operation.documentation_reason = (
                                "Security validation confirmed an operation "
                                "missing from the authoritative baseline"
                            )
                            operation.is_shadow = True
                        result.all_endpoints.append(operation)
                        result.security_operations_discovered += 1

                vulnerability.endpoint_id = operation.id

        result.shadow_endpoints = [
            endpoint for endpoint in result.all_endpoints
            if endpoint.is_shadow
        ]
        result.documented_endpoints = [
            endpoint for endpoint in result.all_endpoints
            if endpoint.documentation_status
            == DocumentationStatus.DOCUMENTED
        ]

    @staticmethod
    def _confirms_live_operation(
        vulnerability: Vulnerability,
        status_code: int | None,
    ) -> bool:
        """Return whether method-level validation confirmed a live operation."""
        if vulnerability.status == VulnStatus.CONFIRMED:
            return True
        return (
            status_code is not None
            and status_code not in {0, 404, 405, 410, 501}
        )

    @staticmethod
    def _operation_key(endpoint: APIEndpoint) -> tuple[str, str]:
        return endpoint.method.upper(), endpoint.inventory_url
