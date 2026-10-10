"""
Phase 2: Shadow / Unmanaged API Detector

Merges static and dynamic findings, compares against documented APIs,
and identifies active, undocumented, unmanaged endpoints.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse
from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint, DocumentationStatus, EndpointSource, ScanResult,
)
from shadow_api_scanner.phase2.api_inventory import APIInventory
from shadow_api_scanner.phase2.route_clusterer import RouteClusterer
from shadow_api_scanner.phase2.traffic_monitor import TrafficMonitor
from shadow_api_scanner.phase2.spec_comparator import SpecComparator
from shadow_api_scanner.phase1.template_resolver import (
    contains_template_expression,
)
from shadow_api_scanner.utils.helpers import is_same_origin, normalize_url

logger = logging.getLogger("shadow_api_scanner")


class ShadowDetector:
    """
    Phase 2 orchestrator: merge inventories and detect shadow/unmanaged APIs.

    1. Run dynamic traffic monitoring
    2. Discover/parse OpenAPI spec
    3. Merge static + dynamic findings
    4. Classify endpoints as documented, shadow/unmanaged, or unverified
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.spec_comparator = SpecComparator(config)
        self.api_inventory = APIInventory(config)
        self.route_clusterer = RouteClusterer()

    async def run(
        self, static_endpoints: list[APIEndpoint], result: ScanResult
    ) -> list[APIEndpoint]:
        """
        Execute Phase 2: dynamic monitoring + shadow detection.

        Args:
            static_endpoints: Endpoints from Phase 1
            result: ScanResult to populate

        Returns:
            List of all endpoints with shadow flag set
        """
        # Step 1: Dynamic traffic monitoring
        monitor = TrafficMonitor(self.config)
        dynamic_endpoints = await monitor.run()
        result.warnings.extend(
            warning for warning in monitor.errors
            if warning not in result.warnings
        )
        result.dynamic_endpoints = dynamic_endpoints
        result.traffic_requests_captured = len(dynamic_endpoints)

        # Step 2: Discover/parse OpenAPI spec
        documented_endpoints = await self.spec_comparator.discover_and_parse()
        if documented_endpoints:
            result.openapi_spec_found = True
            result.authoritative_baseline_found = True
            result.baseline_sources.append("openapi")

        inventory_endpoints = self.api_inventory.load()
        if inventory_endpoints:
            documented_endpoints.extend(inventory_endpoints)
            result.authoritative_baseline_found = True
            result.baseline_sources.append("api_inventory")

        if documented_endpoints:
            result.documented_endpoints = documented_endpoints

        # Step 3: Merge all findings
        raw_endpoints = self._merge_endpoints(
            static_endpoints, dynamic_endpoints, documented_endpoints
        )
        raw_endpoints = self._exclude_documentation_pages(
            raw_endpoints,
            result,
        )
        raw_endpoints = self._exclude_cross_origin(raw_endpoints, result)
        result.raw_endpoints_discovered = len(raw_endpoints)

        # Step 4: Classify documented vs shadow/unmanaged vs unknown
        for ep in raw_endpoints:
            self.classify_endpoint(ep, result)

        clustered_endpoints = self.route_clusterer.cluster(raw_endpoints)
        all_endpoints, candidate_endpoints = (
            self._partition_method_candidates(clustered_endpoints)
        )
        shadow_count = sum(1 for ep in all_endpoints if ep.is_shadow)
        documented_count = sum(
            1 for ep in all_endpoints
            if ep.documentation_status == DocumentationStatus.DOCUMENTED
        )
        unknown_count = sum(
            1 for ep in all_endpoints
            if ep.documentation_status == DocumentationStatus.UNKNOWN
        )

        result.all_endpoints = all_endpoints
        result.candidate_endpoints = candidate_endpoints
        result.shadow_endpoints = [ep for ep in all_endpoints if ep.is_shadow]
        result.documented_endpoints = [
            ep for ep in all_endpoints
            if ep.documentation_status == DocumentationStatus.DOCUMENTED
        ]
        if unknown_count and not result.authoritative_baseline_found:
            result.warnings.append(
                "No authoritative API specification or inventory was found; "
                f"{unknown_count} discovered endpoint(s) are unclassified, "
                "not confirmed Shadow / Unmanaged APIs."
            )
        elif unknown_count:
            result.warnings.append(
                f"{unknown_count} endpoint(s) are related to approved API "
                "families but were not exact inventory/spec matches."
            )
        if candidate_endpoints:
            result.warnings.append(
                f"{len(candidate_endpoints)} server-advertised method(s) "
                "were retained as candidates because live operation was not "
                "confirmed."
            )

        logger.info(f"\nShadow Detection Results:")
        logger.info(
            "  Logical API routes: %s (%s concrete observations)",
            len(all_endpoints),
            len(raw_endpoints),
        )
        logger.info(
            "  Shadow / Unmanaged (active and undocumented): %s",
            shadow_count,
        )
        logger.info(f"  Documented: {documented_count}")
        logger.info(f"  Unknown documentation status: {unknown_count}")
        logger.info(
            "  Unverified method candidates: %s",
            len(candidate_endpoints),
        )
        logger.info(f"  OpenAPI spec found: {result.openapi_spec_found}")

        if result.shadow_endpoints:
            logger.info("\n  Confirmed Shadow / Unmanaged APIs:")
            for ep in result.shadow_endpoints:
                logger.info(f"    {ep.method:6s} {ep.url}")
        elif unknown_count:
            reason = (
                "because no spec was available"
                if not result.openapi_spec_found
                else "because they are related to documented paths but not exact operations"
            )
            logger.info(
                "\n  No confirmed Shadow / Unmanaged APIs; endpoints are "
                "unclassified "
                f"{reason}."
            )

        return all_endpoints

    def classify_additional(
        self,
        endpoints: list[APIEndpoint],
        result: ScanResult,
    ) -> list[APIEndpoint]:
        """Apply the loaded authoritative baseline to later discoveries."""
        retained = self._exclude_documentation_pages(endpoints, result)
        for endpoint in retained:
            self.classify_endpoint(endpoint, result)
        confirmed, candidates = self._partition_method_candidates(retained)
        confirmed_keys = {
            (normalize_url(endpoint.url), endpoint.method.upper())
            for endpoint in confirmed
        }
        result.candidate_endpoints = [
            endpoint
            for endpoint in result.candidate_endpoints
            if (
                normalize_url(endpoint.url),
                endpoint.method.upper(),
            ) not in confirmed_keys
        ]
        existing_candidate_keys = {
            (normalize_url(endpoint.url), endpoint.method.upper())
            for endpoint in result.candidate_endpoints
        }
        for candidate in candidates:
            key = (normalize_url(candidate.url), candidate.method.upper())
            if key not in existing_candidate_keys:
                result.candidate_endpoints.append(candidate)
                existing_candidate_keys.add(key)
        return confirmed

    def classify_endpoint(
        self,
        endpoint: APIEndpoint,
        result: ScanResult,
    ) -> None:
        """Classify one operation using the currently loaded baselines."""
        endpoint.operation_evidence = self._operation_evidence(endpoint)
        self.api_inventory.enrich(endpoint)

        if not result.authoritative_baseline_found:
            if self._has_live_evidence(endpoint):
                self._mark_shadow_unmanaged(
                    endpoint,
                    "Runtime evidence confirmed an active endpoint, but no "
                    "authoritative specification or inventory was available",
                )
            else:
                self._mark_unknown(
                    endpoint,
                    "No authoritative API specification or inventory was "
                    "available, and live operation was not confirmed",
                )
            return

        matched_spec_route = (
            self.spec_comparator.matching_route_pattern(endpoint)
        )
        if (
            matched_spec_route
            or self.api_inventory.is_documented(endpoint)
            or self.spec_comparator.is_documentation_endpoint(endpoint)
        ):
            if matched_spec_route and (
                "{" in matched_spec_route
                or bool(urlparse(endpoint.url).query)
            ):
                endpoint.route_pattern = matched_spec_route
            endpoint.is_shadow = False
            endpoint.documentation_status = DocumentationStatus.DOCUMENTED
            endpoint.documentation_reason = (
                "Matched an authoritative specification or inventory"
            )
        elif "allowed" in endpoint.operation_evidence:
            if self._has_live_evidence(endpoint):
                self._mark_shadow_unmanaged(
                    endpoint,
                    "The active method is missing from the authoritative "
                    "baseline and was confirmed by runtime evidence",
                )
            else:
                self._mark_unknown(
                    endpoint,
                    "Server Allow metadata advertised a method missing from "
                    "the baseline, but the operation was not confirmed live",
                )
        elif self.spec_comparator.is_documented_path_family(endpoint):
            if self._has_live_evidence(endpoint):
                self._mark_shadow_unmanaged(
                    endpoint,
                    "Runtime evidence confirmed an active operation related "
                    "to a documented API family but absent from the baseline",
                )
            else:
                self._mark_unknown(
                    endpoint,
                    "Related to a documented API family without an exact "
                    "match or confirmed live operation",
                )
        elif self.api_inventory.is_documented_path_family(endpoint):
            if self._has_live_evidence(endpoint):
                self._mark_shadow_unmanaged(
                    endpoint,
                    "Runtime evidence confirmed an active operation related "
                    "to an approved inventory family but absent from it",
                )
            else:
                self._mark_unknown(
                    endpoint,
                    "Related to an approved inventory family without an "
                    "exact match or confirmed live operation",
                )
        else:
            if self._has_live_evidence(endpoint):
                self._mark_shadow_unmanaged(
                    endpoint,
                    "Runtime evidence confirmed an active endpoint missing "
                    "from all authoritative specification and inventory sources",
                )
            else:
                self._mark_unknown(
                    endpoint,
                    "Missing from authoritative sources, but live operation "
                    "was not confirmed",
                )

    @staticmethod
    def _has_live_evidence(endpoint: APIEndpoint) -> bool:
        """Return whether evidence shows that the operation is active."""
        if endpoint.status_code is not None:
            return endpoint.status_code not in {404, 410}
        if {"confirmed", "responsive"}.intersection(
            endpoint.operation_evidence
        ):
            return True
        runtime_sources = {
            EndpointSource.DYNAMIC_TRAFFIC.value,
            EndpointSource.TRAFFIC_IMPORT.value,
            EndpointSource.SECURITY_VALIDATION.value,
        }
        return bool(runtime_sources.intersection(
            endpoint.observed_sources or [endpoint.source.value]
        ))

    @staticmethod
    def _mark_shadow_unmanaged(
        endpoint: APIEndpoint,
        reason: str,
    ) -> None:
        endpoint.is_shadow = True
        endpoint.documentation_status = DocumentationStatus.SHADOW
        endpoint.documentation_reason = reason

    @staticmethod
    def _mark_unknown(endpoint: APIEndpoint, reason: str) -> None:
        endpoint.is_shadow = False
        endpoint.documentation_status = DocumentationStatus.UNKNOWN
        endpoint.documentation_reason = reason

    def _exclude_documentation_pages(
        self,
        endpoints: list[APIEndpoint],
        result: ScanResult,
    ) -> list[APIEndpoint]:
        """Remove unresolved and documentation references from operations."""
        retained = []
        for endpoint in endpoints:
            if contains_template_expression(endpoint.url):
                warning = (
                    "Excluded unresolved endpoint template from operation "
                    f"inventory: {endpoint.url}"
                )
                if warning not in result.warnings:
                    result.warnings.append(warning)
                continue
            if self.spec_comparator.is_documentation_endpoint(endpoint):
                warning = (
                    "Excluded API documentation endpoint from operation "
                    f"inventory: {endpoint.url}"
                )
                if warning not in result.warnings:
                    result.warnings.append(warning)
                continue
            if self._is_external_documentation_reference(endpoint):
                warning = (
                    "Excluded external documentation reference from operation "
                    f"inventory: {endpoint.url}"
                )
                if warning not in result.warnings:
                    result.warnings.append(warning)
                continue
            retained.append(endpoint)
        return retained

    def _exclude_cross_origin(
        self,
        endpoints: list[APIEndpoint],
        result: ScanResult,
    ) -> list[APIEndpoint]:
        """Drop absolute URLs on a different host than the target.

        A third-party endpoint (for example a Google OAuth URL referenced by
        the frontend) is not a shadow/unmanaged API *of the scanned target*,
        so it is excluded from the target's operation inventory. Relative and
        same-host endpoints are always kept.
        """
        target_host = urlparse(self.config.target_url).hostname or ""
        retained: list[APIEndpoint] = []
        for endpoint in endpoints:
            host = urlparse(endpoint.url).hostname
            if not host or self._same_target_host(host, target_host):
                retained.append(endpoint)
                continue
            warning = (
                "Excluded cross-origin third-party reference from operation "
                f"inventory: {endpoint.url}"
            )
            if warning not in result.warnings:
                result.warnings.append(warning)
        return retained

    @staticmethod
    def _same_target_host(host: str, target_host: str) -> bool:
        if not target_host:
            return True
        host = host.lower()
        target_host = target_host.lower()
        return host == target_host or host.endswith("." + target_host)

    def _is_external_documentation_reference(
        self,
        endpoint: APIEndpoint,
    ) -> bool:
        """Identify third-party documentation links captured as API URLs."""
        if is_same_origin(self.config.target_url, endpoint.url):
            return False

        path_segments = {
            segment.lower()
            for segment in endpoint.url.split("?", 1)[0].split("/")
            if segment
        }
        return bool(path_segments.intersection({
            "docs",
            "documentation",
            "api-docs",
            "swagger",
            "swagger-ui",
            "redoc",
        }))

    @staticmethod
    def _partition_method_candidates(
        endpoints: list[APIEndpoint],
    ) -> tuple[list[APIEndpoint], list[APIEndpoint]]:
        """Separate Allow-only method hints from confirmed operations."""
        confirmed = []
        candidates = []
        confirming_evidence = {
            "confirmed",
            "documented",
            "manual",
            "observed",
            "referenced",
            "responsive",
            "tested",
        }
        for endpoint in endpoints:
            evidence = set(endpoint.operation_evidence)
            is_candidate = (
                endpoint.documentation_status == DocumentationStatus.UNKNOWN
                and endpoint.status_code is None
                and "allowed" in evidence
                and not confirming_evidence.intersection(evidence)
            )
            (candidates if is_candidate else confirmed).append(endpoint)
        return confirmed, candidates

    def _merge_endpoints(
        self,
        static: list[APIEndpoint],
        dynamic: list[APIEndpoint],
        documented: list[APIEndpoint],
    ) -> list[APIEndpoint]:
        """
        Merge endpoints from all sources, deduplicating by normalized URL + method.
        Dynamic findings take priority (they have response data).
        """
        merged: dict[tuple[str, str], APIEndpoint] = {}

        # Add documented first (lowest priority)
        for ep in documented:
            key = (normalize_url(ep.url), ep.method)
            ep.observed_sources = self._source_values(ep)
            merged[key] = ep

        # Add static (medium priority)
        for ep in static:
            key = (normalize_url(ep.url), ep.method)
            if key not in merged:
                ep.observed_sources = self._source_values(ep)
                merged[key] = ep
            else:
                merged[key].observed_sources = self._combined_sources(
                    merged[key], ep
                )
                merged[key].operation_evidence = list(dict.fromkeys(
                    merged[key].operation_evidence
                    + ep.operation_evidence
                ))
                self._merge_parameter_evidence(merged[key], ep)
                self._merge_response_evidence(merged[key], ep)

        # Add dynamic (highest priority - has real response data)
        for ep in dynamic:
            key = (normalize_url(ep.url), ep.method)
            if key in merged:
                self._merge_parameter_evidence(ep, merged[key])
                ep.observed_sources = self._combined_sources(
                    merged[key], ep
                )
                ep.operation_evidence = list(dict.fromkeys(
                    merged[key].operation_evidence
                    + ep.operation_evidence
                ))
            else:
                ep.observed_sources = self._source_values(ep)
            merged[key] = ep  # Override with dynamic data

        return list(merged.values())

    @staticmethod
    def _merge_parameter_evidence(
        retained: APIEndpoint,
        observed: APIEndpoint,
    ) -> None:
        for source, names in observed.parameter_evidence.items():
            retained.parameter_evidence[source] = list(dict.fromkeys(
                retained.parameter_evidence.get(source, []) + list(names)
            ))

    @staticmethod
    def _merge_response_evidence(
        retained: APIEndpoint,
        observed: APIEndpoint,
    ) -> None:
        """Preserve live response evidence when a static route was seen first."""
        if observed.status_code is None:
            return
        retained.status_code = observed.status_code
        retained.response_headers = observed.response_headers
        retained.response_body = observed.response_body
        retained.response_size = observed.response_size
        retained.content_type = observed.content_type or retained.content_type

    @staticmethod
    def _source_values(endpoint: APIEndpoint) -> list[str]:
        return endpoint.observed_sources or [endpoint.source.value]

    def _combined_sources(
        self,
        first: APIEndpoint,
        second: APIEndpoint,
    ) -> list[str]:
        return list(dict.fromkeys(
            self._source_values(first) + self._source_values(second)
        ))

    @staticmethod
    def _operation_evidence(endpoint: APIEndpoint) -> list[str]:
        evidence = list(endpoint.operation_evidence)
        source_evidence = {
            EndpointSource.STATIC_JS.value: "referenced",
            EndpointSource.DYNAMIC_TRAFFIC.value: "observed",
            EndpointSource.TRAFFIC_IMPORT.value: "observed",
            EndpointSource.OPENAPI_SPEC.value: "documented",
            EndpointSource.API_INVENTORY.value: "documented",
            EndpointSource.PATH_EXPLORATION.value: "probed",
            EndpointSource.SECURITY_VALIDATION.value: "tested",
            EndpointSource.MANUAL.value: "manual",
        }
        for source in (
            endpoint.observed_sources or [endpoint.source.value]
        ):
            if (
                source == EndpointSource.PATH_EXPLORATION.value
                and endpoint.status_code is None
            ):
                continue
            mapped = source_evidence.get(source)
            if mapped:
                evidence.append(mapped)
        if endpoint.status_code is not None:
            evidence.append("responsive")
        return list(dict.fromkeys(evidence))
