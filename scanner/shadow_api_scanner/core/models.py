"""
Data models for Shadow API Scanner.

Defines the core dataclasses used across all four phases:
endpoints, vulnerabilities, findings, and scan results.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from shadow_api_scanner.utils.redaction import (
    redact_body,
    redact_data,
    redact_headers,
    redact_poc_request,
    redact_poc_response,
    redact_url,
)

SHADOW_UNMANAGED_API_LABEL = "Shadow / Unmanaged API"
SHADOW_UNMANAGED_API_DEFINITION = (
    "An active production API endpoint that is invisible to IT security, "
    "lacks central management, has no official documentation, and is not "
    "actively monitored."
)
SHADOW_UNMANAGED_SHARED_RISKS = (
    "Missing authentication, data leakage, and zero security visibility."
)
SHADOW_UNMANAGED_VERIFICATION_LIMIT = (
    "External discovery can confirm live operation and absence from supplied "
    "authoritative baselines; gateway ownership and internal monitoring status "
    "require organizational validation."
)


class EndpointSource(str, Enum):
    """Where an endpoint was discovered."""
    STATIC_JS = "static_js_analysis"
    DYNAMIC_TRAFFIC = "dynamic_traffic_capture"
    TRAFFIC_IMPORT = "traffic_import"
    OPENAPI_SPEC = "openapi_specification"
    API_INVENTORY = "api_inventory"
    PATH_EXPLORATION = "path_exploration"
    SECURITY_VALIDATION = "security_validation"
    MANUAL = "manual_entry"


class EndpointType(str, Enum):
    """Type of API endpoint."""
    REST = "REST"
    GRAPHQL = "GraphQL"
    WEBSOCKET = "WebSocket"
    GRPC = "gRPC"
    UNKNOWN = "Unknown"


class DocumentationStatus(str, Enum):
    """Whether an endpoint is documented, shadow/unmanaged, or unverified."""
    DOCUMENTED = "documented"
    SHADOW = "shadow"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk classification."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class VulnStatus(str, Enum):
    """Vulnerability status."""
    CONFIRMED = "Confirmed"
    POTENTIAL = "Potential"
    FALSE_POSITIVE = "False Positive"
    NOT_TESTED = "Not Tested"


class ValidationOutcome(str, Enum):
    """Standard result states returned by controlled validators."""
    VULNERABLE = "vulnerable"
    PROTECTED = "protected"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    ERROR = "error"


# --------------------------------------------------------------
# Discovered API Endpoint
# --------------------------------------------------------------

@dataclass
class APIEndpoint:
    """Represents a single discovered API endpoint."""

    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.REST
    source: EndpointSource = EndpointSource.STATIC_JS
    is_shadow: bool = False
    documentation_status: DocumentationStatus = DocumentationStatus.UNKNOWN
    documentation_reason: str = ""

    # Request details captured during discovery
    headers: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)
    body_params: dict = field(default_factory=dict)
    content_type: Optional[str] = None
    parameter_evidence: dict[str, list[str]] = field(default_factory=dict)

    # Response details (from dynamic capture)
    status_code: Optional[int] = None
    response_headers: dict = field(default_factory=dict)
    response_body: Optional[str] = None
    response_size: Optional[int] = None
    response_content_type: Optional[str] = None

    # Runtime evidence. Playwright does not expose a browser-independent
    # JavaScript initiator stack, so resource type and originating page are
    # retained as the portable source context.
    runtime_resource_type: Optional[str] = None
    runtime_initiator: Optional[str] = None
    originating_page: Optional[str] = None
    redirected_from: Optional[str] = None

    # Metadata
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    js_file_source: Optional[str] = None  # which JS file it was found in
    confidence: float = 1.0  # 0.0 -> 1.0, how confident we are this is a real endpoint
    owner: Optional[str] = None
    lifecycle: Optional[str] = None
    inventory_source: Optional[str] = None
    route_pattern: Optional[str] = None
    observed_urls: list[str] = field(default_factory=list)
    observed_sources: list[str] = field(default_factory=list)
    operation_evidence: list[str] = field(default_factory=list)
    parent_endpoint_id: Optional[str] = None

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    @property
    def normalized_url(self) -> str:
        """Return URL without query string for deduplication."""
        return self.url.split("?")[0].rstrip("/")

    @property
    def inventory_url(self) -> str:
        """Return the logical route when grouped, otherwise the concrete URL."""
        return self.route_pattern or self.url

    @property
    def observed_count(self) -> int:
        """Return the number of concrete observations represented."""
        return len(self.observed_urls) if self.observed_urls else 1

    def __hash__(self):
        return hash((self.normalized_url, self.method))

    def __eq__(self, other):
        if not isinstance(other, APIEndpoint):
            return False
        return (self.normalized_url == other.normalized_url and
                self.method == other.method)

    def to_dict(self) -> dict:
        response_digest = (
            hashlib.sha256(
                self.response_body.encode("utf-8", errors="replace")
            ).hexdigest()
            if self.response_body is not None else None
        )
        return {
            "id": self.id,
            "url": redact_url(self.url),
            "method": self.method,
            "type": self.endpoint_type.value,
            "source": self.source.value,
            "is_shadow": self.is_shadow,
            "is_unmanaged": self.is_shadow,
            "documentation_status": self.documentation_status.value,
            "documentation_reason": self.documentation_reason,
            "status_code": self.status_code,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at,
            "js_file_source": self.js_file_source,
            "owner": self.owner,
            "lifecycle": self.lifecycle,
            "inventory_source": self.inventory_source,
            "route_pattern": self.route_pattern,
            "representative_url": redact_url(self.url),
            "observed_count": self.observed_count,
            "observed_urls": [
                redact_url(url)
                for url in (self.observed_urls or [self.url])
            ],
            "observed_sources": (
                self.observed_sources or [self.source.value]
            ),
            "operation_evidence": self.operation_evidence,
            "parent_endpoint_id": self.parent_endpoint_id,
            "runtime_evidence": {
                "resource_type": self.runtime_resource_type,
                "initiator": self.runtime_initiator,
                "originating_page": (
                    redact_url(self.originating_page)
                    if self.originating_page else None
                ),
                "redirected_from": (
                    redact_url(self.redirected_from)
                    if self.redirected_from else None
                ),
                "request": {
                    "headers": redact_headers(self.headers),
                    "query_params": redact_data(self.query_params),
                    "body_params": redact_data(self.body_params),
                    "content_type": self.content_type,
                    "parameter_evidence": self.parameter_evidence,
                },
                "response": {
                    "status_code": self.status_code,
                    "headers": redact_headers(self.response_headers),
                    "content_type": self.response_content_type,
                    "size": self.response_size,
                    "body_sample": None,
                    "body_sha256": response_digest,
                },
            },
        }


# --------------------------------------------------------------
# Standardized Security Validation Result
# --------------------------------------------------------------

@dataclass
class ValidationResult:
    """Evidence-oriented result from one controlled security validator."""

    endpoint_id: Optional[str]
    endpoint: str
    method: str
    validator: str
    vulnerability_category: str
    result: ValidationOutcome
    severity: RiskLevel
    confidence: float
    evidence: dict = field(default_factory=dict)
    affected_parameter: Optional[str] = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    normalized_route: Optional[str] = None
    discovery_sources: list[str] = field(default_factory=list)
    documentation_status: Optional[str] = None
    shadow_status: Optional[bool] = None
    response_metadata: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "endpoint_id": self.endpoint_id,
            "endpoint": redact_url(self.endpoint),
            "method": self.method,
            "validator": self.validator,
            "vulnerability_category": self.vulnerability_category,
            "result": self.result.value,
            "severity": self.severity.value,
            "confidence": max(0.0, min(1.0, self.confidence)),
            "evidence": redact_data(self.evidence),
            "affected_parameter": self.affected_parameter,
            "remediation": self.remediation,
            "references": self.references,
            "normalized_route": (
                redact_url(self.normalized_route)
                if self.normalized_route else None
            ),
            "discovery_sources": self.discovery_sources,
            "documentation_status": self.documentation_status,
            "shadow_status": self.shadow_status,
            "response_metadata": redact_data(self.response_metadata),
        }


# --------------------------------------------------------------
# Vulnerability Finding
# --------------------------------------------------------------

@dataclass
class Vulnerability:
    """A single security vulnerability found on an endpoint."""

    endpoint_id: str
    owasp_category: str  # e.g., "API1"
    owasp_name: str
    title: str
    description: str
    severity: RiskLevel = RiskLevel.MEDIUM
    status: VulnStatus = VulnStatus.POTENTIAL
    risk_score: float = 5.0
    confidence: float = 0.5
    # Per-instance base score (0-10) when the specific finding's impact differs
    # from its OWASP category ceiling (e.g. a low-impact information disclosure).
    # When None, the scorer uses the OWASP category base score.
    base_score_override: Optional[float] = None

    # Proof of concept
    poc_request: Optional[str] = None
    poc_response: Optional[str] = None
    poc_status_code: Optional[int] = None
    poc_evidence: Optional[str] = None
    affected_methods: list[str] = field(default_factory=list)
    affected_operation_status_code: Optional[int] = None

    # Remediation
    remediation: str = ""
    cwe_id: Optional[str] = None
    references: list = field(default_factory=list)

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    found_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "endpoint_id": self.endpoint_id,
            "owasp_category": self.owasp_category,
            "owasp_name": self.owasp_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "risk_score": self.risk_score,
            "confidence": max(0.0, min(1.0, self.confidence)),
            "poc_request": self.report_poc_request,
            "poc_response": self.report_poc_response,
            "poc_status_code": self.poc_status_code,
            "poc_evidence": redact_body(self.poc_evidence),
            "affected_methods": self.affected_methods,
            "affected_operation_status_code": (
                self.affected_operation_status_code
            ),
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "references": self.references,
            "found_at": self.found_at,
        }

    @property
    def report_poc_request(self) -> Optional[str]:
        """Return proof-of-concept request text with credentials removed."""
        return redact_poc_request(self.poc_request)

    @property
    def report_poc_response(self) -> Optional[str]:
        """Return proof-of-concept response text with secrets removed."""
        return redact_poc_response(self.poc_response)


# --------------------------------------------------------------
# Scan Result (Aggregate)
# --------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregate result of a complete scan run."""

    target_url: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: Optional[str] = None

    # Phase 1 - static analysis results
    js_files_analyzed: int = 0
    static_endpoints: list[APIEndpoint] = field(default_factory=list)
    template_endpoints_resolved: int = 0
    unresolved_template_endpoints: int = 0

    # Phase 2 - dynamic capture results
    dynamic_endpoints: list[APIEndpoint] = field(default_factory=list)
    traffic_requests_captured: int = 0
    imported_traffic_requests: int = 0
    raw_endpoints_discovered: int = 0

    # Merged inventory & shadow detection
    all_endpoints: list[APIEndpoint] = field(default_factory=list)
    candidate_endpoints: list[APIEndpoint] = field(default_factory=list)
    shadow_endpoints: list[APIEndpoint] = field(default_factory=list)
    documented_endpoints: list[APIEndpoint] = field(default_factory=list)
    openapi_spec_found: bool = False
    authoritative_baseline_found: bool = False
    baseline_sources: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    baseline_history_file: Optional[str] = None
    accuracy_metrics: dict[str, Any] = field(default_factory=dict)

    # Phase 3 - security testing results
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    validation_results: list[ValidationResult] = field(default_factory=list)
    tests_executed: int = 0
    security_operations_discovered: int = 0

    # Phase 4 - risk summary
    overall_risk_score: float = 0.0
    overall_risk_level: RiskLevel = RiskLevel.INFO
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Errors / warnings during scan
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fatal_error: Optional[str] = None
    inventory_diff: dict = field(default_factory=dict)

    def finalize(self):
        """Compute summary statistics after scan completes."""
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.critical_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.CRITICAL
        )
        self.high_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.HIGH
        )
        self.medium_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.MEDIUM
        )
        self.low_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.LOW
        )
        self.info_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.INFO
        )

        if self.vulnerabilities:
            self.overall_risk_score = max(v.risk_score for v in self.vulnerabilities)
        else:
            self.overall_risk_score = 0.0

        if self.overall_risk_score >= 9.0:
            self.overall_risk_level = RiskLevel.CRITICAL
        elif self.overall_risk_score >= 7.0:
            self.overall_risk_level = RiskLevel.HIGH
        elif self.overall_risk_score >= 4.0:
            self.overall_risk_level = RiskLevel.MEDIUM
        elif self.overall_risk_score > 0:
            self.overall_risk_level = RiskLevel.LOW
        else:
            self.overall_risk_level = RiskLevel.INFO

    def zombie_endpoint_ids(self) -> set[str]:
        """Return endpoint IDs with confirmed zombie API findings."""
        return {
            v.endpoint_id
            for v in self.vulnerabilities
            if v.status == VulnStatus.CONFIRMED
            and v.title.startswith("Zombie API")
        }

    def api_classification_for(
        self,
        endpoint: APIEndpoint,
        zombie_endpoint_ids: Optional[set[str]] = None,
    ) -> str:
        """Return the report-facing API classification for an endpoint."""
        zombie_endpoint_ids = (
            self.zombie_endpoint_ids()
            if zombie_endpoint_ids is None
            else zombie_endpoint_ids
        )
        if endpoint.documentation_status == DocumentationStatus.DOCUMENTED:
            return "Documented API"
        if (
            endpoint.documentation_status == DocumentationStatus.SHADOW
            or self._has_runtime_evidence(endpoint)
            or endpoint.id in zombie_endpoint_ids
        ):
            return SHADOW_UNMANAGED_API_LABEL
        return "Unknown API"

    def api_classification_reason_for(
        self,
        endpoint: APIEndpoint,
        zombie_endpoint_ids: Optional[set[str]] = None,
    ) -> str:
        """Explain why an endpoint received its report-facing classification."""
        classification = self.api_classification_for(
            endpoint,
            zombie_endpoint_ids,
        )
        if classification == SHADOW_UNMANAGED_API_LABEL:
            return (
                "Runtime evidence shows an active endpoint that is absent "
                "from the authoritative specification or approved inventory. "
                f"{SHADOW_UNMANAGED_SHARED_RISKS} "
                f"{SHADOW_UNMANAGED_VERIFICATION_LIMIT}"
            )
        if classification == "Documented API":
            return (
                "Endpoint matched the authoritative API specification or "
                "approved inventory baseline."
            )
        return (
            "The endpoint is not documented, but live operation has not been "
            "confirmed; it is not yet a confirmed Shadow / Unmanaged API."
        )

    def api_classification_counts(self) -> dict[str, int]:
        """Count report-facing API classifications across all endpoints."""
        labels = (
            SHADOW_UNMANAGED_API_LABEL,
            "Documented API",
            "Unknown API",
        )
        counts = {label: 0 for label in labels}
        zombie_endpoint_ids = self.zombie_endpoint_ids()
        for endpoint in self.all_endpoints:
            counts[
                self.api_classification_for(endpoint, zombie_endpoint_ids)
            ] += 1
        return counts

    @staticmethod
    def _has_retired_or_deprecated_lifecycle(endpoint: APIEndpoint) -> bool:
        lifecycle = (endpoint.lifecycle or "").lower()
        return lifecycle in {
            "deprecated",
            "retired",
            "sunset",
            "removed",
            "legacy",
        }

    @staticmethod
    def _has_runtime_evidence(endpoint: APIEndpoint) -> bool:
        return (
            endpoint.status_code is not None
            or endpoint.source in {
                EndpointSource.DYNAMIC_TRAFFIC,
                EndpointSource.TRAFFIC_IMPORT,
            }
        )

    def _is_active_retired_or_deprecated(self, endpoint: APIEndpoint) -> bool:
        return (
            self._has_retired_or_deprecated_lifecycle(endpoint)
            and self._has_runtime_evidence(endpoint)
        )

    def _zombie_reason(
        self,
        endpoint: APIEndpoint,
        zombie_endpoint_ids: Optional[set[str]] = None,
    ) -> str:
        zombie_endpoint_ids = (
            self.zombie_endpoint_ids()
            if zombie_endpoint_ids is None
            else zombie_endpoint_ids
        )
        if endpoint.id in zombie_endpoint_ids:
            return (
                "Unused or hidden operation is still active and accepted a "
                "confirmed exploit request."
            )
        if self._has_retired_or_deprecated_lifecycle(endpoint):
            return (
                "Endpoint is marked retired or deprecated in the approved "
                "inventory, but runtime evidence shows it is still active."
            )
        return "Endpoint matched zombie API evidence."

    def _endpoint_to_dict(
        self,
        endpoint: APIEndpoint,
        zombie_endpoint_ids: set[str],
    ) -> dict:
        data = endpoint.to_dict()
        api_classification = self.api_classification_for(
            endpoint,
            zombie_endpoint_ids,
        )
        data["api_classification"] = api_classification
        is_shadow_unmanaged = (
            api_classification == SHADOW_UNMANAGED_API_LABEL
        )
        data["is_shadow"] = is_shadow_unmanaged
        data["is_unmanaged"] = is_shadow_unmanaged
        data["api_classification_reason"] = (
            self.api_classification_reason_for(endpoint, zombie_endpoint_ids)
        )
        return data

    @staticmethod
    def _candidate_to_dict(endpoint: APIEndpoint) -> dict:
        data = endpoint.to_dict()
        data["api_classification"] = "Unknown API"
        data["is_shadow"] = False
        data["is_unmanaged"] = False
        data["api_classification_reason"] = (
            "The server advertised this method, but a live operation was not "
            "confirmed. It remains a candidate rather than an active "
            "Shadow / Unmanaged API."
        )
        return data

    def unified_findings(self) -> dict[str, dict[str, list[dict]]]:
        """Return sanitized discovery and security finding groups."""
        runtime_sources = {
            EndpointSource.DYNAMIC_TRAFFIC.value,
            EndpointSource.TRAFFIC_IMPORT.value,
        }
        static_sources = {EndpointSource.STATIC_JS.value}
        discovery = {
            "documented_api": [],
            "shadow_api": [],
            "undocumented_parameter": [],
            "runtime_only_api": [],
            "static_only_api": [],
        }
        for endpoint in self.all_endpoints:
            sources = list(dict.fromkeys(
                endpoint.observed_sources or [endpoint.source.value]
            ))
            record = {
                "endpoint_id": endpoint.id,
                "endpoint": redact_url(endpoint.url),
                "method": endpoint.method.upper(),
                "normalized_route": redact_url(
                    endpoint.route_pattern or endpoint.normalized_url
                ),
                "discovery_sources": sources,
                "documentation_status": endpoint.documentation_status.value,
                "shadow_status": endpoint.is_shadow,
            }
            if endpoint.documentation_status == DocumentationStatus.DOCUMENTED:
                discovery["documented_api"].append(record)
            if self.api_classification_for(endpoint) == SHADOW_UNMANAGED_API_LABEL:
                discovery["shadow_api"].append(record)
            source_set = set(sources)
            if source_set.intersection(runtime_sources) and not source_set.intersection(
                static_sources
            ):
                discovery["runtime_only_api"].append(record)
            if source_set.intersection(static_sources) and not source_set.intersection(
                runtime_sources
            ):
                discovery["static_only_api"].append(record)

        for validation in self.validation_results:
            if validation.validator != "parameter_manipulation_passive":
                continue
            for parameter in validation.evidence.get(
                "undocumented_observed", []
            ):
                discovery["undocumented_parameter"].append({
                    "endpoint_id": validation.endpoint_id,
                    "endpoint": redact_url(validation.endpoint),
                    "method": validation.method,
                    "parameter": parameter,
                    "confidence": validation.confidence,
                    "result": validation.result.value,
                })

        security = {
            "bola_idor": [],
            "authentication_issue": [],
            "excessive_data_exposure": [],
            "parameter_manipulation": [],
            "rate_limit_weakness": [],
            "injection_indicator": [],
            "session_access_control": [],
        }
        validator_groups = {
            "controlled_bola_idor": "bola_idor",
            "controlled_broken_authentication": "authentication_issue",
            "excessive_data_exposure": "excessive_data_exposure",
            "parameter_manipulation_active": "parameter_manipulation",
            "bounded_rate_limit_assessment": "rate_limit_weakness",
            "safe_injection_indicators": "injection_indicator",
            "controlled_session_access_control": "session_access_control",
        }
        for validation in self.validation_results:
            if validation.result != ValidationOutcome.VULNERABLE:
                continue
            group = validator_groups.get(validation.validator)
            if group:
                security[group].append(validation.to_dict())
        return {"discovery": discovery, "security": security}

    def to_dict(self) -> dict:
        zombie_endpoint_ids = self.zombie_endpoint_ids()
        api_classification_counts = self.api_classification_counts()
        unmanaged_endpoints = [
            endpoint
            for endpoint in self.all_endpoints
            if self.api_classification_for(
                endpoint,
                zombie_endpoint_ids,
            ) == SHADOW_UNMANAGED_API_LABEL
        ]
        unknown_endpoints = [
            endpoint
            for endpoint in self.all_endpoints
            if self.api_classification_for(
                endpoint,
                zombie_endpoint_ids,
            ) == "Unknown API"
        ]
        return {
            "scan_id": self.scan_id,
            "target_url": redact_url(self.target_url),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "summary": {
                "js_files_analyzed": self.js_files_analyzed,
                "template_endpoints_resolved": self.template_endpoints_resolved,
                "unresolved_template_endpoints": (
                    self.unresolved_template_endpoints
                ),
                "total_endpoints_discovered": len(self.all_endpoints),
                "method_candidates": len(self.candidate_endpoints),
                "total_endpoint_observations": (
                    self.raw_endpoints_discovered
                    or sum(e.observed_count for e in self.all_endpoints)
                ),
                "shadow_endpoints": len(unmanaged_endpoints),
                "unmanaged_endpoints": len(unmanaged_endpoints),
                "shadow_unmanaged_endpoints": len(unmanaged_endpoints),
                "shadow_unmanaged_definition": (
                    SHADOW_UNMANAGED_API_DEFINITION
                ),
                "shadow_unmanaged_shared_risks": (
                    SHADOW_UNMANAGED_SHARED_RISKS
                ),
                "shadow_unmanaged_verification_limit": (
                    SHADOW_UNMANAGED_VERIFICATION_LIMIT
                ),
                "documented_endpoints": len(self.documented_endpoints),
                "unknown_documentation_status": sum(
                    1 for e in self.all_endpoints
                    if e.documentation_status == DocumentationStatus.UNKNOWN
                ),
                "unverified_endpoints": api_classification_counts[
                    "Unknown API"
                ],
                "traffic_requests_captured": self.traffic_requests_captured,
                "imported_traffic_requests": self.imported_traffic_requests,
                "openapi_spec_found": self.openapi_spec_found,
                "authoritative_baseline_found": (
                    self.authoritative_baseline_found
                ),
                "baseline_sources": self.baseline_sources,
                "evidence_sources": self.evidence_sources,
                "baseline_history_file": self.baseline_history_file,
                "accuracy_metrics": self.accuracy_metrics,
                "tests_executed": self.tests_executed,
                "security_operations_discovered": (
                    self.security_operations_discovered
                ),
                "vulnerabilities_found": len(self.vulnerabilities),
                "validation_results": len(self.validation_results),
                "overall_risk_score": self.overall_risk_score,
                "overall_risk_level": self.overall_risk_level.value,
                "severity_breakdown": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                    "info": self.info_count,
                },
            },
            "endpoints": {
                "all": [
                    self._endpoint_to_dict(e, zombie_endpoint_ids)
                    for e in self.all_endpoints
                ],
                "shadow": [
                    self._endpoint_to_dict(e, zombie_endpoint_ids)
                    for e in unmanaged_endpoints
                ],
                "unmanaged": [
                    self._endpoint_to_dict(e, zombie_endpoint_ids)
                    for e in unmanaged_endpoints
                ],
                "documented": [
                    self._endpoint_to_dict(e, zombie_endpoint_ids)
                    for e in self.documented_endpoints
                ],
                "unknown": [
                    self._endpoint_to_dict(e, zombie_endpoint_ids)
                    for e in unknown_endpoints
                ],
                "candidates": [
                    self._candidate_to_dict(e)
                    for e in self.candidate_endpoints
                ],
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "validation_results": [
                validation.to_dict()
                for validation in self.validation_results
            ],
            "findings": self.unified_findings(),
            "inventory_diff": self.inventory_diff,
            "errors": [redact_body(error) for error in self.errors],
            "warnings": [redact_body(warning) for warning in self.warnings],
            "fatal_error": redact_body(self.fatal_error),
        }
