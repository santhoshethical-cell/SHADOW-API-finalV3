"""
Phase 4: Risk Scorer

Assigns each finding a 0-10 risk score and a qualitative severity, using a model
grounded in published, citable standards rather than ad-hoc weights:

* Base score      — OWASP API Security Top 10 (2023) per-category severity,
                    expressed on the CVSS 0-10 scale (core/config.OWASP_CATEGORIES).
                    https://owasp.org/API-Security/editions/2023/en/
* Exploit maturity + report confidence — CVSS v3.1 Temporal metrics. The Temporal
                    score is Base x ExploitCodeMaturity x ReportConfidence
                    (Remediation Level = Unavailable = 1.0 at detection time).
                    https://www.first.org/cvss/v3.1/specification-document
* Environmental adjustments — CVSS v3.1 Environmental rationale: an undocumented
                    (shadow) endpoint raises exposure (OWASP API9 Improper
                    Inventory Management), and a destructive HTTP verb raises the
                    Integrity/Availability impact.
* Severity bands  — CVSS v3.1 Qualitative Severity Rating Scale
                    (None 0.0 / Low 0.1-3.9 / Medium 4.0-6.9 / High 7.0-8.9 /
                    Critical 9.0-10.0).

The overall scan score is the maximum finding score (worst-case exposure).
"""

from __future__ import annotations

import logging
from shadow_api_scanner.core.config import OWASP_CATEGORIES
from shadow_api_scanner.core.models import (
    APIEndpoint, ScanResult, Vulnerability, RiskLevel, VulnStatus,
    SHADOW_UNMANAGED_API_LABEL,
)

logger = logging.getLogger("shadow_api_scanner")

# CVSS v3.1 Temporal — Exploit Code Maturity (E). We map validated-exploit
# status onto the standard weights: a tool-reproduced exploit is functional/high
# maturity, an evidence-only detection is proof-of-concept, everything else is
# unproven. (first.org/cvss/v3.1/specification-document, Table 6)
EXPLOIT_CODE_MATURITY = {
    VulnStatus.CONFIRMED: 1.00,   # High: functional exploit reproduced by the tool
    VulnStatus.POTENTIAL: 0.94,   # Proof-of-Concept: evidence, not exercised
}
_UNPROVEN = 0.91                  # Unproven: not tested / inconclusive

# CVSS v3.1 Temporal — Report Confidence (RC), derived from validator confidence.
def _report_confidence(confidence: float) -> float:
    if confidence >= 0.9:
        return 1.00   # Confirmed
    if confidence >= 0.6:
        return 0.96   # Reasonable
    return 0.92       # Unknown

# HTTP verbs whose success implies destructive Integrity/Availability impact.
DESTRUCTIVE_METHODS = {"DELETE", "PUT"}

# CVSS Environmental-style uplifts (documented and capped).
SHADOW_UPLIFT = 0.5       # OWASP API9: undocumented/unmanaged endpoint
DESTRUCTIVE_UPLIFT = 0.5  # CVSS Integrity/Availability impact of destructive verbs


class RiskScorer:
    """Compute CVSS-aligned risk scores for findings and the overall scan."""

    def score(self, result: ScanResult) -> ScanResult:
        logger.info("=" * 60)
        logger.info("PHASE 4: Risk Scoring")
        logger.info("=" * 60)

        # Index every operation the scan knows about, confirmed or candidate,
        # so a finding raised against an advertised (candidate) method still
        # resolves back to its route for the shadow-endpoint uplift.
        endpoint_map: dict[str, APIEndpoint] = {
            ep.id: ep for ep in result.all_endpoints
        }
        for ep in result.candidate_endpoints:
            endpoint_map.setdefault(ep.id, ep)

        for vuln in result.vulnerabilities:
            vuln.risk_score = self._calculate_score(vuln, endpoint_map, result)
            vuln.severity = self._score_to_level(vuln.risk_score)

        result.vulnerabilities.sort(key=lambda v: v.risk_score, reverse=True)
        result.finalize()

        logger.info(f"\nRisk Scoring Results:")
        logger.info(f"  Overall Risk Score: {result.overall_risk_score:.1f}")
        logger.info(f"  Overall Risk Level: {result.overall_risk_level.value}")
        logger.info(f"  Critical: {result.critical_count}")
        logger.info(f"  High: {result.high_count}")
        logger.info(f"  Medium: {result.medium_count}")
        logger.info(f"  Low: {result.low_count}")
        return result

    def _calculate_score(
        self,
        vuln: Vulnerability,
        endpoint_map: dict[str, APIEndpoint],
        result: ScanResult,
    ) -> float:
        """CVSS-v3.1-aligned score for one finding (see module docstring)."""
        # Base = OWASP API 2023 category severity, unless the validator declared
        # a per-instance base (a specific low-impact finding of an otherwise
        # higher-severity category, e.g. version disclosure under API8).
        if vuln.base_score_override is not None:
            base = max(0.0, min(10.0, vuln.base_score_override))
        else:
            cat = OWASP_CATEGORIES.get(vuln.owasp_category, {})
            base = cat.get("base_score", 5.0)

        # Temporal: Base x ExploitCodeMaturity x ReportConfidence
        maturity = EXPLOIT_CODE_MATURITY.get(vuln.status, _UNPROVEN)
        confidence = max(0.0, min(1.0, vuln.confidence or 0.0))
        temporal = base * maturity * _report_confidence(confidence)

        # Environmental uplifts (documented, capped by the 10.0 ceiling below).
        env = 0.0
        if self._endpoint_is_shadow(vuln, endpoint_map, result):
            env += SHADOW_UPLIFT
        if any(
            method.upper() in DESTRUCTIVE_METHODS
            for method in (vuln.affected_methods or [])
        ):
            env += DESTRUCTIVE_UPLIFT

        return round(min(10.0, temporal + env), 1)

    @staticmethod
    def _endpoint_is_shadow(
        vuln: Vulnerability,
        endpoint_map: dict[str, APIEndpoint],
        result: ScanResult,
    ) -> bool:
        """Is the finding's operation on a shadow / unmanaged endpoint?

        Resolves the finding's endpoint (which may be an advertised candidate
        method) and, for a candidate, also considers its parent route, so the
        OWASP-API9 uplift is applied consistently.
        """
        endpoint = endpoint_map.get(vuln.endpoint_id or "")
        if endpoint is None:
            return False
        candidates = [endpoint]
        if endpoint.parent_endpoint_id:
            parent = endpoint_map.get(endpoint.parent_endpoint_id)
            if parent is not None:
                candidates.append(parent)
        for ep in candidates:
            if ep.is_shadow:
                return True
            try:
                if result.api_classification_for(ep) == SHADOW_UNMANAGED_API_LABEL:
                    return True
            except Exception:
                continue
        return False

    def _score_to_level(self, score: float) -> RiskLevel:
        """CVSS v3.1 Qualitative Severity Rating Scale."""
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.INFO
