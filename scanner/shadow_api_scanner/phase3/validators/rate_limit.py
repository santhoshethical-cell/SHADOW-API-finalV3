"""Conservative, hard-capped rate-limit signal assessment."""

from __future__ import annotations

import asyncio
from typing import Any

from shadow_api_scanner.core.config import OWASP_CATEGORIES, ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint,
    RiskLevel,
    ValidationOutcome,
    ValidationResult,
    Vulnerability,
    VulnStatus,
)
from shadow_api_scanner.utils.http_client import AsyncHTTPClient, CapturedRequest


SAFE_METHODS = {"GET", "HEAD"}
MIN_REQUESTS = 2
MAX_REQUESTS = 10
MAX_CONCURRENCY = 3
MIN_DELAY_SECONDS = 0.05
MAX_DELAY_SECONDS = 5.0
MAX_TIMEOUT_SECONDS = 30.0
OWASP_RESOURCE_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa4-unrestricted-resource-consumption/"
)


class RateLimitConfigError(ValueError):
    """Raised when rate assessment bounds are unsafe."""


class RateLimitValidator:
    """Look for throttling signals without attempting resource exhaustion."""

    name = "bounded_rate_limit_assessment"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client
        self._validate_bounds()

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []
        for endpoint in endpoints:
            if not self.config.is_security_target_authorized(endpoint.url):
                results.append(self._result(
                    endpoint,
                    ValidationOutcome.SKIPPED,
                    1.0,
                    "Endpoint is outside the exact security allow-list",
                    {},
                ))
                continue
            if endpoint.method.upper() not in SAFE_METHODS:
                results.append(self._result(
                    endpoint,
                    ValidationOutcome.SKIPPED,
                    1.0,
                    "Only GET and HEAD operations receive bounded rate probes",
                    {"requests_sent": 0},
                ))
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
        captures: list[CapturedRequest] = []
        stop_reason: str | None = None
        request_ceiling = self.config.rate_limit_probe_requests

        while len(captures) < request_ceiling and stop_reason is None:
            batch_size = min(
                self.config.rate_limit_probe_concurrency,
                request_ceiling - len(captures),
            )
            batch = await asyncio.gather(*[
                self._bounded_request(endpoint)
                for _ in range(batch_size)
            ])
            captures.extend(batch)
            for captured in batch:
                stop_reason = self._stop_reason(captured)
                if stop_reason:
                    break
            if stop_reason is None and len(captures) < request_ceiling:
                await asyncio.sleep(self.config.rate_limit_probe_delay)

        evidence = self._evidence(
            captures,
            stop_reason,
            request_ceiling,
            self.config.rate_limit_probe_concurrency,
        )
        statuses = evidence["status_codes"]
        if evidence["timed_out"]:
            outcome = ValidationOutcome.ERROR
            confidence = 1.0
            reason = "A probe reached the strict per-request timeout; assessment stopped"
        elif 429 in statuses:
            outcome = ValidationOutcome.PROTECTED
            confidence = 0.95
            reason = "HTTP 429 throttling was observed within the bounded sample"
        elif evidence["success_after_zero_remaining"]:
            outcome = ValidationOutcome.VULNERABLE
            confidence = 0.68
            reason = (
                "A success response followed a declared zero remaining quota; "
                "this is a potential policy inconsistency, not proof of abuse"
            )
        elif stop_reason:
            outcome = ValidationOutcome.INCONCLUSIVE
            confidence = 0.85
            reason = f"Assessment stopped conservatively after {stop_reason}"
        elif evidence["rate_limit_signal_headers"]:
            outcome = ValidationOutcome.PROTECTED
            confidence = 0.72
            reason = "Rate-limit policy or quota signal headers were observed"
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            confidence = 0.7
            reason = (
                "No throttling signal appeared in the small bounded sample; "
                "absence of HTTP 429 alone is not a vulnerability"
            )

        result = self._result(endpoint, outcome, confidence, reason, evidence)
        if outcome != ValidationOutcome.VULNERABLE:
            return result, None

        category = OWASP_CATEGORIES["API4"]
        vulnerability = Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API4",
            owasp_name=category["name"],
            title="Potential rate-limit policy inconsistency",
            description=(
                "The endpoint returned a success response after advertising "
                "zero remaining requests. This bounded signal requires manual "
                "confirmation against the intended policy."
            ),
            severity=RiskLevel.MEDIUM,
            status=VulnStatus.POTENTIAL,
            risk_score=5.0,
            confidence=confidence,
            poc_status_code=statuses[-1] if statuses else None,
            poc_evidence=reason,
            affected_methods=[endpoint.method.upper()],
            affected_operation_status_code=statuses[-1] if statuses else None,
            remediation=(
                "Enforce declared quotas consistently and return HTTP 429 with "
                "a bounded Retry-After value when the policy is exceeded."
            ),
            cwe_id="CWE-770",
            references=[OWASP_RESOURCE_REFERENCE],
        )
        return result, vulnerability

    async def _bounded_request(self, endpoint: APIEndpoint) -> CapturedRequest:
        try:
            return await asyncio.wait_for(
                self.client.request(
                    endpoint.method,
                    endpoint.url,
                    retries=0,
                ),
                timeout=self.config.rate_limit_probe_timeout,
            )
        except TimeoutError:
            return CapturedRequest(
                method=endpoint.method.upper(),
                url=endpoint.url,
                headers={},
                body=None,
                status_code=0,
                response_headers={},
                response_body="",
                response_time_ms=self.config.rate_limit_probe_timeout * 1000,
            )

    @staticmethod
    def _stop_reason(captured: CapturedRequest) -> str | None:
        headers = {str(key).lower(): value for key, value in captured.response_headers.items()}
        if captured.status_code == 0:
            return "transport error or timeout"
        if captured.status_code == 429:
            return "HTTP 429"
        if "retry-after" in headers:
            return "Retry-After"
        if captured.status_code in {502, 503, 504}:
            return f"HTTP {captured.status_code} service-protection signal"
        return None

    @staticmethod
    def _evidence(
        captures: list[CapturedRequest],
        stop_reason: str | None,
        request_ceiling: int,
        concurrency_cap: int,
    ) -> dict[str, Any]:
        statuses = [capture.status_code for capture in captures]
        signal_headers: set[str] = set()
        zero_remaining_index: int | None = None
        success_after_zero = False
        for index, capture in enumerate(captures):
            headers = {
                str(key).lower(): str(value)
                for key, value in capture.response_headers.items()
            }
            for name in (
                "retry-after",
                "ratelimit-limit",
                "ratelimit-remaining",
                "ratelimit-reset",
                "ratelimit-policy",
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
            ):
                if name in headers:
                    signal_headers.add(name)
            remaining = headers.get(
                "ratelimit-remaining",
                headers.get("x-ratelimit-remaining"),
            )
            if remaining is not None:
                try:
                    if float(remaining) <= 0 and zero_remaining_index is None:
                        zero_remaining_index = index
                except ValueError:
                    pass
            if (
                zero_remaining_index is not None
                and index > zero_remaining_index
                and capture.status_code in range(200, 300)
            ):
                success_after_zero = True
        return {
            "request_ceiling": request_ceiling,
            "requests_sent": len(captures),
            "concurrency_cap": concurrency_cap,
            "status_codes": statuses,
            "stop_reason": stop_reason,
            "retry_after_observed": "retry-after" in signal_headers,
            "rate_limit_signal_headers": sorted(signal_headers),
            "success_after_zero_remaining": success_after_zero,
            "timed_out": any(status == 0 for status in statuses),
        }

    def _result(
        self,
        endpoint: APIEndpoint,
        outcome: ValidationOutcome,
        confidence: float,
        reason: str,
        evidence: dict[str, Any],
    ) -> ValidationResult:
        details = {"reason": reason, **evidence}
        return ValidationResult(
            endpoint_id=endpoint.id,
            endpoint=endpoint.url,
            method=endpoint.method.upper(),
            validator=self.name,
            vulnerability_category="API4:2023 Resource/Rate Control",
            result=outcome,
            severity=(
                RiskLevel.MEDIUM
                if outcome == ValidationOutcome.VULNERABLE
                else RiskLevel.INFO
            ),
            confidence=confidence,
            evidence=details,
            remediation=(
                "Apply per-identity and per-resource quotas with clear 429 and "
                "Retry-After behavior."
            ),
            references=[OWASP_RESOURCE_REFERENCE],
        )

    def _validate_bounds(self) -> None:
        scope_error = self.config.security_scope_error()
        if scope_error:
            raise RateLimitConfigError(scope_error)
        if not MIN_REQUESTS <= self.config.rate_limit_probe_requests <= MAX_REQUESTS:
            raise RateLimitConfigError("Rate-limit request ceiling must be between 2 and 10")
        if not 1 <= self.config.rate_limit_probe_concurrency <= MAX_CONCURRENCY:
            raise RateLimitConfigError("Rate-limit concurrency must be between 1 and 3")
        if not MIN_DELAY_SECONDS <= self.config.rate_limit_probe_delay <= MAX_DELAY_SECONDS:
            raise RateLimitConfigError("Rate-limit delay must be between 0.05 and 5 seconds")
        if not 0 < self.config.rate_limit_probe_timeout <= MAX_TIMEOUT_SECONDS:
            raise RateLimitConfigError("Rate-limit timeout must be between 0 and 30 seconds")
