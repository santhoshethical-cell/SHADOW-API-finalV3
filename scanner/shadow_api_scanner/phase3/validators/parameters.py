"""Passive parameter inventory and controlled mass-assignment validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import yaml

from shadow_api_scanner.core.config import OWASP_CATEGORIES, ScanConfig
from shadow_api_scanner.core.models import (
    APIEndpoint,
    EndpointSource,
    RiskLevel,
    ValidationOutcome,
    ValidationResult,
    Vulnerability,
    VulnStatus,
)
from shadow_api_scanner.utils.helpers import normalize_url
from shadow_api_scanner.utils.http_client import AsyncHTTPClient, CapturedRequest


MAX_CASES = 25
MAX_BODY_BYTES = 65536
WRITE_METHODS = {"POST", "PUT", "PATCH"}
VERIFY_METHODS = {"GET"}
OWASP_PROPERTY_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa3-broken-object-property-level-authorization/"
)


class ParameterConfigError(ValueError):
    """Raised when a mutation case is unsafe or incomplete."""


@dataclass(frozen=True)
class VerificationStep:
    method: str
    url: str
    json_path: str
    original_value: Any
    mutated_value: Any


@dataclass(frozen=True)
class CleanupStep:
    method: str
    url: str
    json_body: dict[str, Any]


@dataclass(frozen=True)
class ParameterCase:
    name: str
    method: str
    url: str
    parameter: str
    mutation_body: dict[str, Any]
    verification: VerificationStep
    cleanup: CleanupStep
    synthetic_record: bool
    allow_state_change: bool


class ParameterManipulationValidator:
    """Inventory parameter sources and prove declared writable-state changes."""

    name = "parameter_manipulation"
    SENSITIVE_WRITABLE_FIELDS = {
        "role",
        "roles",
        "permission",
        "permissions",
        "isadmin",
        "issuperuser",
        "accountowner",
        "ownerid",
        "userid",
        "status",
        "balance",
        "credit",
        "discount",
        "chosen_discount",
    }

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client
        self.cases = self._load_cases(config.parameter_validation_config_file)

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        for endpoint in endpoints:
            try:
                results.append(self._passive_result(endpoint))
            except Exception as error:  # noqa: BLE001 - isolate one bad endpoint
                results.append(self._passive_crash_result(endpoint, error))
        vulnerabilities: list[Vulnerability] = []
        endpoint_map = {
            (endpoint.method.upper(), normalize_url(endpoint.url)): endpoint
            for endpoint in endpoints
        }
        for case in self.cases:
            endpoint = endpoint_map.get((case.method, normalize_url(case.url)))
            if endpoint is None:
                results.append(self._active_result(
                    case,
                    None,
                    ValidationOutcome.SKIPPED,
                    RiskLevel.INFO,
                    1.0,
                    "The declared mutation operation was not discovered",
                ))
                continue
            if not self.config.enable_active_testing or not case.allow_state_change:
                results.append(self._active_result(
                    case,
                    endpoint,
                    ValidationOutcome.SKIPPED,
                    RiskLevel.INFO,
                    1.0,
                    "Mutation requires global --active-testing and per-case "
                    "allow_state_change",
                ))
                continue
            result, vulnerability = await self._validate_case(case, endpoint)
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)
        return results, vulnerabilities

    def _passive_result(self, endpoint: APIEndpoint) -> ValidationResult:
        evidence = self._parameter_inventory(endpoint)
        has_spec = bool(evidence["openapi_operation"])
        observed = set(evidence["static_query"])
        observed.update(evidence["runtime_query"])
        observed.update(evidence["runtime_body"])
        documented = set(evidence["openapi_query"])
        documented.update(evidence["openapi_body"])
        undocumented = sorted(observed - documented) if has_spec else []
        writable = sorted(
            name for name in evidence["runtime_body"]
            if self._normalized_name(name) in self.SENSITIVE_WRITABLE_FIELDS
        )
        response_only = sorted(
            set(evidence["response_fields"]) - observed - documented
        )
        evidence.update({
            "undocumented_observed": undocumented,
            "response_only": response_only,
            "sensitive_writable_candidates": writable,
        })

        if undocumented or writable:
            outcome = ValidationOutcome.INCONCLUSIVE
            confidence = 0.78 if has_spec else 0.62
            reason = (
                "A parameter discrepancy or security-relevant writable field "
                "was observed; passive evidence alone does not prove impact"
            )
        elif has_spec:
            outcome = ValidationOutcome.PROTECTED
            confidence = 0.72
            reason = "Observed request parameters matched the OpenAPI operation"
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            confidence = 0.55
            reason = "No OpenAPI operation was available for parameter comparison"
        evidence["reason"] = reason
        return ValidationResult(
            endpoint_id=endpoint.id,
            endpoint=endpoint.url,
            method=endpoint.method.upper(),
            validator=f"{self.name}_passive",
            vulnerability_category="API3:2023 Parameter/Property Authorization",
            result=outcome,
            severity=RiskLevel.INFO,
            confidence=confidence,
            evidence=evidence,
            affected_parameter=(
                (undocumented or writable or response_only or [None])[0]
            ),
            remediation=(
                "Define request schemas, reject unknown properties, and "
                "allow-list writable fields server-side."
            ),
            references=[OWASP_PROPERTY_REFERENCE],
        )

    def _passive_crash_result(
        self,
        endpoint: APIEndpoint,
        error: Exception,
    ) -> ValidationResult:
        """Isolate an unexpected per-endpoint failure from the rest of the batch.

        A single malformed endpoint must not silently discard every other
        endpoint's already-computed passive result. The distinct
        `validator_crashed_for_item` evidence marker lets a human reading the
        report tell this apart from a validator that was never enabled.
        """
        return ValidationResult(
            endpoint_id=endpoint.id,
            endpoint=endpoint.url,
            method=endpoint.method.upper(),
            validator=f"{self.name}_passive",
            vulnerability_category="API3:2023 Parameter/Property Authorization",
            result=ValidationOutcome.ERROR,
            severity=RiskLevel.INFO,
            confidence=1.0,
            evidence={
                "reason": (
                    "An unhandled exception occurred while assessing this "
                    "endpoint; other endpoints were not affected"
                ),
                "validator_crashed_for_item": True,
                "exception_type": type(error).__name__,
                "exception_message": str(error)[:500],
            },
            remediation=(
                "Define request schemas, reject unknown properties, and "
                "allow-list writable fields server-side."
            ),
            references=[OWASP_PROPERTY_REFERENCE],
        )

    async def _validate_case(
        self,
        case: ParameterCase,
        endpoint: APIEndpoint,
    ) -> tuple[ValidationResult, Vulnerability | None]:
        baseline = await self._verify(case.verification)
        baseline_value = self._json_path(
            baseline.response_body,
            case.verification.json_path,
        )
        if (
            baseline.status_code not in range(200, 300)
            or baseline_value is _MISSING
            or baseline_value != case.verification.original_value
        ):
            return self._active_result(
                case,
                endpoint,
                ValidationOutcome.INCONCLUSIVE,
                RiskLevel.INFO,
                0.95,
                "The declared original synthetic state was not verified; no "
                "mutation was sent",
                baseline=baseline,
            ), None

        mutation = await self.client.request(
            case.method,
            case.url,
            json_body=case.mutation_body,
            retries=0,
        )
        verification = await self._verify(case.verification)
        changed_value = self._json_path(
            verification.response_body,
            case.verification.json_path,
        )

        cleanup = await self.client.request(
            case.cleanup.method,
            case.cleanup.url,
            json_body=case.cleanup.json_body,
            retries=0,
        )
        cleanup_verification = await self._verify(case.verification)
        reverted_value = self._json_path(
            cleanup_verification.response_body,
            case.verification.json_path,
        )
        state_changed = changed_value == case.verification.mutated_value
        cleanup_confirmed = (
            cleanup.status_code in range(200, 300)
            and reverted_value == case.verification.original_value
        )
        evidence = {
            "baseline_status": baseline.status_code,
            "mutation_status": mutation.status_code,
            "verification_status": verification.status_code,
            "cleanup_status": cleanup.status_code,
            "cleanup_verification_status": cleanup_verification.status_code,
            "state_changed": state_changed,
            "cleanup_confirmed": cleanup_confirmed,
            "original_fingerprint": self._fingerprint(baseline_value),
            "observed_fingerprint": self._fingerprint(changed_value),
            "reverted_fingerprint": self._fingerprint(reverted_value),
        }

        if state_changed:
            confidence = 0.98 if cleanup_confirmed else 0.94
            reason = (
                "The declared security-relevant property changed and cleanup "
                + ("was verified" if cleanup_confirmed else "could not be verified")
            )
            result = self._active_result(
                case,
                endpoint,
                ValidationOutcome.VULNERABLE,
                RiskLevel.HIGH,
                confidence,
                reason,
                baseline,
                evidence,
            )
            category = OWASP_CATEGORIES["API3"]
            vulnerability = Vulnerability(
                endpoint_id=endpoint.id,
                owasp_category="API3",
                owasp_name=category["name"],
                title=(
                    "Parameter Manipulation: Security-relevant property "
                    "changed"
                ),
                description=(
                    "A controlled mutation of a researcher-declared synthetic "
                    "record changed security-relevant application state. The "
                    "finding is based on a separate state-verification request, "
                    "not request acceptance alone."
                ),
                severity=RiskLevel.HIGH,
                status=VulnStatus.CONFIRMED,
                risk_score=8.5,
                confidence=confidence,
                poc_status_code=mutation.status_code,
                poc_evidence=reason,
                affected_methods=[case.method],
                affected_operation_status_code=mutation.status_code,
                remediation=(
                    "Allow-list writable properties and enforce property-level "
                    "authorization independently of client input."
                ),
                cwe_id="CWE-915",
                references=[OWASP_PROPERTY_REFERENCE],
            )
            return result, vulnerability

        if changed_value is _MISSING or verification.status_code == 0:
            outcome = ValidationOutcome.ERROR
            confidence = 1.0
            reason = "Post-mutation state verification failed"
        elif mutation.status_code in range(200, 300):
            outcome = ValidationOutcome.PROTECTED
            confidence = 0.9
            reason = "The request was accepted but verified state did not change"
        else:
            outcome = ValidationOutcome.PROTECTED
            confidence = 0.92
            reason = "The mutation was rejected and verified state did not change"
        return self._active_result(
            case,
            endpoint,
            outcome,
            RiskLevel.INFO,
            confidence,
            reason,
            baseline,
            evidence,
        ), None

    async def _verify(self, step: VerificationStep) -> CapturedRequest:
        return await self.client.request(step.method, step.url, retries=0)

    def _active_result(
        self,
        case: ParameterCase,
        endpoint: APIEndpoint | None,
        outcome: ValidationOutcome,
        severity: RiskLevel,
        confidence: float,
        reason: str,
        baseline: CapturedRequest | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> ValidationResult:
        details = {
            "reason": reason,
            "synthetic_record": case.synthetic_record,
            "state_verification_path": case.verification.json_path,
        }
        if baseline is not None:
            details["baseline_status"] = baseline.status_code
        details.update(evidence or {})
        return ValidationResult(
            endpoint_id=endpoint.id if endpoint else None,
            endpoint=case.url,
            method=case.method,
            validator=f"{self.name}_active",
            vulnerability_category="API3:2023 Parameter/Property Authorization",
            result=outcome,
            severity=severity,
            confidence=confidence,
            evidence=details,
            affected_parameter=case.parameter,
            remediation=(
                "Reject unknown properties and authorize each writable "
                "security-relevant field server-side."
            ),
            references=[OWASP_PROPERTY_REFERENCE],
        )

    @classmethod
    def _parameter_inventory(cls, endpoint: APIEndpoint) -> dict[str, list[str]]:
        sources = {
            key: sorted(set(str(name) for name in names))
            for key, names in endpoint.parameter_evidence.items()
        }
        static_query = []
        if (
            endpoint.source == EndpointSource.STATIC_JS
            or EndpointSource.STATIC_JS.value in endpoint.observed_sources
        ):
            static_query = sorted(parse_qs(
                urlparse(endpoint.url).query,
                keep_blank_values=True,
            ))
        response_fields = cls._response_fields(endpoint.response_body)
        return {
            "static_query": static_query,
            "runtime_query": sources.get("runtime_query", sorted(endpoint.query_params)),
            "runtime_body": sources.get(
                "runtime_body",
                sorted(endpoint.body_params) if isinstance(endpoint.body_params, dict) else [],
            ),
            "openapi_operation": sources.get("openapi_operation", []),
            "openapi_path": sources.get("openapi_path", []),
            "openapi_query": sources.get("openapi_query", []),
            "openapi_body": sources.get("openapi_body", []),
            "response_fields": response_fields,
        }

    @staticmethod
    def _response_fields(body: str | None) -> list[str]:
        if not body or len(body.encode("utf-8", errors="replace")) > MAX_BODY_BYTES:
            return []
        try:
            payload = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return []
        fields: set[str] = set()

        def walk(value: Any, depth: int = 0) -> None:
            if depth >= 16 or len(fields) >= 200:
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    fields.add(str(key)[:128])
                    walk(item, depth + 1)
            elif isinstance(value, list):
                for item in value[:50]:
                    walk(item, depth + 1)

        walk(payload)
        return sorted(fields)

    @staticmethod
    def _json_path(body: str, path: str) -> Any:
        try:
            value = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return _MISSING
        if not path.startswith("$."):
            return _MISSING
        for part in path[2:].split("."):
            if not isinstance(value, dict) or part not in value:
                return _MISSING
            value = value[part]
        return value

    @staticmethod
    def _fingerprint(value: Any) -> str | None:
        if value is _MISSING:
            return None
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _normalized_name(value: str) -> str:
        return "".join(
            character
            for character in value.lower()
            if character.isalnum() or character == "_"
        )

    def _load_cases(self, path_value: str | None) -> tuple[ParameterCase, ...]:
        if not path_value:
            return ()
        scope_error = self.config.security_scope_error()
        if scope_error:
            raise ParameterConfigError(scope_error)
        path = Path(path_value)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as error:
            raise ParameterConfigError(f"Unable to load parameter config: {error}") from error
        if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
            raise ParameterConfigError("Parameter config must contain a cases list")
        raw_cases = document["cases"]
        if not raw_cases or len(raw_cases) > MAX_CASES:
            raise ParameterConfigError("Parameter config must contain 1 to 25 cases")
        cases = []
        for index, raw in enumerate(raw_cases):
            if not isinstance(raw, dict):
                raise ParameterConfigError(f"Case {index + 1} must be an object")
            cases.append(self._parse_case(raw, index))
        return tuple(cases)

    def _parse_case(self, raw: dict[str, Any], index: int) -> ParameterCase:
        name = str(raw.get("name") or f"case-{index + 1}")[:128]
        method = str(raw.get("method", "")).upper()
        url = urljoin(self.config.target_url, str(raw.get("url", "")))
        parameter = str(raw.get("parameter", "")).strip()[:128]
        mutation_body = raw.get("mutation_body")
        verification = raw.get("verify")
        cleanup = raw.get("cleanup")
        if method not in WRITE_METHODS:
            raise ParameterConfigError(f"{name}: method must be POST, PUT, or PATCH")
        if not parameter or not isinstance(mutation_body, dict):
            raise ParameterConfigError(f"{name}: parameter and mutation_body are required")
        if not self._body_has_path(mutation_body, parameter):
            raise ParameterConfigError(
                f"{name}: mutation_body must contain the declared parameter"
            )
        if not raw.get("synthetic_record") or not raw.get("allow_state_change"):
            raise ParameterConfigError(
                f"{name}: synthetic_record and allow_state_change must be true"
            )
        if not isinstance(verification, dict) or not isinstance(cleanup, dict):
            raise ParameterConfigError(f"{name}: verify and cleanup objects are required")
        verify_method = str(verification.get("method", "GET")).upper()
        verify_url = urljoin(self.config.target_url, str(verification.get("url", "")))
        json_path = str(verification.get("json_path", ""))
        if verify_method not in VERIFY_METHODS or not json_path.startswith("$."):
            raise ParameterConfigError(
                f"{name}: verification must use GET and a $. path"
            )
        if "original_value" not in verification or "mutated_value" not in verification:
            raise ParameterConfigError(f"{name}: verification values are required")
        cleanup_method = str(cleanup.get("method", "")).upper()
        cleanup_url = urljoin(self.config.target_url, str(cleanup.get("url", "")))
        cleanup_body = cleanup.get("json_body")
        if cleanup_method not in WRITE_METHODS or not isinstance(cleanup_body, dict):
            raise ParameterConfigError(f"{name}: cleanup must be a JSON write operation")
        if not self._body_has_path(cleanup_body, parameter):
            raise ParameterConfigError(
                f"{name}: cleanup body must restore the declared parameter"
            )
        for candidate in (url, verify_url, cleanup_url):
            if not self.config.is_security_target_authorized(candidate):
                raise ParameterConfigError(f"{name}: URL is outside the exact host allow-list")
        for label, body in (("mutation", mutation_body), ("cleanup", cleanup_body)):
            if len(json.dumps(body).encode("utf-8")) > MAX_BODY_BYTES:
                raise ParameterConfigError(f"{name}: {label} body exceeds 65536 bytes")
        return ParameterCase(
            name=name,
            method=method,
            url=url,
            parameter=parameter,
            mutation_body=mutation_body,
            verification=VerificationStep(
                method=verify_method,
                url=verify_url,
                json_path=json_path,
                original_value=verification["original_value"],
                mutated_value=verification["mutated_value"],
            ),
            cleanup=CleanupStep(
                method=cleanup_method,
                url=cleanup_url,
                json_body=cleanup_body,
            ),
            synthetic_record=True,
            allow_state_change=True,
        )

    @staticmethod
    def _body_has_path(body: dict[str, Any], path: str) -> bool:
        value: Any = body
        for part in path.removeprefix("$.").split("."):
            if not part or not isinstance(value, dict) or part not in value:
                return False
            value = value[part]
        return True


_MISSING = object()
