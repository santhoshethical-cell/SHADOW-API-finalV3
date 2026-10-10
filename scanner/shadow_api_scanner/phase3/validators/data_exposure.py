"""Nested JSON excessive-data-exposure analysis with redacted evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
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


OWASP_PROPERTY_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa3-broken-object-property-level-authorization/"
)
MAX_ANALYSIS_BYTES = 1024 * 1024
MAX_EVIDENCE_MATCHES = 50


class DataExposureConfigError(ValueError):
    """Raised when a custom sensitive-field expression is invalid."""


@dataclass(frozen=True)
class SensitiveFieldMatch:
    path: str
    field: str
    category: str
    confidence: float
    sample: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "field": self.field,
            "category": self.category,
            "confidence": self.confidence,
            "redacted_sample": self.sample,
        }


class DataExposureValidator:
    """Identify unnecessary sensitive JSON fields without exposing values."""

    name = "excessive_data_exposure"

    FIELD_CATEGORIES = {
        "password": ("password_material", 0.98),
        "passwd": ("password_material", 0.98),
        "pwd": ("password_material", 0.98),
        "passwordhash": ("password_material", 0.99),
        "passworddigest": ("password_material", 0.99),
        "resettoken": ("authentication_secret", 0.98),
        "refreshtoken": ("authentication_secret", 0.98),
        "accesstoken": ("authentication_secret", 0.98),
        "authtoken": ("authentication_secret", 0.98),
        "sessionid": ("authentication_secret", 0.95),
        "sessiontoken": ("authentication_secret", 0.98),
        "jwt": ("authentication_secret", 0.98),
        "apikey": ("application_secret", 0.98),
        "clientsecret": ("application_secret", 0.98),
        "privatekey": ("application_secret", 0.99),
        "secretkey": ("application_secret", 0.98),
        "ssn": ("personal_identifier", 0.92),
        "nationalid": ("personal_identifier", 0.9),
        "passportnumber": ("personal_identifier", 0.92),
        "creditcard": ("financial_data", 0.95),
        "cardnumber": ("financial_data", 0.95),
        "cardownername": ("financial_data", 0.88),
        "cardtype": ("financial_data", 0.88),
        "cardexpiry": ("financial_data", 0.88),
        "cvv": ("financial_data", 0.97),
        "cvc": ("financial_data", 0.97),
        "bankaccount": ("financial_data", 0.92),
        "routingnumber": ("financial_data", 0.9),
        "iban": ("financial_data", 0.92),
        "salary": ("financial_data", 0.82),
        "permissions": ("authorization_metadata", 0.65),
        "permission": ("authorization_metadata", 0.62),
        "roles": ("authorization_metadata", 0.62),
        "role": ("authorization_metadata", 0.55),
        "scopes": ("authorization_metadata", 0.62),
        "internalid": ("internal_identifier", 0.58),
        "databaseurl": ("infrastructure_metadata", 0.9),
        "internalhost": ("infrastructure_metadata", 0.85),
        "internalip": ("infrastructure_metadata", 0.85),
        "hostname": ("infrastructure_metadata", 0.62),
        "email": ("private_profile", 0.48),
        "phonenumber": ("private_profile", 0.55),
        "phone": ("private_profile", 0.5),
        "dateofbirth": ("private_profile", 0.65),
        "dob": ("private_profile", 0.62),
        "homeaddress": ("private_profile", 0.62),
    }

    JWT_PATTERN = re.compile(
        r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    )
    AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        self.config = config
        self.client = client
        self.custom_patterns = self._compile_patterns(
            config.sensitive_field_patterns
        )

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []
        for endpoint in endpoints:
            try:
                result, vulnerability = await self._validate_endpoint(endpoint)
            except Exception as error:  # noqa: BLE001 - isolate one bad endpoint
                results.append(self._crash_result(endpoint, error))
                continue
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)
        return results, vulnerabilities

    def _crash_result(
        self,
        endpoint: APIEndpoint,
        error: Exception,
    ) -> ValidationResult:
        """Isolate an unexpected per-endpoint failure from the rest of the batch.

        A single malformed response must not silently discard every other
        endpoint's already-computed result for this validator. The distinct
        `validator_crashed_for_item` evidence marker lets the orchestrator
        (and a human reading the report) tell this apart from a validator
        that was never configured/enabled at all.
        """
        return self._result(
            endpoint,
            ValidationOutcome.ERROR,
            RiskLevel.INFO,
            1.0,
            "An unhandled exception occurred while assessing this endpoint; "
            "other endpoints were not affected",
            [],
            crashed=True,
            exception_type=type(error).__name__,
            exception_message=str(error)[:500],
        )

    async def _validate_endpoint(
        self,
        endpoint: APIEndpoint,
    ) -> tuple[ValidationResult, Vulnerability | None]:
        if not self.config.is_security_target_authorized(endpoint.url):
            return self._result(
                endpoint,
                ValidationOutcome.SKIPPED,
                RiskLevel.INFO,
                1.0,
                "Endpoint is outside the exact security allow-list",
                [],
            ), None

        status = endpoint.status_code
        body = endpoint.response_body or ""
        captured: CapturedRequest | None = None
        if not body:
            if endpoint.method.upper() != "GET":
                return self._result(
                    endpoint,
                    ValidationOutcome.SKIPPED,
                    RiskLevel.INFO,
                    1.0,
                    "No captured response was available and the validator "
                    "will not invoke a non-GET operation",
                    [],
                ), None
            captured = await self.client.request(
                "GET",
                endpoint.url,
                retries=0,
            )
            status = captured.status_code
            body = captured.response_body or ""

        if status == 0:
            return self._result(
                endpoint,
                ValidationOutcome.ERROR,
                RiskLevel.INFO,
                1.0,
                "Response retrieval failed at the transport layer",
                [],
            ), None
        if status not in range(200, 300):
            return self._result(
                endpoint,
                ValidationOutcome.INCONCLUSIVE,
                RiskLevel.INFO,
                0.9,
                f"Endpoint returned HTTP {status}; response exposure was not assessed",
                [],
            ), None
        if not body:
            return self._result(
                endpoint,
                ValidationOutcome.PROTECTED,
                RiskLevel.INFO,
                0.8,
                "Successful response did not contain a body",
                [],
            ), None

        payload = self._json_payload(body)
        if payload is None:
            return self._result(
                endpoint,
                ValidationOutcome.INCONCLUSIVE,
                RiskLevel.INFO,
                0.8,
                "Response was not valid JSON; field-level exposure was not assessed",
                [],
            ), None

        matches = self._find_matches(payload)
        if not matches:
            return self._result(
                endpoint,
                ValidationOutcome.PROTECTED,
                RiskLevel.INFO,
                0.8,
                "No configured or high-signal sensitive JSON fields were found",
                [],
            ), None

        confidence = self._aggregate_confidence(matches)
        categories = sorted({match.category for match in matches})
        if confidence >= 0.9:
            outcome = ValidationOutcome.VULNERABLE
            severity = RiskLevel.HIGH
            status_value = VulnStatus.CONFIRMED
            risk_score = 8.5
            reason = "High-signal sensitive response fields were exposed"
        elif confidence >= 0.7:
            outcome = ValidationOutcome.VULNERABLE
            severity = RiskLevel.MEDIUM
            status_value = VulnStatus.POTENTIAL
            risk_score = 6.5
            reason = (
                "Sensitive response fields require application-context review"
            )
        else:
            return self._result(
                endpoint,
                ValidationOutcome.INCONCLUSIVE,
                RiskLevel.INFO,
                confidence,
                "Low-context profile or authorization metadata was present, "
                "but exposure was not established",
                matches,
            ), None

        result = self._result(
            endpoint,
            outcome,
            severity,
            confidence,
            reason,
            matches,
        )
        category = OWASP_CATEGORIES["API3"]
        vulnerability = Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API3",
            owasp_name=category["name"],
            title=f"Excessive Data Exposure: {', '.join(categories[:3])}",
            description=(
                "The JSON response contains sensitive fields that may exceed "
                "the data needed by the client. Evidence contains field paths "
                "and redacted type/length fingerprints only."
            ),
            severity=severity,
            status=status_value,
            risk_score=risk_score,
            confidence=confidence,
            poc_request=(captured.format_request() if captured else None),
            poc_status_code=status,
            poc_evidence=(
                "Sensitive JSON paths: "
                + ", ".join(match.path for match in matches[:10])
            ),
            affected_methods=[endpoint.method.upper()],
            affected_operation_status_code=status,
            remediation=(
                "Define minimal response schemas, remove secret and internal "
                "fields server-side, and apply property-level authorization "
                "before serialization."
            ),
            cwe_id="CWE-213",
            references=[OWASP_PROPERTY_REFERENCE],
        )
        return result, vulnerability

    def _find_matches(self, payload: Any) -> list[SensitiveFieldMatch]:
        matches: list[SensitiveFieldMatch] = []
        for path, field_name, value in self._walk_json(payload):
            if len(matches) >= MAX_EVIDENCE_MATCHES:
                break
            if not self._meaningful_value(value):
                continue
            category, confidence = self._classify_field(
                path,
                field_name,
                value,
            )
            if category is None:
                continue
            matches.append(SensitiveFieldMatch(
                path=path,
                field=field_name,
                category=category,
                confidence=confidence,
                sample=self._redacted_sample(value),
            ))
        return matches

    def _classify_field(
        self,
        path: str,
        field_name: str,
        value: Any,
    ) -> tuple[str | None, float]:
        normalized = re.sub(r"[^a-z0-9]", "", field_name.lower())
        configured = self.FIELD_CATEGORIES.get(normalized)
        if configured:
            return configured
        for pattern in self.custom_patterns:
            if pattern.search(path[-512:]) or pattern.search(field_name):
                return "custom_sensitive_field", 0.78
        if isinstance(value, str):
            if self.JWT_PATTERN.search(value):
                return "authentication_secret", 0.98
            if self.AWS_KEY_PATTERN.search(value):
                return "application_secret", 0.98
            if "-----BEGIN PRIVATE KEY-----" in value:
                return "application_secret", 0.99
            if normalized in {"host", "address", "url"} and self._private_ip(
                value
            ):
                return "infrastructure_metadata", 0.82
        return None, 0.0

    @staticmethod
    def _aggregate_confidence(matches: list[SensitiveFieldMatch]) -> float:
        maximum = max(match.confidence for match in matches)
        private_count = sum(
            match.category == "private_profile" for match in matches
        )
        authorization_count = sum(
            match.category == "authorization_metadata" for match in matches
        )
        if private_count >= 2:
            maximum = max(maximum, 0.72)
        if authorization_count >= 2:
            maximum = max(maximum, 0.7)
        return round(min(maximum, 0.99), 2)

    def _result(
        self,
        endpoint: APIEndpoint,
        outcome: ValidationOutcome,
        severity: RiskLevel,
        confidence: float,
        reason: str,
        matches: list[SensitiveFieldMatch],
        crashed: bool = False,
        exception_type: str | None = None,
        exception_message: str | None = None,
    ) -> ValidationResult:
        evidence = {
            "reason": reason,
            "matches": [match.to_dict() for match in matches],
            "match_count": len(matches),
        }
        if crashed:
            evidence.update({
                "validator_crashed_for_item": True,
                "exception_type": exception_type,
                "exception_message": exception_message,
            })
        return ValidationResult(
            endpoint_id=endpoint.id,
            endpoint=endpoint.url,
            method=endpoint.method.upper(),
            validator=self.name,
            vulnerability_category=(
                "API3:2023 Excessive/Unnecessary Data Exposure"
            ),
            result=outcome,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            affected_parameter=(matches[0].path if matches else None),
            remediation=(
                "Return only fields required by the client and enforce "
                "property-level authorization before serialization."
            ),
            references=[OWASP_PROPERTY_REFERENCE],
        )

    @staticmethod
    def _walk_json(
        value: Any,
        path: str = "$",
        depth: int = 0,
    ):
        if depth >= 32:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key)[:256]
                item_path = f"{path}.{key_text}"
                yield item_path, key_text, item
                yield from DataExposureValidator._walk_json(
                    item,
                    item_path,
                    depth + 1,
                )
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from DataExposureValidator._walk_json(
                    item,
                    f"{path}[{index}]",
                    depth + 1,
                )

    @staticmethod
    def _json_payload(body: str) -> Any:
        encoded = body.encode("utf-8", errors="replace")[:MAX_ANALYSIS_BYTES]
        bounded = encoded.decode("utf-8", errors="replace")
        try:
            return json.loads(bounded)
        except (TypeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _meaningful_value(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            normalized = value.strip().lower()
            if not normalized or normalized in {
                "***",
                "masked",
                "redacted",
                "[redacted]",
                "null",
                "none",
            }:
                return False
        if isinstance(value, dict):
            return False
        if isinstance(value, list):
            return any(
                item is not None and not isinstance(item, (dict, list))
                for item in value
            )
        return True

    @staticmethod
    def _redacted_sample(value: Any) -> str:
        text = str(value)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        return (
            f"[REDACTED type={type(value).__name__} "
            f"length={len(text)} sha256={digest}]"
        )

    @staticmethod
    def _private_ip(value: str) -> bool:
        candidate = value.strip()
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
        compiled = []
        for pattern in patterns:
            if not pattern or len(pattern) > 128:
                raise DataExposureConfigError(
                    "Sensitive-field patterns must contain 1 to 128 characters"
                )
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as error:
                raise DataExposureConfigError(
                    f"Invalid sensitive-field regex {pattern!r}: {error}"
                ) from error
        return compiled
