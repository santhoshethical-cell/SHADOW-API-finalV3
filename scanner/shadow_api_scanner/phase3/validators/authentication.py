"""Controlled broken-authentication validation for declared protected APIs."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml

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
from shadow_api_scanner.utils.http_client import AsyncHTTPClient, CapturedRequest
from shadow_api_scanner.utils.redaction import SENSITIVE_HEADERS, redact_url


SAFE_METHODS = {"GET", "HEAD"}
SUPPORTED_METHODS = SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE"}
MAX_CASES = 25
MAX_COMPARISON_BYTES = 65536
OWASP_AUTH_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa2-broken-authentication/"
)


class AuthConfigError(ValueError):
    """Raised when authentication validation is unsafe or incomplete."""


@dataclass(frozen=True)
class AuthCase:
    name: str
    method: str
    url: str
    evidence_paths: list[str]
    json_body: Any = None
    allow_state_change: bool = False


@dataclass(frozen=True)
class AuthSettings:
    header_name: str
    valid_value: str
    invalid_value: str | None
    expired_value: str | None
    cases: tuple[AuthCase, ...]


class BrokenAuthenticationValidator:
    """Compare a valid baseline with bounded non-authenticated variants."""

    name = "controlled_broken_authentication"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        if not config.auth_validation_config_file:
            raise AuthConfigError(
                "An authentication validation configuration file is required"
            )
        scope_error = config.security_scope_error()
        if scope_error:
            raise AuthConfigError(scope_error)
        self.config = config
        self.client = client
        self.settings = self._load_settings(
            Path(config.auth_validation_config_file),
            config,
        )

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        endpoint_map = {
            (endpoint.method.upper(), normalize_url(endpoint.url)): endpoint
            for endpoint in endpoints
        }
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []
        for case in self.settings.cases:
            endpoint = endpoint_map.get((case.method, normalize_url(case.url)))
            if endpoint is None:
                results.append(self._result(
                    case,
                    None,
                    ValidationOutcome.SKIPPED,
                    RiskLevel.INFO,
                    1.0,
                    "The declared protected operation was not discovered",
                ))
                continue
            if (
                case.method not in SAFE_METHODS
                and not (
                    self.config.enable_active_testing
                    and case.allow_state_change
                )
            ):
                results.append(self._result(
                    case,
                    endpoint,
                    ValidationOutcome.SKIPPED,
                    RiskLevel.INFO,
                    1.0,
                    "State-changing authentication validation requires both "
                    "global --active-testing and per-case allow_state_change",
                ))
                continue
            result, vulnerability = await self._validate_case(case, endpoint)
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)
        return results, vulnerabilities

    async def _validate_case(
        self,
        case: AuthCase,
        endpoint: APIEndpoint,
    ) -> tuple[ValidationResult, Vulnerability | None]:
        omitted = {
            self.settings.header_name,
            self.config.auth_header,
            "Authorization",
            "Cookie",
            *SENSITIVE_HEADERS,
        }
        options = {"omit_headers": omitted, "retries": 0}
        if case.json_body is not None:
            options["json_body"] = case.json_body

        baseline = await self.client.request(
            case.method,
            case.url,
            headers={
                self.settings.header_name: self.settings.valid_value,
            },
            **options,
        )
        if baseline.status_code == 0:
            return self._result(
                case,
                endpoint,
                ValidationOutcome.ERROR,
                RiskLevel.INFO,
                1.0,
                "The authenticated baseline failed at the transport layer",
                baseline=baseline,
            ), None
        if baseline.status_code not in range(200, 300):
            return self._result(
                case,
                endpoint,
                ValidationOutcome.INCONCLUSIVE,
                RiskLevel.INFO,
                0.95,
                "The valid controlled credential did not establish a "
                "successful protected baseline",
                baseline=baseline,
            ), None

        variants: list[tuple[str, str | None]] = [
            ("anonymous", None),
            ("malformed", self._malformed_value(self.settings.header_name)),
        ]
        if self.settings.invalid_value is not None:
            variants.append(("controlled_invalid", self.settings.invalid_value))
        if self.settings.expired_value is not None:
            variants.append(("controlled_expired", self.settings.expired_value))

        assessments = []
        first_vulnerable: CapturedRequest | None = None
        for label, credential in variants:
            headers = (
                {self.settings.header_name: credential}
                if credential is not None else {}
            )
            captured = await self.client.request(
                case.method,
                case.url,
                headers=headers,
                **options,
            )
            assessment = self._assess_variant(
                case,
                baseline,
                captured,
                label,
            )
            assessments.append(assessment)
            if (
                assessment["result"] == ValidationOutcome.VULNERABLE.value
                and first_vulnerable is None
            ):
                first_vulnerable = captured

        outcomes = {item["result"] for item in assessments}
        if ValidationOutcome.VULNERABLE.value in outcomes:
            outcome = ValidationOutcome.VULNERABLE
            severity = RiskLevel.CRITICAL
            confidence = 0.95
            reason = (
                "At least one non-authenticated credential variant received "
                "the declared protected response semantics"
            )
        elif outcomes == {ValidationOutcome.PROTECTED.value}:
            outcome = ValidationOutcome.PROTECTED
            severity = RiskLevel.INFO
            confidence = 0.95
            reason = "All tested credential variants were denied or redirected"
        elif outcomes == {ValidationOutcome.ERROR.value}:
            outcome = ValidationOutcome.ERROR
            severity = RiskLevel.INFO
            confidence = 1.0
            reason = "All authentication variants failed at the transport layer"
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            severity = RiskLevel.INFO
            confidence = 0.7
            reason = (
                "Authentication responses were mixed or lacked sufficient "
                "protected-response semantics"
            )

        result = self._result(
            case,
            endpoint,
            outcome,
            severity,
            confidence,
            reason,
            baseline,
            assessments,
        )
        if outcome != ValidationOutcome.VULNERABLE or first_vulnerable is None:
            return result, None

        category = OWASP_CATEGORIES["API2"]
        vulnerability = Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API2",
            owasp_name=category["name"],
            title=(
                "Authentication Failure: Protected response accessible "
                "without valid authentication"
            ),
            description=(
                "A researcher-declared protected endpoint returned matching "
                "private response semantics for an anonymous, malformed, "
                "invalid, or expired controlled credential. This is an "
                "authentication failure, not an object-authorization finding."
            ),
            severity=RiskLevel.CRITICAL,
            status=VulnStatus.CONFIRMED,
            risk_score=category["base_score"],
            confidence=confidence,
            poc_request=first_vulnerable.format_request(),
            poc_response=first_vulnerable.format_response(),
            poc_status_code=first_vulnerable.status_code,
            poc_evidence=reason,
            affected_methods=[case.method],
            affected_operation_status_code=first_vulnerable.status_code,
            remediation=(
                "Require valid authentication before returning protected data. "
                "Reject missing, malformed, invalid, and expired credentials "
                "consistently before authorization checks."
            ),
            cwe_id="CWE-306",
            references=[OWASP_AUTH_REFERENCE],
        )
        return result, vulnerability

    def _assess_variant(
        self,
        case: AuthCase,
        baseline: CapturedRequest,
        captured: CapturedRequest,
        label: str,
    ) -> dict[str, Any]:
        semantics = self._response_semantics(
            case.evidence_paths,
            baseline.response_body,
            captured.response_body,
        )
        if captured.status_code == 0:
            outcome = ValidationOutcome.ERROR
            reason = "transport error"
        elif captured.status_code in {401, 403, 404}:
            outcome = ValidationOutcome.PROTECTED
            reason = f"HTTP {captured.status_code} denied access"
        elif self._redirected_to_login(case.url, captured.url):
            outcome = ValidationOutcome.PROTECTED
            reason = "redirected to an authentication page"
        elif (
            captured.status_code in range(200, 300)
            and semantics["protected_evidence"]
        ):
            outcome = ValidationOutcome.VULNERABLE
            reason = "protected response semantics were returned"
            if semantics.get("researcher_review_recommended"):
                reason += (
                    "; note: the rest of the response differs substantially "
                    "from the authenticated baseline - confirm the declared "
                    "evidence_paths represent data that is genuinely "
                    "protected, not shared/public content"
                )
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            reason = "response did not prove protected-data access"
        return {
            "variant": label,
            "result": outcome.value,
            "reason": reason,
            "response": self._response_metadata(captured),
            "semantics": semantics,
        }

    def _result(
        self,
        case: AuthCase,
        endpoint: APIEndpoint | None,
        outcome: ValidationOutcome,
        severity: RiskLevel,
        confidence: float,
        reason: str,
        baseline: CapturedRequest | None = None,
        assessments: list[dict[str, Any]] | None = None,
    ) -> ValidationResult:
        evidence: dict[str, Any] = {
            "case": case.name,
            "authentication_header": self.settings.header_name,
            "reason": reason,
            "evidence_paths": case.evidence_paths,
        }
        if baseline is not None:
            evidence["authenticated_baseline"] = self._response_metadata(
                baseline
            )
        if assessments is not None:
            evidence["credential_variants"] = assessments
        return ValidationResult(
            endpoint_id=endpoint.id if endpoint else None,
            endpoint=case.url,
            method=case.method,
            validator=self.name,
            vulnerability_category="API2:2023 Broken Authentication",
            result=outcome,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            remediation=(
                "Validate credentials consistently before returning protected "
                "API response data."
            ),
            references=[OWASP_AUTH_REFERENCE],
        )

    @staticmethod
    def _response_semantics(
        evidence_paths: list[str],
        baseline_body: str,
        candidate_body: str,
    ) -> dict[str, Any]:
        baseline_payload = BrokenAuthenticationValidator._json_payload(
            baseline_body
        )
        candidate_payload = BrokenAuthenticationValidator._json_payload(
            candidate_body
        )
        matching = []
        for path in evidence_paths:
            baseline_value = BrokenAuthenticationValidator._json_path(
                baseline_payload,
                path,
            )
            candidate_value = BrokenAuthenticationValidator._json_path(
                candidate_payload,
                path,
            )
            if baseline_value is not None and baseline_value == candidate_value:
                matching.append(path)
        comparable_a = BrokenAuthenticationValidator._canonical(
            baseline_payload,
            baseline_body,
        )
        comparable_b = BrokenAuthenticationValidator._canonical(
            candidate_payload,
            candidate_body,
        )
        similarity = SequenceMatcher(
            None,
            comparable_a[:MAX_COMPARISON_BYTES],
            comparable_b[:MAX_COMPARISON_BYTES],
        ).ratio() if (comparable_a or comparable_b) else 0.0
        # Exact per-path match on every declared evidence path is sufficient
        # on its own, mirroring AccessControlValidator._semantics's "complete"
        # fingerprint-equality check (evidence_paths is required non-empty by
        # _load_case, so this always requires at least one confirmed path).
        # This must not be vetoed by an unrelated drop in whole-body
        # similarity caused by fields never declared as protected evidence
        # (timestamps, nonces, CSRF tokens, request IDs, etc.) - see the
        # audited broken-auth false-negative gap. response_similarity is
        # retained in the evidence for context, but no longer gates the
        # outcome.
        protected_evidence = (
            len(matching) == len(evidence_paths)
            and bool(evidence_paths)
        )
        # Diagnostic only: does not affect outcome or confidence. An exact
        # evidence-path match combined with a substantially different overall
        # response can mean the declared path legitimately proves the
        # protected data leaked despite unrelated per-request noise (the case
        # this fix targets) - or it can mean the declared path points at data
        # that was never actually protected (e.g. shared/public content),
        # which the tool cannot distinguish automatically. Flag it so a
        # report reader knows to sanity-check the evidence_paths choice.
        review_recommended = protected_evidence and similarity < 0.5
        return {
            "response_similarity": round(similarity, 4),
            "matching_evidence_paths": matching,
            "protected_evidence": protected_evidence,
            "researcher_review_recommended": review_recommended,
        }

    @staticmethod
    def _json_payload(body: str) -> Any:
        try:
            return json.loads(body or "")
        except (TypeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _json_path(payload: Any, path: str) -> Any:
        current = payload
        for segment in path.split("."):
            if isinstance(current, dict) and segment in current:
                current = current[segment]
            elif isinstance(current, list) and segment.isdigit():
                index = int(segment)
                if index >= len(current):
                    return None
                current = current[index]
            else:
                return None
        return current

    @staticmethod
    def _canonical(payload: Any, body: str) -> str:
        if payload is None:
            return " ".join((body or "").split())
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _response_metadata(captured: CapturedRequest) -> dict[str, Any]:
        body = captured.response_body or ""
        return {
            "status_code": captured.status_code,
            "final_url": redact_url(captured.url),
            "content_type": captured.response_headers.get(
                "content-type", ""
            ),
            "body_size": len(body.encode("utf-8", errors="replace")),
            "body_sha256": hashlib.sha256(
                body.encode("utf-8", errors="replace")
            ).hexdigest(),
        }

    @staticmethod
    def _redirected_to_login(original_url: str, final_url: str) -> bool:
        if normalize_url(original_url) == normalize_url(final_url):
            return False
        path = urlparse(final_url).path.lower()
        return any(
            marker in path
            for marker in ("/login", "/signin", "/sign-in", "/auth")
        )

    @staticmethod
    def _malformed_value(header_name: str) -> str:
        if header_name.lower() == "authorization":
            return "Malformed"
        if header_name.lower() == "cookie":
            return "invalid=1"
        return "invalid"

    @classmethod
    def _load_settings(
        cls,
        path: Path,
        config: ScanConfig,
    ) -> AuthSettings:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise AuthConfigError(
                f"Unable to read authentication configuration: {error}"
            ) from error
        if not isinstance(payload, dict):
            raise AuthConfigError(
                "Authentication validation configuration must be an object"
            )
        if "valid_value" in payload or "token" in payload:
            raise AuthConfigError(
                "Raw credentials are not allowed; use environment variables"
            )
        header_name = str(payload.get("header_name", "Authorization")).strip()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header_name):
            raise AuthConfigError("Invalid authentication header name")
        valid_value = cls._environment_value(payload, "valid_env", required=True)
        invalid_value = cls._environment_value(
            payload,
            "invalid_env",
            required=False,
        )
        expired_value = cls._environment_value(
            payload,
            "expired_env",
            required=False,
        )
        supplied_values = [
            value
            for value in (valid_value, invalid_value, expired_value)
            if value is not None
        ]
        if len(supplied_values) != len(set(supplied_values)):
            raise AuthConfigError(
                "Valid, invalid, and expired controlled credentials must differ"
            )

        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise AuthConfigError("At least one protected API case is required")
        if len(raw_cases) > MAX_CASES:
            raise AuthConfigError(
                f"Authentication configuration exceeds the {MAX_CASES}-case cap"
            )
        cases = tuple(
            cls._load_case(case, config, index)
            for index, case in enumerate(raw_cases, start=1)
        )
        return AuthSettings(
            header_name,
            valid_value or "",
            invalid_value,
            expired_value,
            cases,
        )

    @staticmethod
    def _environment_value(
        payload: dict,
        key: str,
        required: bool,
    ) -> str | None:
        raw_name = payload.get(key)
        if raw_name is None:
            if required:
                raise AuthConfigError(f"{key} is required")
            return None
        env_name = str(raw_name).strip()
        if not env_name:
            raise AuthConfigError(f"{key} must name an environment variable")
        value = os.environ.get(env_name)
        if value is None or not value.strip():
            raise AuthConfigError(
                f"Required environment variable {env_name} is not set"
            )
        if "\r" in value or "\n" in value:
            raise AuthConfigError(
                f"Environment variable {env_name} contains invalid data"
            )
        return value

    @staticmethod
    def _load_case(payload: Any, config: ScanConfig, index: int) -> AuthCase:
        if not isinstance(payload, dict):
            raise AuthConfigError(f"Authentication case {index} must be an object")
        method = str(payload.get("method", "GET")).upper()
        if method not in SUPPORTED_METHODS:
            raise AuthConfigError(
                f"Authentication case {index} has invalid method"
            )
        raw_url = payload.get("url")
        if raw_url is None or not str(raw_url).strip():
            raise AuthConfigError(f"Authentication case {index} requires url")
        url = urljoin(
            config.target_url.rstrip("/") + "/",
            str(raw_url).strip(),
        )
        scope_error = config.security_scope_error(url)
        if scope_error:
            raise AuthConfigError(
                f"Authentication case {index} is out of scope: {scope_error}"
            )
        evidence_paths = payload.get("evidence_paths")
        if not isinstance(evidence_paths, list) or not evidence_paths or not all(
            isinstance(item, str) and item.strip()
            for item in evidence_paths
        ):
            raise AuthConfigError(
                f"Authentication case {index} requires JSON evidence_paths"
            )
        return AuthCase(
            name=str(payload.get("name") or f"auth-case-{index}"),
            method=method,
            url=url,
            evidence_paths=[item.strip() for item in evidence_paths],
            json_body=payload.get("json_body"),
            allow_state_change=bool(payload.get("allow_state_change", False)),
        )
