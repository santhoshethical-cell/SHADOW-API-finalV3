"""Controlled multi-identity session and access-control validation."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

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
from shadow_api_scanner.utils.redaction import SENSITIVE_HEADERS


MAX_CASES = 25
CASE_TYPES = {
    "role_boundary",
    "function_access",
    "endpoint_access",
    "cross_user",
    "stale_session",
    "session_invalidation",
}
OWASP_ACCESS_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa5-broken-function-level-authorization/"
)


class AccessControlConfigError(ValueError):
    """Raised when identities or semantic cases are unsafe/incomplete."""


@dataclass(frozen=True)
class ControlledIdentity:
    name: str
    header_name: str
    header_value: str


@dataclass(frozen=True)
class AccessControlCase:
    name: str
    case_type: str
    method: str
    url: str
    allowed_identity: str
    denied_identities: tuple[str, ...]
    evidence_paths: tuple[str, ...]


class AccessControlValidator:
    """Compare approved identities using declared protected response semantics."""

    name = "controlled_session_access_control"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        if not config.access_validation_config_file:
            raise AccessControlConfigError("An access validation config is required")
        scope_error = config.security_scope_error()
        if scope_error:
            raise AccessControlConfigError(scope_error)
        self.config = config
        self.client = client
        self.identities, self.cases = self._load(
            Path(config.access_validation_config_file)
        )

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        endpoint_map = {
            (endpoint.method.upper(), normalize_url(endpoint.url)): endpoint
            for endpoint in endpoints
        }
        results = []
        vulnerabilities = []
        for case in self.cases:
            endpoint = endpoint_map.get((case.method, normalize_url(case.url)))
            if endpoint is None:
                results.append(self._result(
                    case, None, ValidationOutcome.SKIPPED, 1.0,
                    "The declared protected operation was not discovered", [],
                ))
                continue
            result, vulnerability = await self._validate_case(case, endpoint)
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)
        return results, vulnerabilities

    async def _validate_case(
        self,
        case: AccessControlCase,
        endpoint: APIEndpoint,
    ) -> tuple[ValidationResult, Vulnerability | None]:
        allowed = await self._request(case, self.identities[case.allowed_identity])
        allowed_semantics = self._semantics(allowed.response_body, case.evidence_paths)
        if allowed.status_code == 0:
            return self._result(
                case, endpoint, ValidationOutcome.ERROR, 1.0,
                "Allowed-identity baseline failed at the transport layer", [],
            ), None
        if (
            allowed.status_code not in range(200, 300)
            or not allowed_semantics["complete"]
        ):
            return self._result(
                case, endpoint, ValidationOutcome.INCONCLUSIVE, 0.95,
                "Allowed identity did not establish the declared protected semantics",
                [], allowed,
            ), None

        assessments = []
        first_vulnerable: CapturedRequest | None = None
        vulnerable_identity: str | None = None
        for identity_name in case.denied_identities:
            captured = await self._request(case, self.identities[identity_name])
            semantics = self._semantics(captured.response_body, case.evidence_paths)
            if captured.status_code == 0:
                outcome = ValidationOutcome.ERROR
                reason = "transport error"
            elif captured.status_code in {401, 403, 404}:
                outcome = ValidationOutcome.PROTECTED
                reason = "access denied or resource hidden"
            elif (
                captured.status_code in range(200, 300)
                and semantics["complete"]
                and semantics["fingerprints"] == allowed_semantics["fingerprints"]
            ):
                outcome = ValidationOutcome.VULNERABLE
                reason = "declared protected semantics matched the allowed identity"
                if first_vulnerable is None:
                    first_vulnerable = captured
                    vulnerable_identity = identity_name
            else:
                outcome = ValidationOutcome.INCONCLUSIVE
                reason = "status/response did not establish protected semantic access"
            assessments.append({
                "identity": identity_name,
                "status": captured.status_code,
                "result": outcome.value,
                "reason": reason,
                "semantic_fingerprints": semantics["fingerprints"],
            })

        outcomes = {item["result"] for item in assessments}
        if ValidationOutcome.VULNERABLE.value in outcomes:
            outcome = ValidationOutcome.VULNERABLE
            confidence = 0.96
            reason = "At least one denied identity received protected semantics"
        elif outcomes == {ValidationOutcome.PROTECTED.value}:
            outcome = ValidationOutcome.PROTECTED
            confidence = 0.95
            reason = "All denied identities were rejected or the resource was hidden"
        elif outcomes == {ValidationOutcome.ERROR.value}:
            outcome = ValidationOutcome.ERROR
            confidence = 1.0
            reason = "All denied-identity checks failed at the transport layer"
        else:
            outcome = ValidationOutcome.INCONCLUSIVE
            confidence = 0.72
            reason = "Identity results were mixed or lacked protected semantics"

        result = self._result(
            case, endpoint, outcome, confidence, reason, assessments, allowed
        )
        if first_vulnerable is None or vulnerable_identity is None:
            return result, None
        return result, self._vulnerability(
            case, endpoint, first_vulnerable, vulnerable_identity, confidence, reason
        )

    async def _request(
        self,
        case: AccessControlCase,
        identity: ControlledIdentity,
    ) -> CapturedRequest:
        omitted = {
            self.config.auth_header,
            "Authorization",
            "Cookie",
            *SENSITIVE_HEADERS,
            *(item.header_name for item in self.identities.values()),
        }
        return await self.client.request(
            case.method,
            case.url,
            headers={identity.header_name: identity.header_value},
            omit_headers=omitted,
            retries=0,
        )

    @staticmethod
    def _semantics(body: str, paths: tuple[str, ...]) -> dict[str, Any]:
        try:
            payload = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return {"complete": False, "fingerprints": {}}
        fingerprints = {}
        for path in paths:
            value: Any = payload
            found = True
            for part in path.removeprefix("$.").split("."):
                if not isinstance(value, dict) or part not in value:
                    found = False
                    break
                value = value[part]
            if found:
                encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
                fingerprints[path] = hashlib.sha256(
                    encoded.encode("utf-8")
                ).hexdigest()[:12]
        return {
            "complete": len(fingerprints) == len(paths),
            "fingerprints": fingerprints,
        }

    def _result(
        self,
        case: AccessControlCase,
        endpoint: APIEndpoint | None,
        outcome: ValidationOutcome,
        confidence: float,
        reason: str,
        assessments: list[dict[str, Any]],
        allowed: CapturedRequest | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            endpoint_id=endpoint.id if endpoint else None,
            endpoint=case.url,
            method=case.method,
            validator=self.name,
            vulnerability_category=case.case_type,
            result=outcome,
            severity=(
                RiskLevel.HIGH
                if outcome == ValidationOutcome.VULNERABLE
                else RiskLevel.INFO
            ),
            confidence=confidence,
            evidence={
                "reason": reason,
                "allowed_identity": case.allowed_identity,
                "allowed_status": allowed.status_code if allowed else None,
                "evidence_paths": list(case.evidence_paths),
                "identity_assessments": assessments,
                "raw_credentials_stored": False,
            },
            remediation=(
                "Enforce deny-by-default role, function, endpoint, object, and "
                "session checks on every protected operation."
            ),
            references=[OWASP_ACCESS_REFERENCE],
        )

    @staticmethod
    def _vulnerability(
        case: AccessControlCase,
        endpoint: APIEndpoint,
        captured: CapturedRequest,
        identity_name: str,
        confidence: float,
        reason: str,
    ) -> Vulnerability:
        if case.case_type in {"stale_session", "session_invalidation"}:
            api_key, cwe = "API2", "CWE-613"
        elif case.case_type == "cross_user":
            api_key, cwe = "API1", "CWE-639"
        else:
            api_key, cwe = "API5", "CWE-862"
        category = OWASP_CATEGORIES[api_key]
        return Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category=api_key,
            owasp_name=category["name"],
            title=f"Access-control boundary failure: {case.case_type}",
            description=(
                f"Controlled identity {identity_name!r} received the same "
                "declared protected semantics as the allowed identity."
            ),
            severity=RiskLevel.HIGH,
            status=VulnStatus.CONFIRMED,
            risk_score=8.5,
            confidence=confidence,
            poc_request=captured.format_request(),
            poc_status_code=captured.status_code,
            poc_evidence=reason,
            affected_methods=[case.method],
            affected_operation_status_code=captured.status_code,
            remediation=(
                "Enforce authorization and session validity server-side for "
                "each protected operation and deny by default."
            ),
            cwe_id=cwe,
            references=[OWASP_ACCESS_REFERENCE],
        )

    def _load(
        self,
        path: Path,
    ) -> tuple[dict[str, ControlledIdentity], tuple[AccessControlCase, ...]]:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as error:
            raise AccessControlConfigError(f"Unable to load access config: {error}") from error
        if not isinstance(document, dict):
            raise AccessControlConfigError("Access config must be an object")
        raw_identities = document.get("identities")
        raw_cases = document.get("cases")
        if not isinstance(raw_identities, dict) or len(raw_identities) < 2:
            raise AccessControlConfigError("At least two controlled identities are required")
        identities = {}
        for name, raw in raw_identities.items():
            if not isinstance(raw, dict) or "value" in raw:
                raise AccessControlConfigError(
                    f"Identity {name!r} must reference an environment variable"
                )
            header_name = str(raw.get("header_name", "Authorization")).strip()
            env_name = str(raw.get("value_env", "")).strip()
            value = os.environ.get(env_name, "") if env_name else ""
            if not header_name or not env_name or not value:
                raise AccessControlConfigError(
                    f"Identity {name!r} requires a populated value_env"
                )
            identities[str(name)] = ControlledIdentity(str(name), header_name, value)
        if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > MAX_CASES:
            raise AccessControlConfigError("Access config must contain 1 to 25 cases")
        cases = []
        for index, raw in enumerate(raw_cases):
            if not isinstance(raw, dict):
                raise AccessControlConfigError(f"Case {index + 1} must be an object")
            name = str(raw.get("name") or f"case-{index + 1}")[:128]
            case_type = str(raw.get("type", ""))
            method = str(raw.get("method", "GET")).upper()
            url = urljoin(self.config.target_url, str(raw.get("url", "")))
            allowed = str(raw.get("allowed_identity", ""))
            denied = raw.get("denied_identities", [])
            paths = raw.get("evidence_paths", [])
            if case_type not in CASE_TYPES or method not in {"GET", "HEAD"}:
                raise AccessControlConfigError(
                    f"{name}: use a supported type and read-only GET/HEAD method"
                )
            if (
                allowed not in identities
                or not isinstance(denied, list)
                or not denied
                or any(identity not in identities or identity == allowed for identity in denied)
            ):
                raise AccessControlConfigError(f"{name}: identity boundary is invalid")
            if not isinstance(paths, list) or not paths or len(paths) > 20:
                raise AccessControlConfigError(f"{name}: semantic evidence_paths are required")
            if not self.config.is_security_target_authorized(url):
                raise AccessControlConfigError(f"{name}: URL is outside the exact host allow-list")
            cases.append(AccessControlCase(
                name=name,
                case_type=case_type,
                method=method,
                url=url,
                allowed_identity=allowed,
                denied_identities=tuple(dict.fromkeys(str(item) for item in denied)),
                evidence_paths=tuple(dict.fromkeys(str(item) for item in paths)),
            ))
        return identities, tuple(cases)
