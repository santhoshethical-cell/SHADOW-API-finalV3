"""Controlled two-identity BOLA/IDOR validation.

This validator never guesses object identifiers or obtains credentials.  A
researcher must declare User A resources, an explicit host allow-list, and the
environment variable names holding credentials for two controlled identities.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

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


SAFE_METHODS = {"GET", "HEAD"}
SUPPORTED_METHODS = SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE"}
MAX_CASES = 25
MAX_COMPARISON_BYTES = 65536
OWASP_BOLA_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xa1-broken-object-level-authorization/"
)


class BOLAConfigError(ValueError):
    """Raised when controlled BOLA configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class BOLAIdentity:
    name: str
    headers: dict[str, str]


@dataclass(frozen=True)
class BOLACase:
    name: str
    method: str
    url: str
    object_location: str
    object_name: str
    object_value: str
    evidence_paths: list[str] = field(default_factory=list)
    json_body: Any = None
    allow_state_change: bool = False


@dataclass(frozen=True)
class BOLASettings:
    authorized_hosts: frozenset[str]
    user_a: BOLAIdentity
    user_b: BOLAIdentity
    cases: tuple[BOLACase, ...]


class BOLAValidator:
    """Validate access to explicit User A resources using controlled User B."""

    name = "controlled_bola_idor"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        if not config.bola_config_file:
            raise BOLAConfigError("A BOLA configuration file is required")
        self.config = config
        self.client = client
        self.settings = self._load_settings(
            Path(config.bola_config_file),
            config.target_url,
        )

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        results: list[ValidationResult] = []
        vulnerabilities: list[Vulnerability] = []
        endpoints_by_operation = {
            (endpoint.method.upper(), normalize_url(endpoint.url)): endpoint
            for endpoint in endpoints
        }

        for case in self.settings.cases:
            endpoint = endpoints_by_operation.get((
                case.method,
                normalize_url(case.url),
            ))
            if endpoint is None:
                results.append(self._result(
                    case,
                    None,
                    ValidationOutcome.SKIPPED,
                    RiskLevel.INFO,
                    1.0,
                    "The approved User A operation was not discovered",
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
                    "State-changing BOLA validation requires both global "
                    "--active-testing and per-case allow_state_change",
                ))
                continue

            result, vulnerability = await self._validate_case(case, endpoint)
            results.append(result)
            if vulnerability is not None:
                vulnerabilities.append(vulnerability)

        return results, vulnerabilities

    async def _validate_case(
        self,
        case: BOLACase,
        endpoint: APIEndpoint,
    ) -> tuple[ValidationResult, Vulnerability | None]:
        omitted_headers = {
            self.config.auth_header,
            "Authorization",
            "Cookie",
            *SENSITIVE_HEADERS,
            *self.settings.user_a.headers,
            *self.settings.user_b.headers,
        }
        request_options = {
            "omit_headers": omitted_headers,
            "retries": 0,
        }
        if case.json_body is not None:
            request_options["json_body"] = case.json_body

        user_a = await self.client.request(
            case.method,
            case.url,
            headers=self.settings.user_a.headers,
            **request_options,
        )
        user_b = await self.client.request(
            case.method,
            case.url,
            headers=self.settings.user_b.headers,
            **request_options,
        )
        outcome, confidence, reason, semantics = self._classify(
            case,
            user_a,
            user_b,
        )
        severity = (
            RiskLevel.CRITICAL
            if outcome == ValidationOutcome.VULNERABLE
            else RiskLevel.INFO
        )
        result = self._result(
            case,
            endpoint,
            outcome,
            severity,
            confidence,
            reason,
            user_a,
            user_b,
            semantics,
        )
        if outcome != ValidationOutcome.VULNERABLE:
            return result, None

        category = OWASP_CATEGORIES["API1"]
        vulnerability = Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API1",
            owasp_name=category["name"],
            title="BOLA/IDOR: User B accessed a User A resource",
            description=(
                "A researcher-declared User A resource returned matching "
                "ownership semantics when requested with controlled User B "
                "credentials. The result is based on response evidence, not "
                "status code alone."
            ),
            severity=RiskLevel.CRITICAL,
            status=VulnStatus.CONFIRMED,
            risk_score=category["base_score"],
            confidence=confidence,
            poc_request=user_b.format_request(),
            poc_response=user_b.format_response(),
            poc_status_code=user_b.status_code,
            poc_evidence=reason,
            affected_methods=[case.method],
            affected_operation_status_code=user_b.status_code,
            remediation=(
                "Enforce object-level authorization on every request and "
                "verify that the authenticated principal owns or is allowed "
                "to access the requested object."
            ),
            cwe_id="CWE-639",
            references=[OWASP_BOLA_REFERENCE],
        )
        return result, vulnerability

    def _classify(
        self,
        case: BOLACase,
        user_a: CapturedRequest,
        user_b: CapturedRequest,
    ) -> tuple[ValidationOutcome, float, str, dict[str, Any]]:
        semantics = self._response_semantics(case, user_a, user_b)
        if user_a.status_code == 0:
            return (
                ValidationOutcome.ERROR,
                1.0,
                "User A baseline request failed at the transport layer",
                semantics,
            )
        if user_a.status_code not in range(200, 300):
            return (
                ValidationOutcome.INCONCLUSIVE,
                0.95,
                "User A did not receive a successful legitimate baseline",
                semantics,
            )
        if user_b.status_code == 0:
            return (
                ValidationOutcome.ERROR,
                1.0,
                "User B validation request failed at the transport layer",
                semantics,
            )
        if user_b.status_code in {401, 403, 404}:
            return (
                ValidationOutcome.PROTECTED,
                0.85 if user_b.status_code == 404 else 0.95,
                f"User B received HTTP {user_b.status_code}, consistent "
                "with an enforced authorization boundary",
                semantics,
            )
        if user_b.status_code not in range(200, 300):
            return (
                ValidationOutcome.INCONCLUSIVE,
                0.75,
                f"User B received HTTP {user_b.status_code}; this does not "
                "prove either protection or unauthorized access",
                semantics,
            )
        if semantics["ownership_evidence"]:
            reason = (
                "User B received the same researcher-declared User A object "
                "semantics as User A"
            )
            if semantics["researcher_review_recommended"]:
                reason += (
                    "; note: the rest of the response differs substantially "
                    "from User A's - confirm the declared evidence_paths "
                    "represent data genuinely private to this resource, not "
                    "shared/reference data"
                )
            return (
                ValidationOutcome.VULNERABLE,
                0.95,
                reason,
                semantics,
            )
        return (
            ValidationOutcome.INCONCLUSIVE,
            0.6,
            "User B received a successful response, but ownership semantics "
            "were insufficient to establish unauthorized object access",
            semantics,
        )

    def _result(
        self,
        case: BOLACase,
        endpoint: APIEndpoint | None,
        outcome: ValidationOutcome,
        severity: RiskLevel,
        confidence: float,
        reason: str,
        user_a: CapturedRequest | None = None,
        user_b: CapturedRequest | None = None,
        semantics: dict[str, Any] | None = None,
    ) -> ValidationResult:
        evidence = {
            "case": case.name,
            "object": {
                "location": case.object_location,
                "name": case.object_name,
                "representation": self._object_representation(
                    case.object_value
                ),
            },
            "reason": reason,
        }
        if user_a is not None and user_b is not None:
            evidence.update({
                "user_a": self._response_metadata(user_a),
                "user_b": self._response_metadata(user_b),
                "semantics": semantics or {},
            })
        return ValidationResult(
            endpoint_id=endpoint.id if endpoint else None,
            endpoint=case.url,
            method=case.method,
            validator=self.name,
            vulnerability_category="API1:2023 BOLA/IDOR",
            result=outcome,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            affected_parameter=(
                f"{case.object_location}:{case.object_name}"
            ),
            remediation=(
                "Verify object ownership or explicit access grants on every "
                "API request."
            ),
            references=[OWASP_BOLA_REFERENCE],
        )

    @staticmethod
    def _response_metadata(captured: CapturedRequest) -> dict[str, Any]:
        body = captured.response_body or ""
        return {
            "status_code": captured.status_code,
            "content_type": captured.response_headers.get(
                "content-type", ""
            ),
            "body_size": len(body.encode("utf-8", errors="replace")),
            "body_sha256": hashlib.sha256(
                body.encode("utf-8", errors="replace")
            ).hexdigest(),
        }

    @classmethod
    def _response_semantics(
        cls,
        case: BOLACase,
        user_a: CapturedRequest,
        user_b: CapturedRequest,
    ) -> dict[str, Any]:
        user_a_body = (user_a.response_body or "")[:MAX_COMPARISON_BYTES]
        user_b_body = (user_b.response_body or "")[:MAX_COMPARISON_BYTES]
        payload_a = cls._json_payload(user_a_body)
        payload_b = cls._json_payload(user_b_body)
        comparable_a = cls._canonical_payload(payload_a, user_a_body)
        comparable_b = cls._canonical_payload(payload_b, user_b_body)
        similarity = SequenceMatcher(
            None,
            comparable_a,
            comparable_b,
        ).ratio() if (comparable_a or comparable_b) else 0.0

        matching_paths = []
        for path in case.evidence_paths:
            value_a = cls._json_path(payload_a, path)
            value_b = cls._json_path(payload_b, path)
            if value_a is not None and value_a == value_b:
                matching_paths.append(path)

        # Exact per-path match on every researcher-declared evidence path is
        # sufficient on its own, mirroring AccessControlValidator._semantics's
        # "complete" fingerprint-equality check. This must not be vetoed by an
        # unrelated drop in whole-body similarity caused by fields the
        # researcher never declared as ownership evidence (timestamps,
        # nonces, CSRF tokens, request IDs, etc.) - see the audited BOLA
        # false-negative gap. When no evidence_paths are declared, or they do
        # not all resolve/match, ownership falls back to the similarity +
        # declared-object-value heuristic, unchanged in rigor from before.
        evidence_paths_confirmed = (
            bool(case.evidence_paths)
            and len(matching_paths) == len(case.evidence_paths)
        )

        object_in_a = cls._contains_scalar(payload_a, case.object_value)
        object_in_b = cls._contains_scalar(payload_b, case.object_value)
        ownership_evidence = (
            evidence_paths_confirmed
            or (similarity >= 0.8 and object_in_a and object_in_b)
        )
        # Diagnostic only: does not affect outcome or confidence. An exact
        # evidence-path match combined with a substantially different overall
        # response can mean the declared path legitimately proves ownership
        # despite unrelated per-request noise (the case this fix targets) -
        # or it can mean the declared path points at data that is not
        # actually private (e.g. shared reference/catalog data), which the
        # tool cannot distinguish automatically. Flag it so a report reader
        # knows to sanity-check the evidence_paths choice for this case.
        review_recommended = evidence_paths_confirmed and similarity < 0.5
        return {
            "response_similarity": round(similarity, 4),
            "matching_evidence_paths": matching_paths,
            "evidence_paths_confirmed": evidence_paths_confirmed,
            "declared_object_present_for_user_a": object_in_a,
            "declared_object_present_for_user_b": object_in_b,
            "ownership_evidence": ownership_evidence,
            "researcher_review_recommended": review_recommended,
        }

    @staticmethod
    def _json_payload(body: str) -> Any:
        try:
            return json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _canonical_payload(payload: Any, fallback: str) -> str:
        if payload is None:
            return " ".join(fallback.split())
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

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

    @classmethod
    def _contains_scalar(cls, value: Any, expected: str) -> bool:
        if isinstance(value, dict):
            return any(
                cls._contains_scalar(item, expected)
                for item in value.values()
            )
        if isinstance(value, list):
            return any(cls._contains_scalar(item, expected) for item in value)
        return value is not None and str(value) == expected

    @staticmethod
    def _object_representation(value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        return f"sha256:{digest}"

    @classmethod
    def _load_settings(
        cls,
        path: Path,
        target_url: str,
    ) -> BOLASettings:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise BOLAConfigError(
                f"Unable to read BOLA configuration: {error}"
            ) from error
        if not isinstance(payload, dict):
            raise BOLAConfigError("BOLA configuration must be an object")

        hosts = payload.get("authorized_hosts")
        if not isinstance(hosts, list) or not hosts:
            raise BOLAConfigError(
                "authorized_hosts must explicitly list at least one host"
            )
        authorized_hosts = frozenset(
            str(host).strip().lower() for host in hosts if str(host).strip()
        )
        if any("*" in host or "/" in host for host in authorized_hosts):
            raise BOLAConfigError(
                "authorized_hosts must contain exact hostnames without wildcards"
            )
        target_host = (urlparse(target_url).hostname or "").lower()
        if target_host not in authorized_hosts:
            raise BOLAConfigError(
                "The scan target host is not present in authorized_hosts"
            )

        identities = payload.get("identities")
        if not isinstance(identities, dict):
            raise BOLAConfigError("identities.user_a and user_b are required")
        user_a = cls._load_identity("user_a", identities.get("user_a"))
        user_b = cls._load_identity("user_b", identities.get("user_b"))
        if user_a.headers == user_b.headers:
            raise BOLAConfigError(
                "User A and User B must use distinct controlled credentials"
            )

        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise BOLAConfigError("At least one BOLA case is required")
        if len(raw_cases) > MAX_CASES:
            raise BOLAConfigError(
                f"BOLA configuration exceeds the {MAX_CASES}-case safety cap"
            )
        cases = tuple(
            cls._load_case(
                item,
                target_url,
                authorized_hosts,
                index,
            )
            for index, item in enumerate(raw_cases, start=1)
        )
        return BOLASettings(authorized_hosts, user_a, user_b, cases)

    @staticmethod
    def _load_identity(name: str, payload: Any) -> BOLAIdentity:
        if not isinstance(payload, dict):
            raise BOLAConfigError(f"identities.{name} is required")
        if "headers" in payload:
            raise BOLAConfigError(
                f"identities.{name}.headers is not allowed; use header_env"
            )
        header_env = payload.get("header_env")
        if not isinstance(header_env, dict) or not header_env:
            raise BOLAConfigError(
                f"identities.{name}.header_env must map headers to env vars"
            )
        headers = {}
        for header, env_name in header_env.items():
            header = str(header).strip()
            env_name = str(env_name).strip()
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header):
                raise BOLAConfigError(
                    f"Invalid header name for identity {name}"
                )
            value = os.environ.get(env_name)
            if value is None or not value.strip():
                raise BOLAConfigError(
                    f"Required environment variable {env_name} is not set"
                )
            if "\r" in value or "\n" in value:
                raise BOLAConfigError(
                    f"Environment variable {env_name} contains invalid data"
                )
            headers[header] = value
        return BOLAIdentity(name=name, headers=headers)

    @staticmethod
    def _load_case(
        payload: Any,
        target_url: str,
        authorized_hosts: frozenset[str],
        index: int,
    ) -> BOLACase:
        if not isinstance(payload, dict):
            raise BOLAConfigError(f"BOLA case {index} must be an object")
        method = str(payload.get("method", "GET")).upper()
        if method not in SUPPORTED_METHODS:
            raise BOLAConfigError(f"BOLA case {index} has invalid method")
        raw_url_value = payload.get("url")
        raw_url = (
            str(raw_url_value).strip()
            if raw_url_value is not None else ""
        )
        if not raw_url:
            raise BOLAConfigError(f"BOLA case {index} requires url")
        url = urljoin(target_url.rstrip("/") + "/", raw_url)
        parsed = urlparse(url)
        if (
            parsed.scheme not in {"http", "https"}
            or (parsed.hostname or "").lower() not in authorized_hosts
        ):
            raise BOLAConfigError(
                f"BOLA case {index} is outside authorized_hosts"
            )
        location = str(payload.get("object_location", "path")).lower()
        if location not in {"path", "query", "body"}:
            raise BOLAConfigError(
                f"BOLA case {index} has invalid object_location"
            )
        raw_object_name = payload.get("object_name")
        raw_object_value = payload.get("object_value")
        object_name = (
            str(raw_object_name).strip()
            if raw_object_name is not None else ""
        )
        object_value = (
            str(raw_object_value).strip()
            if raw_object_value is not None else ""
        )
        if not object_name or not object_value:
            raise BOLAConfigError(
                f"BOLA case {index} requires object_name and object_value"
            )
        if location == "path" and object_value not in parsed.path.split("/"):
            raise BOLAConfigError(
                f"BOLA case {index} path does not contain object_value"
            )
        if location == "query" and object_value not in {
            value
            for values in parse_qs(parsed.query).values()
            for value in values
        }:
            raise BOLAConfigError(
                f"BOLA case {index} query does not contain object_value"
            )
        json_body = payload.get("json_body")
        if location == "body" and not BOLAValidator._body_has_object(
            json_body,
            object_name,
            object_value,
        ):
            raise BOLAConfigError(
                f"BOLA case {index} body does not contain the declared object"
            )
        evidence_paths = payload.get("evidence_paths", [])
        if not isinstance(evidence_paths, list) or not all(
            isinstance(item, str) and item.strip()
            for item in evidence_paths
        ):
            raise BOLAConfigError(
                f"BOLA case {index} evidence_paths must be string paths"
            )
        return BOLACase(
            name=str(payload.get("name") or f"bola-case-{index}"),
            method=method,
            url=url,
            object_location=location,
            object_name=object_name,
            object_value=object_value,
            evidence_paths=[item.strip() for item in evidence_paths],
            json_body=json_body,
            allow_state_change=bool(payload.get("allow_state_change", False)),
        )

    @staticmethod
    def _body_has_object(value: Any, name: str, expected: str) -> bool:
        if isinstance(value, dict):
            if name in value and str(value[name]) == expected:
                return True
            return any(
                BOLAValidator._body_has_object(item, name, expected)
                for item in value.values()
            )
        if isinstance(value, list):
            return any(
                BOLAValidator._body_has_object(item, name, expected)
                for item in value
            )
        return False
