"""Controlled, non-destructive injection indicator validation."""

from __future__ import annotations

import hashlib
import re
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


MAX_CASES = 25
SUPPORTED_CATEGORIES = {"sql", "nosql", "command", "template"}
PROBES = {
    "sql": "scanner-probe-'",
    "nosql": '{"$invalidScannerOperator":"probe"}',
    "command": ";SCANNER_INJECTION_PROBE",
    "template": "{{'SCANNER_PROBE_' ~ (7*7)}}",
}
CONTROL_VALUE = "scanner-control-7f3a"
INDICATORS = {
    "sql": {
        "sqlstate": re.compile(r"\bsqlstate\b", re.I),
        "database syntax": re.compile(
            r"(?:mysql|postgresql|sqlite|ora-\d+|unclosed quotation|sql syntax)",
            re.I,
        ),
    },
    "nosql": {
        "NoSQL driver": re.compile(
            r"(?:mongoservererror|unknown operator|bson|cast to objectid)",
            re.I,
        ),
    },
    "command": {
        "shell parser": re.compile(
            r"(?:/bin/(?:ba)?sh:|cmd\.exe|not recognized as an internal|"
            r"syntax error near unexpected token)",
            re.I,
        ),
    },
}
OWASP_INJECTION_REFERENCE = (
    "https://owasp.org/API-Security/editions/2023/en/"
    "0xaa0-owasp-api-security-top-10-2023/"
)


class InjectionConfigError(ValueError):
    """Raised when a controlled injection case is unsafe or incomplete."""


@dataclass(frozen=True)
class InjectionCase:
    name: str
    method: str
    url: str
    parameter: str
    baseline_value: str
    categories: tuple[str, ...]


class SafeInjectionValidator:
    """Compare fixed safe probes with baseline and neutral-control responses."""

    name = "safe_injection_indicators"

    def __init__(self, config: ScanConfig, client: AsyncHTTPClient):
        if not config.injection_validation_config_file:
            raise InjectionConfigError("An injection validation config is required")
        scope_error = config.security_scope_error()
        if scope_error:
            raise InjectionConfigError(scope_error)
        self.config = config
        self.client = client
        self.cases = self._load_cases(Path(config.injection_validation_config_file))

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
        for case in self.cases:
            endpoint = endpoint_map.get((case.method, normalize_url(case.url)))
            if endpoint is None:
                for category in case.categories:
                    results.append(self._result(
                        case, None, category, ValidationOutcome.SKIPPED,
                        1.0, "The declared operation was not discovered", {},
                    ))
                continue
            case_results, case_vulnerabilities = await self._validate_case(
                case, endpoint
            )
            results.extend(case_results)
            vulnerabilities.extend(case_vulnerabilities)
        return results, vulnerabilities

    async def _validate_case(
        self,
        case: InjectionCase,
        endpoint: APIEndpoint,
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        baseline = await self._request(case, case.baseline_value)
        control = await self._request(case, CONTROL_VALUE)
        results = []
        vulnerabilities = []
        if baseline.status_code == 0 or control.status_code == 0:
            reason = "Baseline or neutral-control request failed at the transport layer"
            for category in case.categories:
                results.append(self._result(
                    case, endpoint, category, ValidationOutcome.ERROR,
                    1.0, reason, self._evidence(baseline, control, None, []),
                ))
            return results, vulnerabilities
        if baseline.status_code not in range(200, 300):
            reason = "The declared baseline did not establish a successful operation"
            for category in case.categories:
                results.append(self._result(
                    case, endpoint, category, ValidationOutcome.INCONCLUSIVE,
                    0.95, reason, self._evidence(baseline, control, None, []),
                ))
            return results, vulnerabilities

        for category in case.categories:
            probe = await self._request(case, PROBES[category])
            outcome, confidence, reason, indicators = self._classify(
                category, baseline, control, probe
            )
            evidence = self._evidence(baseline, control, probe, indicators)
            result = self._result(
                case, endpoint, category, outcome, confidence, reason, evidence
            )
            results.append(result)
            if outcome == ValidationOutcome.VULNERABLE:
                vulnerabilities.append(self._vulnerability(
                    case, endpoint, category, probe, confidence, reason
                ))
        return results, vulnerabilities

    async def _request(
        self,
        case: InjectionCase,
        value: str,
    ) -> CapturedRequest:
        return await self.client.request(
            case.method,
            case.url,
            params={case.parameter: value},
            retries=0,
        )

    @staticmethod
    def _classify(
        category: str,
        baseline: CapturedRequest,
        control: CapturedRequest,
        probe: CapturedRequest,
    ) -> tuple[ValidationOutcome, float, str, list[str]]:
        if probe.status_code == 0:
            return ValidationOutcome.ERROR, 1.0, "Probe transport failed", []
        baseline_body = baseline.response_body or ""
        control_body = control.response_body or ""
        probe_body = probe.response_body or ""
        if category == "template":
            evaluated = (
                "SCANNER_PROBE_49" in probe_body
                and "SCANNER_PROBE_49" not in baseline_body
                and "SCANNER_PROBE_49" not in control_body
                and PROBES[category] not in probe_body
            )
            if evaluated:
                return (
                    ValidationOutcome.VULNERABLE,
                    0.96,
                    "The fixed arithmetic template marker was evaluated",
                    ["evaluated template marker"],
                )
        indicators = []
        for name, pattern in INDICATORS.get(category, {}).items():
            if (
                pattern.search(probe_body)
                and not pattern.search(baseline_body)
                and not pattern.search(control_body)
            ):
                indicators.append(name)
        if indicators:
            return (
                ValidationOutcome.VULNERABLE,
                0.86,
                "Category-specific parser/error indicators appeared only for the probe",
                indicators,
            )
        if probe.status_code in {400, 409, 422} and control.status_code in range(200, 300):
            return (
                ValidationOutcome.PROTECTED,
                0.82,
                "The probe was rejected while the neutral control was accepted",
                [],
            )
        if probe.status_code >= 500 and control.status_code < 500:
            return (
                ValidationOutcome.INCONCLUSIVE,
                0.7,
                "A probe-specific server error lacked a category-specific indicator",
                [],
            )
        return (
            ValidationOutcome.INCONCLUSIVE,
            0.62,
            "No category-specific differential indicator was established",
            [],
        )

    @staticmethod
    def _evidence(
        baseline: CapturedRequest,
        control: CapturedRequest,
        probe: CapturedRequest | None,
        indicators: list[str],
    ) -> dict[str, Any]:
        def summary(captured: CapturedRequest | None) -> dict[str, Any] | None:
            if captured is None:
                return None
            body = captured.response_body or ""
            return {
                "status": captured.status_code,
                "body_length": len(body),
                "body_sha256": hashlib.sha256(
                    body.encode("utf-8", errors="replace")
                ).hexdigest()[:12],
            }
        return {
            "baseline": summary(baseline),
            "neutral_control": summary(control),
            "probe": summary(probe),
            "indicators": indicators,
            "timing_probe_used": False,
            "destructive_probe_used": False,
        }

    def _result(
        self,
        case: InjectionCase,
        endpoint: APIEndpoint | None,
        category: str,
        outcome: ValidationOutcome,
        confidence: float,
        reason: str,
        evidence: dict[str, Any],
    ) -> ValidationResult:
        return ValidationResult(
            endpoint_id=endpoint.id if endpoint else None,
            endpoint=case.url,
            method=case.method,
            validator=self.name,
            vulnerability_category=f"Injection indicator: {category}",
            result=outcome,
            severity=(
                RiskLevel.HIGH
                if outcome == ValidationOutcome.VULNERABLE
                else RiskLevel.INFO
            ),
            confidence=confidence,
            evidence={"reason": reason, "probe_category": category, **evidence},
            affected_parameter=case.parameter,
            remediation=(
                "Use parameterized APIs, strict typed validation, and avoid "
                "passing user input to interpreters."
            ),
            references=[OWASP_INJECTION_REFERENCE],
        )

    @staticmethod
    def _vulnerability(
        case: InjectionCase,
        endpoint: APIEndpoint,
        category: str,
        probe: CapturedRequest,
        confidence: float,
        reason: str,
    ) -> Vulnerability:
        category_info = OWASP_CATEGORIES["API10"]
        cwe = {
            "sql": "CWE-89",
            "nosql": "CWE-943",
            "command": "CWE-78",
            "template": "CWE-1336",
        }[category]
        return Vulnerability(
            endpoint_id=endpoint.id,
            owasp_category="API10",
            owasp_name=category_info["name"],
            title=f"Safe {category.upper()} injection indicator",
            description=(
                "A fixed non-destructive probe produced a category-specific "
                "response differential absent from both baseline and neutral control."
            ),
            severity=RiskLevel.HIGH,
            status=(
                VulnStatus.CONFIRMED
                if category == "template" and confidence >= 0.95
                else VulnStatus.POTENTIAL
            ),
            risk_score=8.0,
            confidence=confidence,
            poc_status_code=probe.status_code,
            poc_evidence=reason,
            affected_methods=[case.method],
            affected_operation_status_code=probe.status_code,
            remediation=(
                "Use typed allow-list validation and parameterized APIs; never "
                "concatenate untrusted input into queries or interpreter input."
            ),
            cwe_id=cwe,
            references=[OWASP_INJECTION_REFERENCE],
        )

    def _load_cases(self, path: Path) -> tuple[InjectionCase, ...]:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as error:
            raise InjectionConfigError(f"Unable to load injection config: {error}") from error
        raw_cases = document.get("cases") if isinstance(document, dict) else None
        if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > MAX_CASES:
            raise InjectionConfigError("Injection config must contain 1 to 25 cases")
        cases = []
        for index, raw in enumerate(raw_cases):
            if not isinstance(raw, dict):
                raise InjectionConfigError(f"Case {index + 1} must be an object")
            name = str(raw.get("name") or f"case-{index + 1}")[:128]
            method = str(raw.get("method", "GET")).upper()
            url = urljoin(self.config.target_url, str(raw.get("url", "")))
            parameter = str(raw.get("parameter", "")).strip()[:128]
            baseline_value = str(raw.get("baseline_value", ""))
            categories = raw.get("categories", [])
            if method != "GET":
                raise InjectionConfigError(f"{name}: only read-only GET cases are supported")
            if not parameter or not baseline_value or len(baseline_value) > 256:
                raise InjectionConfigError(f"{name}: bounded parameter and baseline_value are required")
            if (
                not isinstance(categories, list)
                or not categories
                or not set(categories).issubset(SUPPORTED_CATEGORIES)
            ):
                raise InjectionConfigError(f"{name}: categories must use sql, nosql, command, or template")
            if not self.config.is_security_target_authorized(url):
                raise InjectionConfigError(f"{name}: URL is outside the exact host allow-list")
            cases.append(InjectionCase(
                name=name,
                method=method,
                url=url,
                parameter=parameter,
                baseline_value=baseline_value,
                categories=tuple(dict.fromkeys(categories)),
            ))
        return tuple(cases)
