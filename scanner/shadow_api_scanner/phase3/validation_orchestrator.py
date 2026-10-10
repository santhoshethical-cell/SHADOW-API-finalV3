"""Registry-driven orchestration for modular security validators."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, ValidationResult
from shadow_api_scanner.phase3.validators.access_control import (
    AccessControlConfigError,
    AccessControlValidator,
)
from shadow_api_scanner.phase3.validators.authentication import (
    AuthConfigError,
    BrokenAuthenticationValidator,
)
from shadow_api_scanner.phase3.validators.base import (
    ValidationBatch,
    Validator,
)
from shadow_api_scanner.phase3.validators.bola import BOLAConfigError, BOLAValidator
from shadow_api_scanner.phase3.validators.graphql import (
    GraphQLConfigError,
    GraphQLValidator,
)
from shadow_api_scanner.phase3.validators.data_exposure import (
    DataExposureConfigError,
    DataExposureValidator,
)
from shadow_api_scanner.phase3.validators.injection import (
    InjectionConfigError,
    SafeInjectionValidator,
)
from shadow_api_scanner.phase3.validators.parameters import (
    ParameterConfigError,
    ParameterManipulationValidator,
)
from shadow_api_scanner.phase3.validators.rate_limit import (
    RateLimitConfigError,
    RateLimitValidator,
)
from shadow_api_scanner.phase3.validators.unused_method import (
    MethodEnumerationConfigError,
    UnusedMethodValidator,
)
from shadow_api_scanner.phase3.validators.info_disclosure import (
    InfoDisclosureConfigError,
    InfoDisclosureValidator,
)
from shadow_api_scanner.utils.helpers import normalize_url
from shadow_api_scanner.utils.http_client import AsyncHTTPClient


logger = logging.getLogger("shadow_api_scanner")


@dataclass(frozen=True)
class ValidatorRegistration:
    name: str
    factory: Callable[[ScanConfig, AsyncHTTPClient], Validator]
    enabled: Callable[[ScanConfig], bool]
    config_error: type[ValueError]


class ValidationOrchestrator:
    """Run enabled validators and enrich their common result schema."""

    def __init__(
        self,
        config: ScanConfig,
        client: AsyncHTTPClient,
        registrations: tuple[ValidatorRegistration, ...] | None = None,
    ):
        self.config = config
        self.client = client
        self.registrations = registrations or self.default_registrations()

    async def run(self, endpoints: list[APIEndpoint]) -> ValidationBatch:
        batch = ValidationBatch()
        authorized = [
            endpoint for endpoint in endpoints
            if self.config.is_security_target_authorized(endpoint.url)
        ]
        for registration in self.registrations:
            if not registration.enabled(self.config):
                continue
            try:
                validator = registration.factory(self.config, self.client)
                results, vulnerabilities = await validator.validate(authorized)
            except registration.config_error as error:
                message = f"{registration.name} validation blocked: {error}"
                logger.error("  %s", message)
                batch.errors.append(message)
                continue
            except Exception as error:
                message = f"{registration.name} validation error: {error}"
                logger.warning("  %s", message)
                batch.errors.append(message)
                continue
            self._enrich(results, authorized)
            self._record_item_crashes(registration.name, results, batch)
            batch.results.extend(results)
            batch.vulnerabilities.extend(vulnerabilities)
            batch.executed_validators.append(registration.name)
            logger.info(
                "  %s assessments: %s (%s findings)",
                registration.name,
                len(results),
                len(vulnerabilities),
            )
        return batch

    @staticmethod
    def _record_item_crashes(
        validator_name: str,
        results: list[ValidationResult],
        batch: ValidationBatch,
    ) -> None:
        """Surface per-endpoint validator crashes into batch/result errors.

        The validator itself continues past a single bad endpoint and marks
        that one result with `validator_crashed_for_item` (see
        DataExposureValidator._crash_result and
        ParameterManipulationValidator._passive_crash_result). This makes the
        distinction visible at the scan-result level too, so it reads
        differently from "validator skipped by config" rather than looking
        identical to a clean run.
        """
        for result in results:
            if not result.evidence.get("validator_crashed_for_item"):
                continue
            message = (
                f"{validator_name} raised "
                f"{result.evidence.get('exception_type', 'an exception')} "
                f"while assessing {result.method} {result.endpoint}: "
                f"{result.evidence.get('exception_message', '')} "
                "(other endpoints for this validator completed normally)"
            )
            logger.warning("  %s", message)
            batch.errors.append(message)

    @staticmethod
    def _enrich(
        results: list[ValidationResult],
        endpoints: list[APIEndpoint],
    ) -> None:
        by_id = {endpoint.id: endpoint for endpoint in endpoints}
        by_operation = {
            (endpoint.method.upper(), normalize_url(endpoint.url)): endpoint
            for endpoint in endpoints
        }
        for result in results:
            endpoint = by_id.get(result.endpoint_id or "") or by_operation.get((
                result.method.upper(),
                normalize_url(result.endpoint),
            ))
            if endpoint is None:
                continue
            result.normalized_route = endpoint.route_pattern or endpoint.normalized_url
            result.discovery_sources = list(dict.fromkeys(
                endpoint.observed_sources or [endpoint.source.value]
            ))
            result.documentation_status = endpoint.documentation_status.value
            result.shadow_status = endpoint.is_shadow
            result.response_metadata = {
                "status_code": endpoint.status_code,
                "content_type": endpoint.response_content_type,
                "size": endpoint.response_size,
            }

    @staticmethod
    def default_registrations() -> tuple[ValidatorRegistration, ...]:
        return (
            ValidatorRegistration(
                "controlled_bola_idor", BOLAValidator,
                lambda config: bool(config.bola_config_file), BOLAConfigError,
            ),
            ValidatorRegistration(
                "controlled_broken_authentication", BrokenAuthenticationValidator,
                lambda config: bool(config.auth_validation_config_file), AuthConfigError,
            ),
            ValidatorRegistration(
                "excessive_data_exposure", DataExposureValidator,
                lambda config: True, DataExposureConfigError,
            ),
            ValidatorRegistration(
                "parameter_manipulation", ParameterManipulationValidator,
                lambda config: True, ParameterConfigError,
            ),
            ValidatorRegistration(
                "bounded_rate_limit", RateLimitValidator,
                lambda config: True, RateLimitConfigError,
            ),
            ValidatorRegistration(
                "unused_method_exposure", UnusedMethodValidator,
                lambda config: True, MethodEnumerationConfigError,
            ),
            ValidatorRegistration(
                "information_disclosure", InfoDisclosureValidator,
                lambda config: True, InfoDisclosureConfigError,
            ),
            ValidatorRegistration(
                "graphql_introspection", GraphQLValidator,
                lambda config: True, GraphQLConfigError,
            ),
            ValidatorRegistration(
                "safe_injection", SafeInjectionValidator,
                lambda config: bool(config.injection_validation_config_file),
                InjectionConfigError,
            ),
            ValidatorRegistration(
                "session_access_control", AccessControlValidator,
                lambda config: bool(config.access_validation_config_file),
                AccessControlConfigError,
            ),
        )
