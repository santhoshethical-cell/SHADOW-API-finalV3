"""Shared contracts for independently testable security validators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from shadow_api_scanner.core.models import (
    APIEndpoint,
    ValidationResult,
    Vulnerability,
)


class Validator(Protocol):
    """Common asynchronous validator interface."""

    name: str

    async def validate(
        self,
        endpoints: list[APIEndpoint],
    ) -> tuple[list[ValidationResult], list[Vulnerability]]:
        ...


@dataclass
class ValidationBatch:
    """Standard output from the modular validation pipeline."""

    results: list[ValidationResult] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    executed_validators: list[str] = field(default_factory=list)
