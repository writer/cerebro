"""Secret validation heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cerebro.telemetry.schemas import SecretsScanResult

from .catalog import SecretDescriptor, SecretFamily, identify_secret_family


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating a detected secret."""

    family: SecretFamily
    status: str
    confidence: float
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _extract_candidate_value(raw_result: dict[str, Any] | None) -> str:
    if not raw_result:
        return ""

    for key in ("redacted", "Redacted", "raw", "Raw", "secret", "Secret"):
        value = raw_result.get(key)
        if isinstance(value, str):
            return value
    return ""


def _pattern_matches(descriptor: SecretDescriptor, candidate: str) -> bool:
    return any(pattern.search(candidate) for pattern in descriptor.patterns)


def validate_secret_payload(secret: SecretsScanResult) -> ValidationResult:
    """Validate a secret detection payload."""

    descriptor = identify_secret_family(secret.secret_type, secret.raw_result)

    if secret.verified:
        return ValidationResult(
            family=descriptor.family,
            status="verified",
            confidence=0.95,
            reason="Source scanner verified secret via active check.",
            metadata={"detector": secret.detector_name},
        )

    candidate = _extract_candidate_value(secret.raw_result)
    if candidate and _pattern_matches(descriptor, candidate):
        return ValidationResult(
            family=descriptor.family,
            status="format_match",
            confidence=0.7,
            reason="Secret matches expected format for family.",
            metadata={
                "example": candidate[:12] + "…" if len(candidate) > 12 else candidate
            },
        )

    if descriptor.family is SecretFamily.GENERIC:
        return ValidationResult(
            family=descriptor.family,
            status="unknown",
            confidence=0.3,
            reason="Secret type unclassified; further review required.",
            metadata={},
        )

    if secret.secret_type:
        return ValidationResult(
            family=descriptor.family,
            status="inferred",
            confidence=0.5,
            reason="Secret inferred from scanner metadata but not format verified.",
            metadata={"detector": secret.detector_name},
        )

    return ValidationResult(
        family=descriptor.family,
        status="unknown",
        confidence=0.2,
        reason="Unable to validate secret format.",
        metadata={},
    )
