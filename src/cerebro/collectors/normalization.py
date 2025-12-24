"""Declarative normalization utilities for ingestion connectors."""

from __future__ import annotations

_NORMALIZATION_CONFIG: dict[str, dict[str, dict[str, str]]] = {
    "severity": {
        "default": {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
            "info": "informational",
            "informational": "informational",
            "warning": "medium",
            "unknown": "unknown",
        },
        "github": {
            "error": "high",
            "critical": "critical",
            "high": "high",
            "moderate": "medium",
            "medium": "medium",
            "low": "low",
        },
        "aws": {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        },
    },
    "exposure": {
        "default": {
            "public": "public",
            "external": "public",
            "internet": "public",
            "internal": "internal",
            "private": "internal",
            "restricted": "restricted",
            "confidential": "restricted",
            "unknown": "unknown",
        }
    },
}


def _normalize(category: str, value: str | None, provider: str) -> str:
    if not value:
        return "unknown"

    lowered = value.lower().strip()
    provider_mappings = _NORMALIZATION_CONFIG.get(category, {})
    provider_rules = provider_mappings.get(provider, {})
    default_rules = provider_mappings.get("default", {})

    return provider_rules.get(lowered) or default_rules.get(lowered, "unknown")


def normalize_severity(value: str | None, *, provider: str) -> str:
    """Normalize a provider-provided severity label into Cerebro's taxonomy."""

    return _normalize("severity", value, provider)


def normalize_exposure(value: str | None, *, provider: str) -> str:
    """Normalize a provider-provided exposure label."""

    return _normalize("exposure", value, provider)


__all__ = ["normalize_exposure", "normalize_severity"]
