"""Utilities for reasoning about finding severity."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cerebro.domain.entities import Severity

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def exposures_contain_public(
    exposures: Iterable[Mapping[str, Any]] | None,
) -> bool:
    """Return ``True`` when any exposure dictionary represents public access."""

    if not exposures:
        return False

    for exposure in exposures:
        if exposure.get("public") is True:
            return True

        public_targets = exposure.get("publicTargets")
        if isinstance(public_targets, Iterable) and any(public_targets):
            return True

        public_instances = exposure.get("publicInstances")
        if isinstance(public_instances, Iterable) and any(public_instances):
            return True

    return False


def exposures_contain_type(
    exposures: Iterable[Mapping[str, Any]] | None,
    exposure_type: str,
) -> bool:
    """Return ``True`` when any exposure dictionary has the requested type."""

    if not exposures:
        return False

    for exposure in exposures:
        if exposure.get("type") == exposure_type:
            return True
    return False


def downgrade_severity_for_namespace_policy(
    severity: Severity,
    *,
    namespace_posture: Mapping[str, Any] | None,
    when: Severity,
    downgrade_to: Severity,
    require_ingress_default_deny: bool = True,
    require_egress_default_deny: bool = False,
) -> Severity:
    """Downgrade severity when namespace network policy guards are present."""

    if severity != when or not namespace_posture:
        return severity

    if require_ingress_default_deny and not namespace_posture.get(
        "default_deny_ingress"
    ):
        return severity

    if require_egress_default_deny and not namespace_posture.get("default_deny_egress"):
        return severity

    return downgrade_to


def max_severity(*severities: Severity) -> Severity:
    """Return the highest severity level from the provided values."""

    if not severities:
        return Severity.INFO

    return max(severities, key=lambda value: _SEVERITY_ORDER.get(value, 0))
