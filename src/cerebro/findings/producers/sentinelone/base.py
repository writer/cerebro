"""Shared helpers for SentinelOne finding producers."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any
from uuid import UUID

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import BaseFindingProducer, ProducerContext
from cerebro.findings.producers.utils import coerce_mapping_sequence, resolve_rule_id


class BaseSentinelOneProducer(BaseFindingProducer):
    """Base class providing helpers for SentinelOne threat producers."""

    @property
    def desired_sources(self) -> set[str]:
        return {"endpoint"}

    @property
    def resource_types(self) -> set[str]:
        return {"endpoint.device"}

    def _resolve_rule_id(self, context: ProducerContext | None) -> UUID:
        return resolve_rule_id(rule_name=self.rule_name, context=context)

    def _extract_threats(self, config: ConfigEntity) -> list[dict[str, Any]]:
        threats = coerce_mapping_sequence(
            (config.normalized_config or {}).get("threats")
        )
        return [dict(threat) for threat in threats]

    def _is_active_threat(self, threat: Mapping[str, Any]) -> bool:
        status = str(threat.get("status", "")).lower()
        mitigation = str(threat.get("mitigation_status", "")).lower()
        verdict = str(threat.get("analyst_verdict", "")).lower()
        resolved_at = threat.get("resolved_at")

        resolved_tokens = {
            "resolved",
            "mitigated",
            "dismissed",
            "benign",
            "false_positive",
        }

        if resolved_at:
            return False
        if any(token in status for token in resolved_tokens):
            return False
        if any(token in mitigation for token in resolved_tokens):
            return False
        if verdict in {"benign", "false_positive", "expected_behavior"}:
            return False
        return True

    def _create_threat_finding(
        self,
        *,
        resource: ResourceEntity,
        rule_id: UUID,
        threat_id: str,
        title: str,
        summary: str,
        severity: Severity,
        evidence: dict[str, Any],
    ) -> FindingEntity:
        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=title,
            summary=summary,
            evidence=evidence,
            severity=severity,
        )
        fingerprint_material = (
            f"{rule_id}|{resource.external_id}|{threat_id}|{self.rule_name}"
        )
        finding.fingerprint = hashlib.sha256(fingerprint_material.encode()).hexdigest()
        return finding

    @staticmethod
    def _map_severity(value: str | None) -> Severity:
        if not value:
            return Severity.HIGH
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "moderate": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(str(value).lower(), Severity.HIGH)

    @staticmethod
    def _comma_join(values: Iterable[Any]) -> str | None:
        cleaned = [str(item) for item in values if item not in (None, "")]
        return ", ".join(cleaned) if cleaned else None
