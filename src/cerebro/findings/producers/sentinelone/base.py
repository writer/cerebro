"""Shared helpers for SentinelOne finding producers."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional, Set
from uuid import UUID

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.base import BaseFindingProducer


class BaseSentinelOneProducer(BaseFindingProducer):
    """Base class providing helpers for SentinelOne threat producers."""

    @property
    def desired_sources(self) -> Set[str]:
        return {"endpoint"}

    @property
    def resource_types(self) -> Set[str]:
        return {"endpoint.device"}

    def _resolve_rule_id(self, context: Optional[Dict[str, Any]]) -> UUID:
        if context and context.get("rule_id"):
            return context["rule_id"]
        from cerebro.rules.rule_service import get_rule_by_name_sync

        return get_rule_by_name_sync(self.rule_name)

    def _extract_threats(self, config: ConfigEntity) -> List[Dict[str, Any]]:
        threats = config.normalized_config.get("threats", [])
        return [threat for threat in threats if isinstance(threat, dict)]

    def _is_active_threat(self, threat: Dict[str, Any]) -> bool:
        status = str(threat.get("status", "")).lower()
        mitigation = str(threat.get("mitigation_status", "")).lower()
        verdict = str(threat.get("analyst_verdict", "")).lower()
        resolved_at = threat.get("resolved_at")

        resolved_tokens = {"resolved", "mitigated", "dismissed", "benign", "false_positive"}

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
        evidence: Dict[str, Any],
    ) -> FindingEntity:
        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=title,
            summary=summary,
            evidence=evidence,
            severity=severity,
        )
        fingerprint_material = f"{rule_id}|{resource.external_id}|{threat_id}|{self.rule_name}"
        finding.fingerprint = hashlib.sha256(fingerprint_material.encode()).hexdigest()
        return finding

    @staticmethod
    def _map_severity(value: Optional[str]) -> Severity:
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
    def _comma_join(values: Iterable[Any]) -> Optional[str]:
        cleaned = [str(item) for item in values if item not in (None, "")]
        return ", ".join(cleaned) if cleaned else None
