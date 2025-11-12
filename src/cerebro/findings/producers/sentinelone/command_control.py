"""Finding producer for SentinelOne command-and-control detections."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer

from .base import BaseSentinelOneProducer

ContextData = Mapping[str, Any]
ThreatData = Mapping[str, Any]


@register_producer
class SentinelOneCommandControlProducer(BaseSentinelOneProducer):
    """Create findings when SentinelOne reports command-and-control activity."""

    @property
    def finding_name(self) -> str:
        return "SentinelOne: Command and Control Activity"

    @property
    def rule_name(self) -> str:
        return "sentinelone_command_control_activity"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "SentinelOne detected potential command-and-control communications"

    @property
    def remediation(self) -> str:
        return (
            "Isolate the endpoint, block the identified C2 infrastructure, and "
            "perform full eradication"
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-7", "SI-4"],
            "cis": ["13.10"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ContextData | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        threats = self._extract_threats(config)
        if not threats:
            return findings

        rule_id = self._resolve_rule_id(context)

        for threat in threats:
            threat_id = threat.get("threat_id")
            if not threat_id:
                continue
            if not self._is_active_threat(threat):
                continue
            if not self._has_c2_indicator(threat):
                continue

            severity = self._map_severity(threat.get("severity"))
            title = self._build_title(resource, threat)
            summary = self._build_summary(resource, threat)
            evidence = self._build_evidence(threat)

            findings.append(
                self._create_threat_finding(
                    resource=resource,
                    rule_id=rule_id,
                    threat_id=str(threat_id),
                    title=title,
                    summary=summary,
                    severity=severity,
                    evidence=evidence,
                )
            )

        return findings

    def _has_c2_indicator(self, threat: ThreatData) -> bool:
        categories = {str(cat).lower() for cat in threat.get("categories", []) if cat}
        tactics = {str(tac).lower() for tac in threat.get("mitre_tactics", []) if tac}
        domains = threat.get("c2_domains") or []

        if domains:
            return True
        if categories & {"command and control", "c2", "exfiltration"}:
            return True
        if any("command" in tactic for tactic in tactics):
            return True
        return False

    def _build_title(self, resource: ResourceEntity, threat: ThreatData) -> str:
        host_name = resource.name or resource.external_id
        indicator = threat.get("c2_domains", ["unknown destination"])[0]
        return (
            "SentinelOne observed command-and-control traffic from "
            f"{host_name} to {indicator}"
        )

    def _build_summary(self, resource: ResourceEntity, threat: ThreatData) -> str:
        host_name = resource.name or resource.external_id
        domains = threat.get("c2_domains") or []
        domain_text = ", ".join(domains) if domains else "unknown destinations"
        detected_at = threat.get("detected_at")
        parts = [
            f"SentinelOne identified possible C2 communication targeting {domain_text}",
        ]
        if detected_at:
            parts.append(f"detected at {detected_at}")
        return f"{', '.join(parts)} from {host_name}."

    def _build_evidence(self, threat: ThreatData) -> dict[str, Any]:
        return {
            "classification": threat.get("classification"),
            "confidence": threat.get("confidence"),
            "severity": threat.get("severity"),
            "status": threat.get("status"),
            "mitigation_status": threat.get("mitigation_status"),
            "detected_at": threat.get("detected_at"),
            "c2_domains": threat.get("c2_domains"),
            "source_ips": threat.get("source_ips"),
            "mitre_tactics": threat.get("mitre_tactics"),
            "mitre_techniques": threat.get("mitre_techniques"),
            "indicators": threat.get("indicators"),
        }
