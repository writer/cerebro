"""Producer for detecting GCP projects without audit logging."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseGCPProducer


@register_producer
class GCPLoggingDisabledProducer(BaseGCPProducer):
    """Detect GCP projects/resources without proper audit logging."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.project", "gcp.logging.sink", "gcp.iam.audit_config"}

    @property
    def finding_name(self) -> str:
        return "GCP: Audit Logging Not Configured"

    @property
    def rule_name(self) -> str:
        return "gcp_logging_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "GCP audit logging is not properly configured for the project."

    @property
    def remediation(self) -> str:
        return (
            "Enable Data Access audit logs for all services. "
            "Configure log sinks for long-term retention. "
            "Export logs to Cloud Storage or BigQuery."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AU-2", "AU-3", "AU-12"],
            "cwe": ["CWE-778"],
            "cis_gcp": ["2.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate audit logging configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check audit configs
        audit_configs = data.get("audit_configs", []) or []
        data_access_enabled = False

        for config_entry in audit_configs:
            if isinstance(config_entry, dict):
                audit_log_configs = config_entry.get("audit_log_configs", [])
                for log_config in audit_log_configs:
                    if isinstance(log_config, dict):
                        log_type = log_config.get("log_type", "")
                        if "DATA" in log_type.upper():
                            data_access_enabled = True
                            break

        # Check for log sinks
        sinks = data.get("sinks", []) or []

        if data_access_enabled and sinks:
            return findings

        risk_factors: list[str] = []
        if not data_access_enabled:
            risk_factors.append("data_access_logs_disabled")
        if not sinks:
            risk_factors.append("no_log_sinks")

        evidence = {
            "project_id": data.get("project_id") or resource.external_id,
            "data_access_logs_enabled": data_access_enabled,
            "audit_configs_count": len(audit_configs),
            "sinks_count": len(sinks),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Audit logging not properly configured for {data.get('project_id', resource.name)}",
                summary=f"Data access logs: {data_access_enabled}. Log sinks: {len(sinks)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
