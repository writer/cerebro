"""Producer for detecting Azure Key Vault without logging enabled."""

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

from .base import BaseAzureProducer


@register_producer
class AzureKeyVaultLoggingDisabledProducer(BaseAzureProducer):
    """Detect Azure Key Vault without diagnostic logging enabled.

    Key Vault logging is critical for detecting unauthorized access
    to secrets, keys, and certificates.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"azure.keyvault.vault", "azure.key_vault"}

    @property
    def finding_name(self) -> str:
        return "Azure: Key Vault Logging Disabled"

    @property
    def rule_name(self) -> str:
        return "azure_keyvault_logging_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Azure Key Vault does not have diagnostic logging enabled. "
            "Without logging, unauthorized access attempts cannot be detected."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable diagnostic settings for the Key Vault. "
            "Send logs to Log Analytics workspace or Storage Account. "
            "Enable both AuditEvent and AllMetrics categories."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AU-2", "AU-3", "AU-6"],
            "cwe": ["CWE-778"],
            "cis_azure": ["5.1.5"],
            "mitre_attack": ["T1552.004"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Key Vault for logging configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check diagnostic settings
        diagnostic_settings = data.get("diagnostic_settings", []) or []

        # Check if logging is enabled
        logging_enabled = False
        audit_events_enabled = False
        log_destinations: list[str] = []

        for setting in diagnostic_settings:
            if not isinstance(setting, dict):
                continue

            # Check for enabled logs
            logs = setting.get("logs", []) or []
            for log in logs:
                if isinstance(log, dict):
                    category = log.get("category", "").lower()
                    enabled = log.get("enabled", False)
                    if enabled and category == "auditevent":
                        audit_events_enabled = True
                        logging_enabled = True

            # Track destinations
            if setting.get("workspace_id"):
                log_destinations.append("log_analytics")
            if setting.get("storage_account_id"):
                log_destinations.append("storage_account")
            if setting.get("event_hub_authorization_rule_id"):
                log_destinations.append("event_hub")

        # Also check for logging_enabled flag if present
        if data.get("logging_enabled"):
            logging_enabled = True

        # Create finding if logging is not properly configured
        if logging_enabled and audit_events_enabled:
            return findings

        # Build risk factors
        risk_factors: list[str] = []

        if not logging_enabled:
            risk_factors.append("no_diagnostic_settings")
        elif not audit_events_enabled:
            risk_factors.append("audit_events_not_enabled")

        if not log_destinations:
            risk_factors.append("no_log_destination")

        # Check for soft delete and purge protection
        soft_delete_enabled = data.get("soft_delete_enabled", False)
        purge_protection_enabled = data.get("purge_protection_enabled", False)

        if not soft_delete_enabled:
            risk_factors.append("soft_delete_disabled")
        if not purge_protection_enabled:
            risk_factors.append("purge_protection_disabled")

        evidence = {
            "vault_name": resource.name,
            "vault_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "location": data.get("location"),
            "logging_enabled": logging_enabled,
            "audit_events_enabled": audit_events_enabled,
            "log_destinations": log_destinations,
            "diagnostic_settings_count": len(diagnostic_settings),
            "soft_delete_enabled": soft_delete_enabled,
            "purge_protection_enabled": purge_protection_enabled,
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Key Vault {resource.name} does not have logging enabled",
                summary=(
                    f"Audit events: {'enabled' if audit_events_enabled else 'disabled'}. "
                    f"Destinations: {', '.join(log_destinations) if log_destinations else 'none'}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
