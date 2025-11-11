"""Detect Azure storage containers allowing anonymous writes."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseAzureProducer


@register_producer
class AzureStoragePublicWriteProducer(BaseAzureProducer):
    """Flags blob containers with public write access."""

    @property
    def resource_types(self) -> Set[str]:
        return {"azure.storage.container"}

    @property
    def finding_name(self) -> str:
        return "Azure: Storage container allows anonymous write"

    @property
    def rule_name(self) -> str:
        return "azure_storage_container_public_write"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Azure Blob container configured with public write access"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, object]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config
        public_access = normalized.get("public_access")
        allow_account_public = normalized.get("allow_blob_public_access")

        if public_access not in {"container", "blob"}:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "container": resource.name,
            "account_name": normalized.get("account_name"),
            "resource_group": normalized.get("resource_group"),
            "public_access": public_access,
            "allow_account_public_access": allow_account_public,
            "signed_identifiers": normalized.get("signed_identifiers", []),
            "network_rules": normalized.get("network_rules"),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Container {resource.name} allows public write access",
            summary=(
                f"Azure storage container {resource.name} is publicly accessible and allows anonymous write operations."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
