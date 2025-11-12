"""Detect Azure storage containers allowing anonymous writes."""

from __future__ import annotations

from collections.abc import Mapping

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseAzureProducer


@register_producer
class AzureStoragePublicWriteProducer(BaseAzureProducer):
    """Flags blob containers with public write access."""

    @property
    def resource_types(self) -> set[str]:
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
        context: Mapping[str, object] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        public_access = normalized.get("public_access")
        allow_account_public = normalized.get("allow_blob_public_access")

        if public_access not in {"container", "blob"}:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

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
                "Azure storage container "
                f"{resource.name} is publicly accessible and allows anonymous "
                "write operations."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
