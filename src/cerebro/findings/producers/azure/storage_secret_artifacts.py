"""Detect leaked secrets in Azure storage containers."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseAzureProducer

SUSPICIOUS_KEYWORDS = {
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "password",
    "service_account",
    "pem",
    "pfx",
    "p12",
    "ssh",
}

SUSPICIOUS_EXTENSIONS = {
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".json",
    ".env",
    ".ini",
    ".config",
}


def _is_public(normalized: Dict[str, object]) -> bool:
    public_access = normalized.get("public_access")
    if public_access in {"container", "blob"}:
        return True
    return bool(normalized.get("allow_blob_public_access"))


def _is_suspicious(name: Optional[str]) -> bool:
    if not name:
        return False
    lowered = name.lower()
    if any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS):
        return True
    return any(lowered.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


@register_producer
class AzureStorageSecretArtifactProducer(BaseAzureProducer):
    """Flags suspicious credential artifacts in public Azure storage containers."""

    @property
    def resource_types(self) -> Set[str]:
        return {"azure.storage.container"}

    @property
    def finding_name(self) -> str:
        return "Azure: Public container exposes potential secrets"

    @property
    def rule_name(self) -> str:
        return "azure_storage_container_secret_artifacts"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Azure storage container contains files indicative of credentials while publicly accessible"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, object]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config

        if not _is_public(normalized):
            return []

        samples = normalized.get("objectsSample", []) or []
        matches = [obj for obj in samples if _is_suspicious(obj.get("name"))]
        if not matches:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "container": resource.name,
            "account_name": normalized.get("account_name"),
            "resource_group": normalized.get("resource_group"),
            "public_access": normalized.get("public_access"),
            "matched_objects": matches[:10],
            "sample_size": len(samples),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Public container {resource.name} contains potential secrets",
            summary=(
                f"Azure container {resource.name} is publicly accessible and contains objects resembling credentials or API keys."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
