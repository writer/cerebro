"""Detect suspicious secret artifacts exposed in public GCS buckets."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseGCPProducer

SUSPICIOUS_KEYWORDS = {
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "password",
    "service_account",
    "pem",
    "p12",
    "ssh",
}

SUSPICIOUS_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".json",
    ".env",
    ".ini",
    ".tfvars",
}


def _is_public(normalized: Dict[str, Any]) -> bool:
    if normalized.get("is_public"):
        return True
    public_prevention = normalized.get("public_access_prevention")
    if isinstance(public_prevention, str) and public_prevention.lower() == "enforced":
        return False
    return normalized.get("uniform_bucket_level_access", {}).get("enabled") is False


def _iter_object_keys(normalized: Dict[str, Any]) -> List[Dict[str, Any]]:
    objects = normalized.get("objectsSample") or normalized.get("objects") or []
    if isinstance(objects, dict):
        # flatten dictionaries keyed by object names
        return [
            {"key": key, **(value if isinstance(value, dict) else {"size": value})}
            for key, value in objects.items()
        ]
    return [obj for obj in objects if isinstance(obj, dict)]


def _is_suspicious(key: Optional[str]) -> bool:
    if not key:
        return False
    lowered = key.lower()
    if any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS):
        return True
    return any(lowered.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


@register_producer
class GCPBucketSecretArtifactProducer(BaseGCPProducer):
    """Flags suspicious credential artifacts within publicly exposed GCS buckets."""

    @property
    def resource_types(self) -> Set[str]:
        return {"gcp.storage.bucket"}

    @property
    def finding_name(self) -> str:
        return "GCP: Public bucket exposes potential secrets"

    @property
    def rule_name(self) -> str:
        return "gcp_storage_bucket_secret_artifacts"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Cloud Storage bucket contains files indicative of credentials while accessible publicly"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config

        if not _is_public(normalized):
            return []

        objects = _iter_object_keys(normalized)
        matches = [obj for obj in objects if _is_suspicious(obj.get("key"))]
        if not matches:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "bucket": resource.external_id,
            "region": normalized.get("location") or normalized.get("region"),
            "matched_objects": matches[:10],
            "total_objects_sampled": len(objects),
            "public_access_prevention": normalized.get("public_access_prevention"),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Public bucket {resource.name or resource.external_id} exposes suspicious files",
            summary=(
                f"GCS bucket {resource.name or resource.external_id} is publicly accessible and contains objects"
                " that resemble credentials or API keys."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
