"""Detect GCP Storage buckets allowing anonymous write access."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseGCPProducer


def _binding_allows_public_write(binding: Dict[str, Any]) -> bool:
    members = binding.get("members", [])
    if not any(member in {"allUsers", "allAuthenticatedUsers"} for member in members):
        return False

    role = (binding.get("role") or "").lower()
    writable_roles = {
        "roles/storage.admin",
        "roles/storage.objectadmin",
        "roles/storage.objectcreator",
        "roles/storage.legacybucketwriter",
        "roles/storage.legacyobjectowner",
    }

    if role in writable_roles:
        return True

    if "owner" in role or "writer" in role or "editor" in role:
        return True

    return False


def _acl_allows_public_write(entry: Dict[str, Any]) -> bool:
    entity = entry.get("entity") or entry.get("user")
    if entity not in {"allUsers", "allAuthenticatedUsers"}:
        return False

    role = (entry.get("role") or "").upper()
    return role in {"WRITER", "OWNER", "EDITOR"}


@register_producer
class GCPBucketPublicWriteProducer(BaseGCPProducer):
    """Flags GCS buckets where anonymous principals can write objects."""

    @property
    def resource_types(self) -> Set[str]:
        return {"gcp.storage.bucket"}

    @property
    def finding_name(self) -> str:
        return "GCP: Cloud Storage bucket allows anonymous write"

    @property
    def rule_name(self) -> str:
        return "gcp_storage_bucket_public_write"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Cloud Storage bucket grants public principals permission to write objects"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config

        iam_bindings = normalized.get("iam_bindings")
        if iam_bindings is None:
            iam_bindings = normalized.get("iam", {}).get("bindings", [])

        acl_entries = normalized.get("acl") or normalized.get("access_controls") or []

        public_write = any(_binding_allows_public_write(binding) for binding in iam_bindings)
        if not public_write:
            public_write = any(_acl_allows_public_write(entry) for entry in acl_entries)

        if not public_write:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "bucket": resource.external_id,
            "region": normalized.get("location") or normalized.get("region"),
            "public_access_prevention": normalized.get("public_access_prevention"),
            "uniform_bucket_level_access": normalized.get("uniform_bucket_level_access"),
            "iam_bindings": iam_bindings[:5],
            "acl_entries": acl_entries[:5],
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Bucket {resource.name or resource.external_id} allows public writes",
            summary=(
                f"GCS bucket {resource.name or resource.external_id} grants anonymous principals write access via"
                " IAM policy or ACL permissions."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
