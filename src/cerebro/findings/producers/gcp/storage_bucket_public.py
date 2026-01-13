"""Producer for detecting publicly accessible GCP Storage buckets."""

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
class GCPStorageBucketPublicProducer(BaseGCPProducer):
    """Detect Cloud Storage buckets with public access."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.storage.bucket", "gcp.cloudstorage.bucket"}

    @property
    def finding_name(self) -> str:
        return "GCP: Storage Bucket Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "gcp_storage_bucket_public"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Cloud Storage bucket is accessible to allUsers or allAuthenticatedUsers."

    @property
    def remediation(self) -> str:
        return (
            "Remove allUsers and allAuthenticatedUsers from bucket IAM policy. "
            "Enable uniform bucket-level access. "
            "Use signed URLs for controlled public access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-6"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_gcp": ["5.1"],
            "mitre_attack": ["T1530"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate storage bucket for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check IAM bindings
        iam_bindings = data.get("iam_configuration", {}).get("bindings", []) or []
        if not iam_bindings:
            iam_bindings = data.get("iam_bindings", []) or []

        public_bindings: list[dict[str, Any]] = []

        for binding in iam_bindings:
            if not isinstance(binding, dict):
                continue
            members = binding.get("members", [])
            role = binding.get("role", "")

            public_members = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
            if public_members:
                public_bindings.append({
                    "role": role,
                    "public_members": public_members,
                })

        # Also check ACLs
        acl = data.get("acl", []) or []
        for entry in acl:
            if isinstance(entry, dict):
                entity = entry.get("entity", "")
                if entity in ("allUsers", "allAuthenticatedUsers"):
                    public_bindings.append({
                        "role": entry.get("role"),
                        "public_members": [entity],
                        "source": "acl",
                    })

        if not public_bindings:
            return findings

        # Check bucket settings
        uniform_access = data.get("iam_configuration", {}).get("uniform_bucket_level_access", {}).get("enabled", False)
        versioning = data.get("versioning", {}).get("enabled", False)
        encryption = data.get("encryption", {})

        risk_factors: list[str] = ["public_access"]
        if not uniform_access:
            risk_factors.append("uniform_access_disabled")
        if not versioning:
            risk_factors.append("versioning_disabled")

        evidence = {
            "bucket_name": resource.name,
            "bucket_id": resource.external_id,
            "project_id": data.get("project_id"),
            "location": data.get("location"),
            "public_bindings": public_bindings,
            "uniform_bucket_level_access": uniform_access,
            "versioning_enabled": versioning,
            "default_kms_key": encryption.get("default_kms_key_name"),
            "storage_class": data.get("storage_class"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Storage bucket {resource.name} is publicly accessible",
                summary=f"Found {len(public_bindings)} public access bindings",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
