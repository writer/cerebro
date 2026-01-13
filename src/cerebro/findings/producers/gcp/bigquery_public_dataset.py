"""Producer for detecting publicly accessible BigQuery datasets."""

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
class GCPBigQueryPublicDatasetProducer(BaseGCPProducer):
    """Detect BigQuery datasets with public access."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.bigquery.dataset"}

    @property
    def finding_name(self) -> str:
        return "GCP: BigQuery Dataset Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "gcp_bigquery_public_dataset"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "BigQuery dataset is accessible to allUsers or allAuthenticatedUsers."

    @property
    def remediation(self) -> str:
        return (
            "Remove allUsers and allAuthenticatedUsers from the dataset's access list. "
            "Use specific IAM bindings for authorized access."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-6"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_gcp": ["7.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate BigQuery dataset for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        access = data.get("access", []) or []
        iam_bindings = data.get("iam_bindings", []) or []

        public_access: list[dict[str, Any]] = []

        # Check access entries
        for entry in access:
            if not isinstance(entry, dict):
                continue
            special_group = entry.get("specialGroup", "")
            iam_member = entry.get("iamMember", "")
            if special_group in ("allUsers", "allAuthenticatedUsers"):
                public_access.append({"type": "specialGroup", "value": special_group, "role": entry.get("role")})
            if iam_member in ("allUsers", "allAuthenticatedUsers"):
                public_access.append({"type": "iamMember", "value": iam_member, "role": entry.get("role")})

        # Check IAM bindings
        for binding in iam_bindings:
            if not isinstance(binding, dict):
                continue
            members = binding.get("members", [])
            role = binding.get("role", "")
            for member in members:
                if member in ("allUsers", "allAuthenticatedUsers"):
                    public_access.append({"type": "iam_binding", "value": member, "role": role})

        if not public_access:
            return findings

        evidence = {
            "dataset_id": resource.name,
            "dataset_ref": resource.external_id,
            "project_id": data.get("project_id"),
            "location": data.get("location"),
            "public_access": public_access,
            "default_table_expiration_ms": data.get("default_table_expiration_ms"),
            "labels": data.get("labels"),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"BigQuery dataset {resource.name} is publicly accessible",
                summary=f"Found {len(public_access)} public access entries",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
