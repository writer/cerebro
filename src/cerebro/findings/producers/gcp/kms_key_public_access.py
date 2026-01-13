"""Producer for detecting publicly accessible GCP KMS keys."""

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
class GCPKMSKeyPublicAccessProducer(BaseGCPProducer):
    """Detect GCP KMS keys with public access (allUsers or allAuthenticatedUsers)."""

    @property
    def resource_types(self) -> set[str]:
        return {"gcp.kms.cryptokey", "gcp.kms.key"}

    @property
    def finding_name(self) -> str:
        return "GCP: KMS Key Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "gcp_kms_key_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "GCP KMS key is accessible to allUsers or allAuthenticatedUsers."

    @property
    def remediation(self) -> str:
        return (
            "Remove allUsers and allAuthenticatedUsers from the key's IAM policy. "
            "Restrict access to specific service accounts or users."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "SC-12"],
            "cwe": ["CWE-284"],
            "cis_gcp": ["1.9"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate KMS key for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        members = data.get("members", []) or data.get("iam_members", []) or []
        bindings = data.get("iam_bindings", []) or []

        # Collect all members from bindings
        all_members: list[str] = list(members)
        for binding in bindings:
            if isinstance(binding, dict):
                all_members.extend(binding.get("members", []))

        public_members = [m for m in all_members if m in ("allUsers", "allAuthenticatedUsers")]

        if not public_members:
            return findings

        evidence = {
            "key_name": resource.name,
            "key_id": resource.external_id,
            "project_id": data.get("project_id"),
            "key_ring": data.get("key_ring"),
            "location": data.get("location"),
            "public_members": public_members,
            "rotation_period": data.get("rotation_period"),
            "primary_state": data.get("primary", {}).get("state"),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"KMS key {resource.name} is publicly accessible",
                summary=f"Public members: {', '.join(public_members)}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
