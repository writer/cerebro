"""Detect public write access to storage buckets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseAWSProducer


@register_producer
class StorageWriteAccessProducer(BaseAWSProducer):
    """Flags S3 buckets that allow anonymous write access."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.s3.bucket"}

    @property
    def finding_name(self) -> str:
        return "AWS: S3 bucket allows anonymous write"

    @property
    def rule_name(self) -> str:
        return "aws_s3_bucket_public_write"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Bucket accepts unauthenticated write operations"

    @property
    def remediation(self) -> str:
        return (
            "Block public access, restrict bucket policies, and remove ACL entries that grant write access to"
            " AllUsers or AuthenticatedUsers groups."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Mapping[str, Any] | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        policy_allows_write = normalized.get("policyAllowsPublicWrite", False)
        acl_allows_write = normalized.get("aclAllowsPublicWrite", False)
        block_public_access_effective = normalized.get("blockPublicAccess", {}).get("effective", True)

        if not policy_allows_write and not acl_allows_write:
            return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = {
            "bucket": resource.external_id,
            "region": normalized.get("region"),
            "policy_allows_public_write": policy_allows_write,
            "acl_allows_public_write": acl_allows_write,
            "block_public_access": normalized.get("blockPublicAccess", {}),
            "policy_summary": normalized.get("policy"),
            "acl_summary": normalized.get("acl"),
        }

        severity = self.severity if block_public_access_effective else Severity.CRITICAL

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"S3 bucket {resource.name or resource.external_id} permits anonymous writes",
            summary=(
                f"Bucket {resource.name or resource.external_id} grants public write access via "
                f"{'bucket policy' if policy_allows_write else ''}"
                f"{' and ' if policy_allows_write and acl_allows_write else ''}"
                f"{'bucket ACL' if acl_allows_write else ''}."
            ),
            evidence=evidence,
            severity=severity,
        )

        findings.append(finding)
        return findings
