"""Detect public write access to storage buckets."""

from __future__ import annotations

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import coerce_mapping, resolve_rule_id

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
            "Block public access, restrict bucket policies, and remove ACL entries "
            "that grant write access to AllUsers or AuthenticatedUsers groups."
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        policy_allows_write = bool(normalized.get("policyAllowsPublicWrite", False))
        acl_allows_write = bool(normalized.get("aclAllowsPublicWrite", False))
        block_public_access = coerce_mapping(normalized.get("blockPublicAccess")) or {}
        block_public_access_effective = block_public_access.get("effective", True)

        if not policy_allows_write and not acl_allows_write:
            return findings

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = {
            "bucket": resource.external_id,
            "region": normalized.get("region"),
            "policy_allows_public_write": policy_allows_write,
            "acl_allows_public_write": acl_allows_write,
            "block_public_access": block_public_access,
            "policy_summary": coerce_mapping(normalized.get("policy")) or {},
            "acl_summary": coerce_mapping(normalized.get("acl")) or {},
        }

        severity = self.severity if block_public_access_effective else Severity.CRITICAL

        bucket_label = resource.name or resource.external_id
        vector_text = _summarize_vectors(policy_allows_write, acl_allows_write)

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"S3 bucket {bucket_label} permits anonymous writes",
            summary=(
                f"Bucket {bucket_label} grants public write access via {vector_text}."
            ),
            evidence=evidence,
            severity=severity,
        )

        findings.append(finding)
        return findings


def _summarize_vectors(policy_allows_write: bool, acl_allows_write: bool) -> str:
    vectors: list[str] = []
    if policy_allows_write:
        vectors.append("bucket policy")
    if acl_allows_write:
        vectors.append("bucket ACL")
    return " and ".join(vectors) if vectors else "unspecified configuration"
