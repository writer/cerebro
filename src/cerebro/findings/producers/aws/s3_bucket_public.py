"""Producer for detecting publicly accessible S3 buckets."""

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
class S3BucketPublicProducer(BaseAWSProducer):
    """Detects publicly accessible S3 buckets."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.s3.bucket"}

    @property
    def finding_name(self) -> str:
        return "AWS: S3 Bucket Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_s3_bucket_public"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "S3 bucket allows public read or write access"

    @property
    def remediation(self) -> str:
        return (
            "Enable S3 block public access settings and review bucket policies "
            "and ACLs for anonymous permissions."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["2.1.1", "2.1.5"],
            "nist_800_53": ["AC-3", "AC-4"],
            "cwe": ["CWE-200"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate S3 bucket for public access."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        policy_allows_public = bool(normalized.get("policyAllowsPublic", False))
        acl_allows_public = bool(normalized.get("aclAllowsPublic", False))
        block_public_config = coerce_mapping(normalized.get("blockPublicAccess")) or {}
        block_public_disabled = not block_public_config.get("effective", True)

        is_public = policy_allows_public or acl_allows_public or block_public_disabled

        if is_public:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            access_vectors: list[str] = []
            if policy_allows_public:
                access_vectors.append("bucket_policy")
            if acl_allows_public:
                access_vectors.append("bucket_acl")
            if block_public_disabled:
                access_vectors.append("block_public_access_disabled")

            bucket_name = resource.name or resource.external_id
            bucket_policy = coerce_mapping(normalized.get("policy")) or {}
            bucket_acl = coerce_mapping(normalized.get("acl")) or {}

            evidence = {
                "bucket_name": bucket_name,
                "bucket_arn": f"arn:aws:s3:::{bucket_name}",
                "region": normalized.get("region"),
                "access_vectors": access_vectors,
                "policy_analysis": {
                    "policy_allows_public": policy_allows_public,
                    "acl_allows_public": acl_allows_public,
                    "block_public_access": block_public_config,
                },
                "bucket_policy": bucket_policy,
                "bucket_acl": bucket_acl,
                "creation_date": normalized.get("creation_date"),
                "encryption": normalized.get("encryption", {}),
                "versioning": normalized.get("versioning", {}),
                "logging": normalized.get("logging", {}),
            }

            severity = self.severity
            if policy_allows_public and "s3:GetObject" in str(bucket_policy):
                severity = Severity.CRITICAL

            vector_list = ", ".join(access_vectors) or "unspecified configuration"

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"S3 bucket {bucket_name} is publicly accessible",
                summary=(
                    f"S3 bucket {bucket_name} allows public access via {vector_list}"
                ),
                evidence=evidence,
                severity=severity,
            )
            findings.append(finding)

        return findings
