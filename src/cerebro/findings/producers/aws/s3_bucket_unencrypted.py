"""Producer for detecting unencrypted S3 buckets."""

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
class S3BucketUnencryptedProducer(BaseAWSProducer):
    """Detects S3 buckets without default encryption enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.s3.bucket"}

    @property
    def finding_name(self) -> str:
        return "AWS: S3 Bucket Without Encryption"

    @property
    def rule_name(self) -> str:
        return "aws_s3_bucket_unencrypted"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "S3 bucket does not have default encryption enabled"

    @property
    def remediation(self) -> str:
        return (
            "Enable default encryption (AES-256 or AWS KMS) on the bucket to "
            "protect data at rest."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["2.1.1"],
            "nist_800_53": ["SC-28", "SC-13"],
            "pci_dss": ["3.4"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate S3 bucket encryption configuration."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        encryption = coerce_mapping(normalized.get("encryption")) or {}
        encryption_enabled = bool(encryption.get("enabled", False))

        versioning = coerce_mapping(normalized.get("versioning")) or {}
        versioning_enabled = bool(versioning.get("enabled", False))

        policy_allows_public = bool(normalized.get("policyAllowsPublic", False))
        acl_allows_public = bool(normalized.get("aclAllowsPublic", False))
        is_public = policy_allows_public or acl_allows_public

        if not encryption_enabled:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            risk_factors: list[str] = []
            if is_public:
                risk_factors.append("publicly_accessible")
            if versioning_enabled:
                risk_factors.append("versioning_enabled")
            logging_config = coerce_mapping(normalized.get("logging")) or {}
            if not logging_config.get("enabled", False):
                risk_factors.append("no_access_logging")

            bucket_name = resource.name or resource.external_id
            block_public = coerce_mapping(normalized.get("blockPublicAccess")) or {}

            evidence = {
                "bucket_name": bucket_name,
                "bucket_arn": f"arn:aws:s3:::{bucket_name}",
                "region": normalized.get("region"),
                "encryption": encryption,
                "versioning": versioning,
                "public_access": {
                    "policy_allows_public": policy_allows_public,
                    "acl_allows_public": acl_allows_public,
                    "block_public_access": block_public,
                },
                "risk_factors": risk_factors,
                "logging": logging_config,
                "lifecycle_policy": normalized.get("lifecycle", {}),
                "creation_date": normalized.get("creation_date"),
            }

            severity = Severity.HIGH if is_public else self.severity

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=(
                    "S3 bucket "
                    f"{bucket_name} is not encrypted"
                ),
                summary=(
                    "S3 bucket "
                    f"{bucket_name} lacks default encryption. Risk factors: "
                    f"{', '.join(risk_factors) if risk_factors else 'None'}"
                ),
                evidence=evidence,
                severity=severity,
            )
            findings.append(finding)

        return findings
