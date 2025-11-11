"""Detect cleartext keys or credentials in public S3 buckets."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseAWSProducer


SUSPICIOUS_KEYWORDS = {
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "password",
    "ssh",
    "pem",
    "p12",
    "key",
}

SUSPICIOUS_EXTENSIONS = {".pem", ".key", ".pfx", ".p12", ".env", ".ini", ".json"}


def _is_suspicious_key(key: Optional[str]) -> bool:
    if not key:
        return False
    lowered = key.lower()
    if any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS):
        return True
    for ext in SUSPICIOUS_EXTENSIONS:
        if lowered.endswith(ext):
            return True
    return False


@register_producer
class BucketCleartextKeyProducer(BaseAWSProducer):
    """Detects suspicious credential artefacts in publicly exposed buckets."""

    @property
    def resource_types(self) -> Set[str]:
        return {"aws.s3.bucket"}

    @property
    def finding_name(self) -> str:
        return "AWS: Sensitive secrets stored in public bucket"

    @property
    def rule_name(self) -> str:
        return "aws_s3_bucket_cleartext_secrets"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "Sensitive credentials detected in a publicly accessible S3 bucket"

    @property
    def remediation(self) -> str:
        return (
            "Remove the exposed objects and rotate affected credentials."
            " Enforce block public access or move secrets to a dedicated secret manager."
        )

    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        base = dict(super().framework_mappings)
        base.update({
            "cwe": ["CWE-200", "CWE-522"],
        })
        return base

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[FindingEntity]:
        findings: List[FindingEntity] = []

        normalized = config.normalized_config
        objects_sample = normalized.get("objectsSample", [])
        if not objects_sample:
            return findings

        matches = [obj for obj in objects_sample if _is_suspicious_key(obj.get("key"))]
        if not matches:
            return findings

        is_public = (
            normalized.get("policyAllowsPublic", False)
            or normalized.get("aclAllowsPublic", False)
            or not normalized.get("blockPublicAccess", {}).get("effective", True)
        )

        if not is_public:
            return findings

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "bucket": resource.external_id,
            "region": normalized.get("region"),
            "matched_objects": matches[:10],
            "public_access": {
                "policy_allows_public": normalized.get("policyAllowsPublic"),
                "acl_allows_public": normalized.get("aclAllowsPublic"),
                "block_public_access": normalized.get("blockPublicAccess", {}),
            },
            "object_sample_size": len(objects_sample),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Public bucket {resource.name or resource.external_id} contains potential secrets",
            summary=
            (
                f"S3 bucket {resource.name or resource.external_id} is publicly accessible and contains files "
                f"indicative of credentials or API keys."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        finding.fingerprint = self._build_fingerprint(rule_id, resource.external_id, matches)
        findings.append(finding)
        return findings

    @staticmethod
    def _build_fingerprint(rule_id: Any, bucket_id: str, matches: List[Dict[str, Any]]) -> str:
        from hashlib import sha256

        key_fragment = ";".join(sorted(obj.get("key", "") for obj in matches[:5]))
        raw = f"{rule_id}|{bucket_id}|{key_fragment}"
        return sha256(raw.encode()).hexdigest()
