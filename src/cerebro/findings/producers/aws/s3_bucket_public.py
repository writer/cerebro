"""Producer for detecting publicly accessible S3 buckets."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseAWSProducer


@register_producer
class S3BucketPublicProducer(BaseAWSProducer):
    """Detects publicly accessible S3 buckets."""
    
    @property
    def resource_types(self) -> Set[str]:
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
        return "Enable S3 Block Public Access settings and review bucket policies and ACLs"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["2.1.1", "2.1.5"],
            "nist_800_53": ["AC-3", "AC-4"],
            "cwe": ["CWE-200"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate S3 bucket for public access."""
        findings = []
        
        # Check multiple ways a bucket can be public
        policy_allows_public = config.normalized_config.get("policyAllowsPublic", False)
        acl_allows_public = config.normalized_config.get("aclAllowsPublic", False)
        block_public_disabled = not config.normalized_config.get("blockPublicAccess", {}).get("effective", True)
        
        is_public = policy_allows_public or acl_allows_public or block_public_disabled
        
        if is_public:
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name_sync
                rule_id = get_rule_by_name_sync(self.rule_name)
            
            # Determine specific public access vectors
            access_vectors = []
            if policy_allows_public:
                access_vectors.append("bucket_policy")
            if acl_allows_public:
                access_vectors.append("bucket_acl")
            if block_public_disabled:
                access_vectors.append("block_public_access_disabled")
            
            evidence = {
                "bucket_name": resource.name,
                "bucket_arn": f"arn:aws:s3:::{resource.name}",
                "region": config.normalized_config.get("region"),
                "access_vectors": access_vectors,
                "policy_analysis": {
                    "policy_allows_public": policy_allows_public,
                    "acl_allows_public": acl_allows_public,
                    "block_public_access": config.normalized_config.get("blockPublicAccess", {}),
                },
                "bucket_policy": config.normalized_config.get("policy"),
                "bucket_acl": config.normalized_config.get("acl"),
                "creation_date": config.normalized_config.get("creation_date"),
                "encryption": config.normalized_config.get("encryption", {}),
                "versioning": config.normalized_config.get("versioning", {}),
                "logging": config.normalized_config.get("logging", {}),
            }
            
            # Adjust severity based on access type
            severity = self.severity
            if policy_allows_public and "s3:GetObject" in str(config.normalized_config.get("policy", {})):
                severity = Severity.CRITICAL  # Public read is critical
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"S3 bucket {resource.name} is publicly accessible",
                summary=f"S3 bucket {resource.name} allows public access via {', '.join(access_vectors)}",
                evidence=evidence,
                severity=severity
            )
            findings.append(finding)
        
        return findings
