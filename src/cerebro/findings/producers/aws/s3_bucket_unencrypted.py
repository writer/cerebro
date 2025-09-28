"""Producer for detecting unencrypted S3 buckets."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseAWSProducer


@register_producer
class S3BucketUnencryptedProducer(BaseAWSProducer):
    """Detects S3 buckets without default encryption enabled."""
    
    @property
    def resource_types(self) -> Set[str]:
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
        return "Enable default encryption with AES-256 or AWS KMS in S3 bucket settings"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["2.1.1"],
            "nist_800_53": ["SC-28", "SC-13"],
            "pci_dss": ["3.4"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate S3 bucket encryption configuration."""
        findings = []
        
        # Check encryption configuration
        encryption = config.normalized_config.get("encryption", {})
        encryption_enabled = encryption.get("enabled", False)
        
        # Check for versioning (affects encryption importance)
        versioning_enabled = config.normalized_config.get("versioning", {}).get("enabled", False)
        
        # Check for public access (increases severity if unencrypted)
        is_public = (
            config.normalized_config.get("policyAllowsPublic", False) or
            config.normalized_config.get("aclAllowsPublic", False)
        )
        
        if not encryption_enabled:
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name
                rule_id = get_rule_by_name(self.rule_name)
            
            # Assess risk factors
            risk_factors = []
            if is_public:
                risk_factors.append("publicly_accessible")
            if versioning_enabled:
                risk_factors.append("versioning_enabled")
            if not config.normalized_config.get("logging", {}).get("enabled", False):
                risk_factors.append("no_access_logging")
            
            evidence = {
                "bucket_name": resource.name,
                "bucket_arn": f"arn:aws:s3:::{resource.name}",
                "region": config.normalized_config.get("region"),
                "encryption": encryption,
                "versioning": config.normalized_config.get("versioning", {}),
                "public_access": {
                    "policy_allows_public": config.normalized_config.get("policyAllowsPublic", False),
                    "acl_allows_public": config.normalized_config.get("aclAllowsPublic", False),
                    "block_public_access": config.normalized_config.get("blockPublicAccess", {}),
                },
                "risk_factors": risk_factors,
                "logging": config.normalized_config.get("logging", {}),
                "lifecycle_policy": config.normalized_config.get("lifecycle", {}),
                "creation_date": config.normalized_config.get("creation_date"),
            }
            
            # Escalate severity if bucket is public
            severity = Severity.HIGH if is_public else self.severity
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"S3 bucket {resource.name} is not encrypted",
                summary=f"S3 bucket {resource.name} does not have default encryption enabled. Risk factors: {', '.join(risk_factors) if risk_factors else 'None'}",
                evidence=evidence,
                severity=severity
            )
            findings.append(finding)
        
        return findings
