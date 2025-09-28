"""Finding producers inspired by ThreatKey's findings-producer architecture."""

import abc
from typing import List, Set, Dict, Any, Optional, Type
from datetime import datetime
from uuid import UUID
import logging

from cerebro.domain.entities import ResourceEntity, PrincipalEntity, ConfigEntity, FindingEntity, RuleEntity
from cerebro.rules.library import RuleLibrary

logger = logging.getLogger(__name__)


class BaseFindingProducer(abc.ABC):
    """Base class for finding producers."""
    
    @property
    @abc.abstractmethod
    def desired_sources(self) -> Set[str]:
        """The providers this producer cares about."""
        pass
    
    @property
    @abc.abstractmethod
    def resource_types(self) -> Set[str]:
        """Resource types this producer evaluates."""
        pass
    
    @property
    @abc.abstractmethod
    def finding_name(self) -> str:
        """Name of the finding this producer creates."""
        pass
    
    @property
    @abc.abstractmethod
    def severity(self) -> str:
        """Severity level of findings this producer creates."""
        pass
    
    @abc.abstractmethod
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate resource and config to produce findings."""
        pass
    
    def create_finding(
        self,
        resource: ResourceEntity,
        rule_id: UUID,
        title: str,
        summary: str,
        evidence: Dict[str, Any],
        severity: Optional[str] = None
    ) -> FindingEntity:
        """Helper to create standardized findings."""
        finding = FindingEntity(
            rule_id=rule_id,
            resource_external_id=resource.external_id,
            title=title,
            summary=summary,
            severity=severity or self.severity,
            evidence=evidence,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        
        # Generate fingerprint
        import hashlib
        fingerprint_str = f"{rule_id}|{resource.external_id}|{self.finding_name}"
        finding.fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
        
        return finding


class GitHubPublicRepoNoBranchProtectionProducer(BaseFindingProducer):
    """Detects public GitHub repositories without branch protection."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"github"}
    
    @property
    def resource_types(self) -> Set[str]:
        return {"github.repo"}
    
    @property
    def finding_name(self) -> str:
        return "GitHub: Public Repository Without Branch Protection"
    
    @property
    def severity(self) -> str:
        return "high"
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate GitHub repository for branch protection."""
        findings = []
        
        # Check if public repo without branch protection
        if (config.normalized_config.get("visibility") == "public" and
            not config.normalized_config.get("branchProtection", {}).get("requirePR", False) and
            not config.normalized_config.get("archived", False)):
            
            finding = self.create_finding(
                resource=resource,
                rule_id=UUID("12345678-1234-5678-9012-123456789012"),  # Would be real rule ID
                title=f"Public repository {resource.name} lacks branch protection",
                summary=f"Repository {resource.name} is public but does not require pull request reviews for the default branch",
                evidence={
                    "repository": resource.name,
                    "visibility": config.normalized_config.get("visibility"),
                    "default_branch": config.normalized_config.get("defaultBranch"),
                    "branch_protection_enabled": False,
                    "require_pr": config.normalized_config.get("branchProtection", {}).get("requirePR", False),
                    "repo_url": config.normalized_config.get("fullName"),
                }
            )
            findings.append(finding)
        
        return findings


class AWSS3PublicBucketProducer(BaseFindingProducer):
    """Detects publicly accessible S3 buckets."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"aws"}
    
    @property
    def resource_types(self) -> Set[str]:
        return {"aws.s3.bucket"}
    
    @property
    def finding_name(self) -> str:
        return "AWS: S3 Bucket Publicly Accessible"
    
    @property
    def severity(self) -> str:
        return "high"
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate S3 bucket for public access."""
        findings = []
        
        # Check multiple ways a bucket can be public
        is_public = (
            config.normalized_config.get("policyAllowsPublic", False) or
            config.normalized_config.get("aclAllowsPublic", False) or
            not config.normalized_config.get("blockPublicAccess", {}).get("effective", True)
        )
        
        if is_public:
            finding = self.create_finding(
                resource=resource,
                rule_id=UUID("23456789-2345-6789-0123-234567890123"),  # Would be real rule ID
                title=f"S3 bucket {resource.name} is publicly accessible",
                summary=f"S3 bucket {resource.name} allows public access through policy, ACL, or disabled block public access settings",
                evidence={
                    "bucket_name": resource.name,
                    "policy_allows_public": config.normalized_config.get("policyAllowsPublic", False),
                    "acl_allows_public": config.normalized_config.get("aclAllowsPublic", False),
                    "block_public_access_enabled": config.normalized_config.get("blockPublicAccess", {}).get("effective", True),
                    "region": config.normalized_config.get("region"),
                }
            )
            findings.append(finding)
        
        return findings


class AWSIAMUserWithoutMFAProducer(BaseFindingProducer):
    """Detects IAM users without MFA enabled."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"aws"}
    
    @property
    def resource_types(self) -> Set[str]:
        return {"aws.iam.user"}
    
    @property
    def finding_name(self) -> str:
        return "AWS: IAM User Without MFA"
    
    @property
    def severity(self) -> str:
        return "medium"
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate IAM user for MFA configuration.""" 
        findings = []
        
        # Check if user has console access but no MFA
        if (config.normalized_config.get("console_access", False) and
            not config.normalized_config.get("mfa", {}).get("enabled", False)):
            
            finding = self.create_finding(
                resource=resource,
                rule_id=UUID("34567890-3456-7890-1234-345678901234"),  # Would be real rule ID
                title=f"IAM user {resource.name} has console access without MFA",
                summary=f"IAM user {resource.name} can access the AWS console but does not have MFA enabled",
                evidence={
                    "username": resource.name,
                    "user_arn": resource.external_id,
                    "console_access": config.normalized_config.get("console_access"),
                    "mfa_enabled": config.normalized_config.get("mfa", {}).get("enabled", False),
                    "password_last_used": config.normalized_config.get("password_last_used"),
                }
            )
            findings.append(finding)
        
        return findings


class ProducerRegistry:
    """Registry for finding producers."""
    
    def __init__(self):
        """Initialize producer registry."""
        self._producers: Dict[str, Type[BaseFindingProducer]] = {}
        self._producer_instances: Dict[str, BaseFindingProducer] = {}
    
    def register(self, producer_class: Type[BaseFindingProducer]) -> None:
        """Register a producer class."""
        producer_name = producer_class.__name__
        self._producers[producer_name] = producer_class
        self._producer_instances[producer_name] = producer_class()
        
        logger.info(f"Registered finding producer: {producer_name}")
    
    def get_producers_for_resource(
        self, 
        provider: str, 
        resource_type: str
    ) -> List[BaseFindingProducer]:
        """Get all producers that can evaluate a resource."""
        matching_producers = []
        
        for producer in self._producer_instances.values():
            if (provider in producer.desired_sources and 
                resource_type in producer.resource_types):
                matching_producers.append(producer)
        
        return matching_producers
    
    def evaluate_resource(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate resource using all applicable producers."""
        findings = []
        
        producers = self.get_producers_for_resource(
            resource.provider, 
            resource.resource_type
        )
        
        for producer in producers:
            try:
                producer_findings = producer.evaluate(resource, config, context)
                findings.extend(producer_findings)
                
                if producer_findings:
                    logger.info(f"Producer {producer.__class__.__name__} generated {len(producer_findings)} findings")
                    
            except Exception as e:
                logger.error(f"Producer {producer.__class__.__name__} failed: {e}")
        
        return findings
    
    def list_producers(self) -> List[str]:
        """List all registered producers."""
        return list(self._producers.keys())


# Global producer registry
producer_registry = ProducerRegistry()

# Register built-in producers
producer_registry.register(GitHubPublicRepoNoBranchProtectionProducer)
producer_registry.register(AWSS3PublicBucketProducer)
producer_registry.register(AWSIAMUserWithoutMFAProducer)


def register_producer(producer_class: Type[BaseFindingProducer]):
    """Decorator to register a producer."""
    producer_registry.register(producer_class)
    return producer_class


# Enhanced finding service using producers
class ProducerBasedFindingService:
    """Finding service using the producer pattern."""
    
    def __init__(self, registry: ProducerRegistry):
        """Initialize with producer registry."""
        self.registry = registry
    
    def generate_findings_for_resources(
        self,
        resources: List[ResourceEntity],
        configs: Dict[str, ConfigEntity],
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Generate findings for multiple resources using producers."""
        all_findings = []
        
        for resource in resources:
            config = configs.get(resource.external_id)
            if not config:
                logger.warning(f"No config found for resource {resource.external_id}")
                continue
            
            findings = self.registry.evaluate_resource(resource, config, context)
            all_findings.extend(findings)
        
        logger.info(f"Generated {len(all_findings)} findings from {len(resources)} resources")
        return all_findings
