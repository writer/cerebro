"""Producer for detecting IAM users without MFA."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseAWSProducer


@register_producer
class IAMUserWithoutMFAProducer(BaseAWSProducer):
    """Detects IAM users with console access but no MFA."""
    
    @property
    def resource_types(self) -> Set[str]:
        return {"aws.iam.user"}
    
    @property
    def finding_name(self) -> str:
        return "AWS: IAM User Without MFA"
    
    @property
    def rule_name(self) -> str:
        return "aws_iam_user_without_mfa"
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    @property
    def description(self) -> str:
        return "IAM user with console access does not have MFA enabled"
    
    @property
    def remediation(self) -> str:
        return "Enable MFA for all IAM users with console access, or disable console access and use roles instead"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["1.2"],
            "nist_800_53": ["IA-2(1)"],
            "cwe": ["CWE-287"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate IAM user for MFA configuration."""
        findings = []
        
        # Check if user has console access but no MFA
        console_access = config.normalized_config.get("console_access", False)
        mfa_enabled = config.normalized_config.get("mfa", {}).get("enabled", False)
        password_last_used = config.normalized_config.get("password_last_used")
        access_keys = config.normalized_config.get("access_keys", [])
        
        # User needs MFA if they have console access or recently used passwords
        needs_mfa = console_access or (password_last_used is not None)
        
        if needs_mfa and not mfa_enabled:
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name_sync
                rule_id = get_rule_by_name_sync(self.rule_name)
            
            # Analyze risk factors
            risk_factors = []
            if console_access:
                risk_factors.append("console_access_enabled")
            if password_last_used:
                risk_factors.append("password_recently_used")
            if len(access_keys) > 0:
                risk_factors.append("has_access_keys")
            
            # Check for admin privileges
            attached_policies = config.normalized_config.get("attached_policies", [])
            is_admin = any("Admin" in policy for policy in attached_policies)
            if is_admin:
                risk_factors.append("has_admin_privileges")
            
            evidence = {
                "username": resource.name,
                "user_arn": resource.external_id,
                "console_access": console_access,
                "mfa_enabled": mfa_enabled,
                "password_last_used": password_last_used,
                "access_keys_count": len(access_keys),
                "attached_policies": attached_policies,
                "groups": config.normalized_config.get("groups", []),
                "risk_factors": risk_factors,
                "user_creation_date": config.normalized_config.get("create_date"),
                "path": config.normalized_config.get("path", "/"),
            }
            
            # Escalate severity if user has admin privileges
            severity = Severity.CRITICAL if is_admin else self.severity
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"IAM user {resource.name} lacks MFA with console access",
                summary=f"IAM user {resource.name} has console access but no MFA enabled. Risk factors: {', '.join(risk_factors)}",
                evidence=evidence,
                severity=severity
            )
            findings.append(finding)
        
        return findings
