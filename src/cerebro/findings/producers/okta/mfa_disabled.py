"""Producer for detecting Okta users without MFA."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseOktaProducer


@register_producer
class OktaMFADisabledProducer(BaseOktaProducer):
    """Detects Okta users without MFA enabled."""
    
    @property
    def resource_types(self) -> Set[str]:
        return {"okta.user"}
    
    @property
    def finding_name(self) -> str:
        return "Okta: User Without MFA"
    
    @property
    def rule_name(self) -> str:
        return "okta_user_without_mfa"
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    @property
    def description(self) -> str:
        return "Okta user does not have multi-factor authentication enabled"
    
    @property
    def remediation(self) -> str:
        return "Enable MFA for the user or enforce organization-wide MFA policy"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["IA-2(1)", "IA-2(2)"],
            "cwe": ["CWE-287"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate Okta user MFA configuration."""
        findings = []
        
        # Check MFA enrollment status
        mfa_enrolled = config.normalized_config.get("mfa_enrolled", False)
        user_status = config.normalized_config.get("status", "UNKNOWN")
        last_login = config.normalized_config.get("last_login")
        
        # Only flag active users without MFA
        if user_status == "ACTIVE" and not mfa_enrolled:
            # Get rule ID
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name_sync
                rule_id = get_rule_by_name_sync(self.rule_name)
            
            # Assess risk factors
            risk_factors = []
            if last_login:
                risk_factors.append("recent_login_activity")
            
            admin_roles = config.normalized_config.get("admin_roles", [])
            if admin_roles:
                risk_factors.append("has_admin_privileges")
            
            evidence = {
                "user_id": resource.external_id,
                "email": config.normalized_config.get("email"),
                "login": config.normalized_config.get("login"),
                "status": user_status,
                "mfa_enrolled": mfa_enrolled,
                "last_login": last_login,
                "admin_roles": admin_roles,
                "risk_factors": risk_factors,
                "profile": config.normalized_config.get("profile", {}),
                "groups": config.normalized_config.get("groups", []),
            }
            
            # Escalate severity for admin users
            severity = Severity.CRITICAL if admin_roles else self.severity
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Okta user {config.normalized_config.get('email', resource.name)} lacks MFA",
                summary=f"Active Okta user without MFA enrollment. Risk factors: {', '.join(risk_factors) if risk_factors else 'None'}",
                evidence=evidence,
                severity=severity
            )
            findings.append(finding)
        
        return findings
