"""Producer for detecting GitHub admin users without 2FA."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseGitHubProducer


@register_producer
class AdminWithout2FAProducer(BaseGitHubProducer):
    """Detects GitHub admin users without 2FA enabled."""
    
    @property
    def resource_types(self) -> Set[str]:
        return {"github.user"}  # Note: this would need to be added to GitHub provider
    
    @property
    def finding_name(self) -> str:
        return "GitHub: Admin User Without 2FA"
    
    @property
    def rule_name(self) -> str:
        return "github_admin_without_2fa"
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    @property
    def description(self) -> str:
        return "GitHub admin user does not have two-factor authentication enabled"
    
    @property
    def remediation(self) -> str:
        return "Enable two-factor authentication for all admin users in GitHub organization settings"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["5.1.1"],
            "nist_800_53": ["IA-2(1)"],
            "cwe": ["CWE-287"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate GitHub user for 2FA configuration."""
        findings = []
        
        # Check if user is admin and doesn't have 2FA
        is_admin = config.normalized_config.get("is_admin", False)
        has_2fa = config.normalized_config.get("two_factor_authentication", False)
        is_human = config.normalized_config.get("type") == "User"
        
        if is_admin and not has_2fa and is_human:
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name
                rule_id = get_rule_by_name(self.rule_name)
            
            evidence = {
                "username": resource.name,
                "user_id": resource.external_id,
                "is_admin": is_admin,
                "two_factor_authentication": has_2fa,
                "account_type": config.normalized_config.get("type"),
                "site_admin": config.normalized_config.get("site_admin", False),
                "profile_url": config.normalized_config.get("html_url"),
                "last_seen": config.captured_at.isoformat(),
            }
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"GitHub admin user {resource.name} lacks 2FA",
                summary=f"Admin user {resource.name} has administrative privileges but does not have two-factor authentication enabled",
                evidence=evidence
            )
            findings.append(finding)
        
        return findings
