"""Producer for detecting GitHub organizations with 2FA disabled."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseGitHubProducer


@register_producer
class Org2FADisabledProducer(BaseGitHubProducer):
    """Detects GitHub organizations that do not enforce 2FA."""
    
    @property
    def resource_types(self) -> Set[str]:
        return {"github.org"}
    
    @property
    def finding_name(self) -> str:
        return "GitHub: Organization 2FA Not Enforced"
    
    @property
    def rule_name(self) -> str:
        return "github_org_2fa_disabled"
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    @property
    def description(self) -> str:
        return "GitHub organization does not enforce two-factor authentication for members"
    
    @property
    def remediation(self) -> str:
        return "Go to Organization Settings > Authentication security and enable 'Require two-factor authentication for everyone in the organization'"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["5.1.1"],
            "nist_800_53": ["IA-2(1)", "AC-2"],
            "cwe": ["CWE-287"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate GitHub organization 2FA enforcement."""
        findings = []
        
        # Check if organization enforces 2FA
        requires_2fa = config.normalized_config.get("two_factor_requirement_enabled", False)
        member_count = config.normalized_config.get("public_members", 0) + config.normalized_config.get("private_members", 0)
        
        # Only flag organizations with members
        if not requires_2fa and member_count > 0:
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name_sync
                rule_id = get_rule_by_name_sync(self.rule_name)
            
            evidence = {
                "organization": resource.name,
                "login": resource.external_id,
                "two_factor_requirement_enabled": requires_2fa,
                "total_members": member_count,
                "public_members": config.normalized_config.get("public_members", 0),
                "private_members": config.normalized_config.get("private_members", 0),
                "billing_email": config.normalized_config.get("billing_email"),
                "plan": config.normalized_config.get("plan", {}).get("name"),
                "created_at": config.normalized_config.get("created_at"),
                "updated_at": config.normalized_config.get("updated_at"),
            }
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"GitHub organization {resource.name} does not enforce 2FA",
                summary=f"Organization {resource.name} with {member_count} members does not require two-factor authentication",
                evidence=evidence
            )
            findings.append(finding)
        
        return findings
