"""Producer for detecting M365 files shared externally."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.base import BaseFindingProducer


@register_producer
class M365FileSharedExternallyProducer(BaseFindingProducer):
    """Detects M365 files shared with external users."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"m365"}
    
    @property
    def resource_types(self) -> Set[str]:
        return {"m365.sharepoint.site", "m365.file"}
    
    @property
    def finding_name(self) -> str:
        return "Microsoft 365: File Shared Externally"
    
    @property
    def rule_name(self) -> str:
        return "m365_file_shared_externally"
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def description(self) -> str:
        return "Microsoft 365 file or folder shared with external users"
    
    @property
    def remediation(self) -> str:
        return "Review external sharing settings and ensure only authorized external access"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-4"],
            "cwe": ["CWE-200"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate M365 resource for external sharing."""
        findings = []
        
        # Check SharePoint site external sharing
        if resource.resource_type == "m365.sharepoint.site":
            external_sharing = config.normalized_config.get("external_sharing", False)
            permissions = config.normalized_config.get("permissions", [])
            
            # Look for external users in permissions
            external_users = [
                perm for perm in permissions 
                if perm.get("grantedToV2", {}).get("user", {}).get("email", "").endswith(("@gmail.com", "@yahoo.com", "@hotmail.com"))
                or not perm.get("grantedToV2", {}).get("user", {}).get("email", "").endswith(context.get("organization_domains", []) if context else [])
            ]
            
            if external_sharing and external_users:
                rule_id = context.get("rule_id") if context else None
                if not rule_id:
                    from cerebro.rules.rule_service import get_rule_by_name_sync
                    rule_id = get_rule_by_name_sync(self.rule_name)
                
                evidence = {
                    "site_name": resource.name,
                    "site_url": config.normalized_config.get("web_url"),
                    "external_sharing_enabled": external_sharing,
                    "external_users_count": len(external_users),
                    "external_users": [
                        {
                            "email": user.get("grantedToV2", {}).get("user", {}).get("email"),
                            "display_name": user.get("grantedToV2", {}).get("user", {}).get("displayName"),
                            "role": user.get("roles", [])
                        }
                        for user in external_users[:10]  # Limit to first 10
                    ],
                    "sharing_capability": config.normalized_config.get("sharing_capability"),
                    "site_id": resource.external_id
                }
                
                finding = self.create_finding(
                    resource=resource,
                    rule_id=rule_id,
                    title=f"SharePoint site {resource.name} shared with {len(external_users)} external users",
                    summary=f"SharePoint site has external sharing enabled with {len(external_users)} external users having access",
                    evidence=evidence
                )
                findings.append(finding)
        
        return findings
