"""Producer for detecting inconsistent MFA enforcement across providers."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.base import BaseFindingProducer


@register_producer
class InconsistentMFAEnforcementProducer(BaseFindingProducer):
    """Detects users with inconsistent MFA enforcement across providers."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {"github", "aws", "gcp", "google_workspace"}
    
    @property
    def resource_types(self) -> Set[str]:
        return {"identity_cluster"}  # Special resource type for identity clusters
    
    @property
    def finding_name(self) -> str:
        return "Cross-Provider: Inconsistent MFA Enforcement"
    
    @property
    def rule_name(self) -> str:
        return "cross_provider_inconsistent_mfa"
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def description(self) -> str:
        return "User has MFA enabled in some providers but not others"
    
    @property
    def remediation(self) -> str:
        return "Enable MFA consistently across all platforms for each user identity"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "nist_800_53": ["IA-2(1)", "IA-4"],
            "cwe": ["CWE-287"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,  # This would be an identity cluster
        config: ConfigEntity,      # Aggregated identity config across providers
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate identity cluster for consistent MFA enforcement."""
        findings = []
        
        # Parse identity cluster data from config
        identity_data = config.normalized_config
        providers_with_mfa = []
        providers_without_mfa = []
        
        for provider, user_data in identity_data.items():
            if provider in self.desired_sources:
                mfa_enabled = user_data.get("mfa", {}).get("enabled", False)
                
                if mfa_enabled:
                    providers_with_mfa.append(provider)
                else:
                    providers_without_mfa.append(provider)
        
        # Flag if MFA is inconsistent (enabled in some providers but not others)
        if providers_with_mfa and providers_without_mfa:
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name
                rule_id = get_rule_by_name(self.rule_name)
            
            evidence = {
                "identity_cluster_id": resource.external_id,
                "email": identity_data.get("email"),
                "display_name": identity_data.get("display_name"),
                "providers_with_mfa": providers_with_mfa,
                "providers_without_mfa": providers_without_mfa,
                "total_providers": len(providers_with_mfa) + len(providers_without_mfa),
                "mfa_coverage_percentage": len(providers_with_mfa) / (len(providers_with_mfa) + len(providers_without_mfa)) * 100,
                "provider_details": {
                    provider: {
                        "username": user_data.get("username"),
                        "mfa_enabled": user_data.get("mfa", {}).get("enabled", False),
                        "last_login": user_data.get("last_login"),
                        "account_type": user_data.get("account_type"),
                    }
                    for provider, user_data in identity_data.items()
                    if provider in self.desired_sources
                }
            }
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Inconsistent MFA for {identity_data.get('email', 'unknown user')}",
                summary=f"User has MFA enabled in {len(providers_with_mfa)} providers but disabled in {len(providers_without_mfa)} providers",
                evidence=evidence
            )
            findings.append(finding)
        
        return findings
