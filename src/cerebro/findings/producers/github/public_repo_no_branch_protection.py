"""Producer for detecting public GitHub repositories without branch protection."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseGitHubProducer


@register_producer
class PublicRepoNoBranchProtectionProducer(BaseGitHubProducer):
    """Detects public GitHub repositories without branch protection."""
    
    @property
    def resource_types(self) -> Set[str]:
        return {"github.repo"}
    
    @property
    def finding_name(self) -> str:
        return "GitHub: Public Repository Without Branch Protection"
    
    @property
    def rule_name(self) -> str:
        return "github_public_repo_no_branch_protection"
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    @property
    def description(self) -> str:
        return "Public GitHub repository lacks required branch protection rules"
    
    @property
    def remediation(self) -> str:
        return "Enable branch protection with required pull request reviews for the default branch"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["5.1.4"],
            "nist_800_53": ["CM-3"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate GitHub repository for branch protection."""
        findings = []
        
        # Check conditions:
        # 1. Repository is public
        # 2. Branch protection is not enabled OR doesn't require PR reviews  
        # 3. Repository is not archived
        is_public = config.normalized_config.get("visibility") == "public"
        is_archived = config.normalized_config.get("archived", False)
        branch_protection = config.normalized_config.get("branchProtection", {})
        requires_pr = branch_protection.get("requirePR", False)
        
        if is_public and not requires_pr and not is_archived:
            # Get rule ID from context or rule registry
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                # Look up rule by name using deterministic UUID
                from cerebro.rules.rule_service import get_rule_by_name_sync
                rule_id = get_rule_by_name_sync(self.rule_name)
            
            evidence = {
                "repository": resource.name,
                "full_name": config.normalized_config.get("fullName"),
                "visibility": config.normalized_config.get("visibility"),
                "default_branch": config.normalized_config.get("defaultBranch"),
                "branch_protection": {
                    "enabled": branch_protection.get("requirePR", False),
                    "required_reviewers": branch_protection.get("requiredReviewers", 0),
                    "dismiss_stale_reviews": branch_protection.get("dismissStaleReviews", False),
                    "require_code_owner_reviews": branch_protection.get("requireCodeOwnerReviews", False),
                },
                "repo_url": config.normalized_config.get("fullName"),
                "last_push": config.normalized_config.get("lastPush"),
                "collaborators_count": config.normalized_config.get("collaboratorsCount", 0),
            }
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                evidence=evidence
            )
            findings.append(finding)
        
        return findings
