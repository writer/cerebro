"""Producer for detecting public GitHub repositories without branch protection."""

from __future__ import annotations

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import coerce_mapping, resolve_rule_id

from .base import BaseGitHubProducer


@register_producer
class PublicRepoNoBranchProtectionProducer(BaseGitHubProducer):
    """Detects public GitHub repositories without branch protection."""

    @property
    def resource_types(self) -> set[str]:
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
        return "Public GitHub repository lacks required branch protection rules."

    @property
    def remediation(self) -> str:
        return (
            "Enable branch protection with required pull request reviews for the "
            "default branch."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "cis": ["5.1.4"],
            "nist_800_53": ["CM-3"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate GitHub repository for branch protection."""
        findings: list[FindingEntity] = []

        normalized = config.normalized_config or {}
        is_public = normalized.get("visibility") == "public"
        is_archived = bool(normalized.get("archived", False))
        branch_protection = coerce_mapping(normalized.get("branchProtection")) or {}
        requires_pr = bool(branch_protection.get("requirePR", False))

        if is_public and not requires_pr and not is_archived:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            evidence = {
                "repository": resource.name,
                "full_name": normalized.get("fullName"),
                "visibility": normalized.get("visibility"),
                "default_branch": normalized.get("defaultBranch"),
                "branch_protection": {
                    "enabled": requires_pr,
                    "required_reviewers": branch_protection.get(
                        "requiredReviewers",
                        0,
                    ),
                    "dismiss_stale_reviews": branch_protection.get(
                        "dismissStaleReviews",
                        False,
                    ),
                    "require_code_owner_reviews": branch_protection.get(
                        "requireCodeOwnerReviews",
                        False,
                    ),
                },
                "repo_url": normalized.get("fullName"),
                "last_push": normalized.get("lastPush"),
                "collaborators_count": normalized.get("collaboratorsCount", 0),
            }
            summary = (
                f"Public repository {resource.name} lacks required pull request "
                "review enforcement on the default branch."
            )

            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                summary=summary,
                evidence=evidence,
                severity=self.severity,
            )
            findings.append(finding)

        return findings
