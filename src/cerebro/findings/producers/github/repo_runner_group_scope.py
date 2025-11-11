"""Producers for GitHub repository runner group scoping."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseGitHubProducer


def _is_broad_runner_group(group_info: Optional[Dict[str, object]]) -> bool:
    if not group_info:
        return False

    visibility = group_info.get("visibility")
    allows_public = group_info.get("allows_public_repositories")
    restricted_to_workflows = group_info.get("restricted_to_workflows")

    if visibility in {"all", "public"}:
        return True
    if allows_public:
        return True
    if restricted_to_workflows is False:
        return True

    return False


def _references_multiple_repos(repositories: Optional[List[Dict[str, object]]]) -> bool:
    if not repositories:
        return False
    return len(repositories) > 1


@register_producer
class GithubRepoRunnerGroupScopeProducer(BaseGitHubProducer):
    """Detect repositories attached to overly broad runner groups."""

    @property
    def resource_types(self) -> Set[str]:
        return {"github.repo"}

    @property
    def finding_name(self) -> str:
        return "GitHub: Repository uses organization-wide runner group"

    @property
    def rule_name(self) -> str:
        return "github_repo_runner_group_scope"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "Repository is configured with a runner group that can be used by untrusted repositories"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, object]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config or {}
        runner_meta = normalized.get("runner") or {}
        runner_group = normalized.get("runner_group") or {}
        repositories = normalized.get("repositories") or []

        risky_group = _is_broad_runner_group(runner_group)
        multi_repo = _references_multiple_repos(repositories)

        if not (risky_group or multi_repo):
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "repository": resource.external_id,
            "runner_id": runner_meta.get("id"),
            "runner_name": runner_meta.get("name"),
            "runner_labels": runner_meta.get("labels"),
            "runner_group": runner_group,
            "shared_repositories": repositories,
        }

        summary_parts: List[str] = []
        if risky_group:
            summary_parts.append("runner group permits organization-wide use")
        if multi_repo:
            summary_parts.append("runner group is shared with multiple repositories")

        summary = "; ".join(summary_parts)

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Repository {resource.name or resource.external_id} uses broad runner group",
            summary=f"{resource.external_id}: {summary}",
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
