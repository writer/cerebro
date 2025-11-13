"""Producers for GitHub workflow permissions hardening."""

from __future__ import annotations

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    ProducerRunContext,
    build_workflow_permission_evidence,
    coerce_mapping,
    resolve_rule_id,
)

from .base import BaseGitHubProducer


@register_producer
class GithubWorkflowDefaultWriteProducer(BaseGitHubProducer):
    """Detect repositories with default workflow write permissions."""

    @property
    def resource_types(self) -> set[str]:
        return {"github.repo"}

    @property
    def finding_name(self) -> str:
        return "GitHub: Workflow default permissions set to write"

    @property
    def rule_name(self) -> str:
        return "github_workflow_default_write_permissions"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return "Repository allows GitHub Actions workflows default write access"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        run_context = ProducerRunContext.ensure(context)

        normalized = config.normalized_config or {}
        permissions = coerce_mapping(normalized.get("actionsPermissions")) or {}
        if not permissions:
            return []

        default_permission = permissions.get("default_workflow_permissions")
        can_approve_forks = permissions.get("can_approve_pull_request_reviews")

        if default_permission != "write" and not can_approve_forks:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        risk_factors = ["default_write_permissions"]
        if can_approve_forks:
            risk_factors.append("approves_fork_prs")

        evidence = build_workflow_permission_evidence(
            repository=resource.external_id,
            default_permissions=permissions,
            workflow_access={
                "can_approve_pull_request_reviews": can_approve_forks,
            },
            risk_factors=risk_factors,
        )

        repo_name = resource.name or resource.external_id
        title = f"Repository {repo_name} grants workflow write permissions"
        summary = (
            "GitHub Actions workflows execute with default write permissions or "
            "can approve pull request reviews, increasing the blast radius of "
            "compromised workflows."
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=title,
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
