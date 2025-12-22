"""Producer detecting risky GitHub organization workflow defaults."""

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
class GithubOrgWorkflowRiskProducer(BaseGitHubProducer):
    """Flag GitHub organizations that allow untrusted workflow defaults."""

    @property
    def resource_types(self) -> set[str]:
        return {"github.org"}

    @property
    def finding_name(self) -> str:
        return "GitHub: Organization workflow defaults allow untrusted writes"

    @property
    def rule_name(self) -> str:
        return "github_org_workflow_default_writes"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Organization workflows run with write privileges or allow approval "
            "of forked pull requests."
        )

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

        default_permissions = permissions.get("default_workflow_permissions")
        can_approve = permissions.get("can_approve_pull_request_reviews")
        allowed_actions = permissions.get("allowed_actions")

        risky_default = default_permissions == "write"
        risky_approval = bool(can_approve)
        risky_allowed_actions = allowed_actions == "all"

        if not (risky_default or risky_approval or risky_allowed_actions):
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=run_context)

        risk_factors: list[str] = []
        if risky_default:
            risk_factors.append("default_write_permissions")
        if risky_approval:
            risk_factors.append("approves_fork_prs")
        if risky_allowed_actions:
            risk_factors.append("allows_all_actions")

        evidence = build_workflow_permission_evidence(
            organization=resource.external_id,
            default_permissions=permissions,
            workflow_access={
                "allowed_actions": allowed_actions,
                "can_approve_pull_request_reviews": can_approve,
            },
            risk_factors=risk_factors,
        )

        summary_parts: list[str] = []
        if risky_default:
            summary_parts.append("workflows run with write permissions")
        if risky_approval:
            summary_parts.append("workflows can approve forked pull requests")
        if risky_allowed_actions:
            summary_parts.append("all actions are permitted by default")

        summary_detail = ", ".join(summary_parts)

        subject = resource.name or resource.external_id
        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"Organization {subject} allows untrusted workflow defaults",
            summary=(f"GitHub organization {resource.external_id} {summary_detail}."),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
