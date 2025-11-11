"""Detect reuse of CodeBuild source credentials across projects."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from cerebro.domain.entities import ConfigEntity, FindingEntity, ResourceEntity, Severity
from cerebro.findings.producers.registry import register_producer

from .base import BaseAWSProducer


@register_producer
class CodeBuildSharedCredentialProducer(BaseAWSProducer):
    """Flag projects that reuse source credentials across multiple builds."""

    @property
    def resource_types(self) -> Set[str]:
        return {"aws.codebuild.project"}

    @property
    def finding_name(self) -> str:
        return "AWS: CodeBuild project reuses source credentials"

    @property
    def rule_name(self) -> str:
        return "aws_codebuild_shared_source_credentials"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "CodeBuild project stores source credentials internally and enables insecure SSL options"

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, object]] = None,
    ) -> List[FindingEntity]:
        normalized = config.normalized_config or {}
        source = normalized.get("source") or {}
        fetch_logs = normalized.get("logsConfig") or {}
        environment = normalized.get("environment") or {}

        auth = source.get("auth") or {}
        source_type = source.get("type")
        auth_type = auth.get("type")
        auth_resource = auth.get("resource")
        insecure_ssl = source.get("insecureSsl")
        report_status = source.get("reportBuildStatus")

        environment_variables = environment.get("environmentVariables") or []
        has_token_env = any(
            env_var.get("name", "").lower() in {"token", "password", "secret", "github_token"}
            for env_var in environment_variables
        )

        if not (auth_type or auth_resource):
            return []

        if source_type not in {"GITHUB", "BITBUCKET", "GITHUB_ENTERPRISE", "GITHUB_ENTERPRISE_SERVER"}:
            return []

        if auth_type == "CODECONNECTIONS":
            return []

        insecure_conditions = insecure_ssl or report_status is True or has_token_env

        if not insecure_conditions:
            return []

        rule_id = context.get("rule_id") if context else None
        if not rule_id:
            from cerebro.rules.rule_service import get_rule_by_name_sync

            rule_id = get_rule_by_name_sync(self.rule_name)

        evidence = {
            "project": resource.external_id,
            "source_type": source_type,
            "auth_type": auth_type,
            "auth_resource": auth_resource,
            "insecure_ssl": insecure_ssl,
            "report_build_status": report_status,
            "env_variables": environment_variables,
            "logs_enabled": bool(fetch_logs),
        }

        summary_flags: List[str] = []
        if insecure_ssl:
            summary_flags.append("insecure SSL enabled")
        if report_status:
            summary_flags.append("reportBuildStatus leaks credentials")
        if has_token_env:
            summary_flags.append("tokens present in environment variables")

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=f"CodeBuild project {resource.name or resource.external_id} reuses source credentials",
            summary=f"Project stores credentials ({', '.join(summary_flags)})",
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
