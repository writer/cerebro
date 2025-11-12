"""Detect reuse of CodeBuild source credentials across projects."""

from __future__ import annotations

from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    build_ci_pipeline_exposure,
    resolve_rule_id,
)

from .base import BaseAWSProducer


@register_producer
class CodeBuildSharedCredentialProducer(BaseAWSProducer):
    """Flag projects that reuse source credentials across multiple builds."""

    @property
    def resource_types(self) -> set[str]:
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
        return (
            "CodeBuild project stores embedded source credentials and "
            "enables insecure SSL options"
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
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

        environment_variables: list[dict[str, Any]] = (
            environment.get("environmentVariables") or []
        )
        has_token_env = any(
            env_var.get("name", "").lower()
            in {"token", "password", "secret", "github_token"}
            for env_var in environment_variables
        )

        if not (auth_type or auth_resource):
            return []

        if source_type not in {
            "GITHUB",
            "BITBUCKET",
            "GITHUB_ENTERPRISE",
            "GITHUB_ENTERPRISE_SERVER",
        }:
            return []

        if auth_type == "CODECONNECTIONS":
            return []

        insecure_conditions = insecure_ssl or report_status is True or has_token_env

        if not insecure_conditions:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = build_ci_pipeline_exposure(
            project=resource.external_id,
            source_type=source_type,
            auth_type=auth_type,
            auth_resource=auth_resource,
            insecure_ssl=insecure_ssl,
            report_build_status=report_status,
            env_variables=environment_variables,
            logs_enabled=bool(fetch_logs),
            extra={"tokens_present": has_token_env},
        )

        summary_flags: list[str] = []
        if insecure_ssl:
            summary_flags.append("insecure SSL enabled")
        if report_status:
            summary_flags.append("reportBuildStatus leaks credentials")
        if has_token_env:
            summary_flags.append("tokens present in environment variables")

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "CodeBuild project "
                f"{resource.name or resource.external_id} reuses source credentials"
            ),
            summary=f"Project stores credentials ({', '.join(summary_flags)})",
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
