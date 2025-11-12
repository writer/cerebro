"""Detect CodeBuild projects exposed to public webhook triggers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseAWSProducer

PUBLIC_SOURCE_TYPES = {
    "GITHUB",
    "GITHUB_ENTERPRISE",
    "GITHUB_ENTERPRISE_SERVER",
    "BITBUCKET",
}
SENSITIVE_AUTH_TYPES = {"OAUTH", "BASIC_AUTH", "PERSONAL_ACCESS_TOKEN"}


def _has_restrictive_filters(filter_groups: list[list[dict[str, str]]] | None) -> bool:
    if not filter_groups:
        return False

    for group in filter_groups:
        if not group:
            continue

        has_branch_or_path_restriction = any(
            filter_def.get("type") in {"BASE_REF", "HEAD_REF", "FILE_PATH"}
            and filter_def.get("pattern")
            for filter_def in group
        )

        if not has_branch_or_path_restriction:
            return False

    return True


@register_producer
class CodeBuildPublicTriggerProducer(BaseAWSProducer):
    """Flags CodeBuild projects that accept public webhook triggers."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.codebuild.project"}

    @property
    def finding_name(self) -> str:
        return "AWS: CodeBuild project exposes public webhook trigger"

    @property
    def rule_name(self) -> str:
        return "aws_codebuild_public_trigger"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "CodeBuild project uses public repository webhooks without restrictive "
            "filters"
        )

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Mapping[str, Any] | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        source = normalized.get("source") or {}
        webhook = normalized.get("webhook") or {}

        source_type = source.get("type")
        auth = source.get("auth") or {}
        webhook_present = bool(webhook and webhook.get("url"))

        filter_groups = webhook.get("filterGroups") if webhook else None
        location = (source.get("location") or "").lower()
        auth_type = auth.get("type")

        public_source = source_type in PUBLIC_SOURCE_TYPES
        sensitive_auth = auth_type in SENSITIVE_AUTH_TYPES or bool(auth.get("resource"))
        risky_filters = webhook_present and not _has_restrictive_filters(filter_groups)
        public_location = any(
            domain in location for domain in ("github.com", "bitbucket.org")
        )

        if not webhook_present and not sensitive_auth:
            return []

        if not public_source:
            return []

        if webhook_present and not risky_filters:
            return []

        if not public_location and source_type not in {
            "GITHUB_ENTERPRISE",
            "GITHUB_ENTERPRISE_SERVER",
        }:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        webhook_host = None
        try:
            webhook_host = urlparse(webhook.get("url", "")).netloc or None
        except Exception:
            webhook_host = None

        evidence = {
            "project": resource.name or resource.external_id,
            "source_type": source_type,
            "repository": source.get("location"),
            "auth_type": auth_type,
            "webhook_host": webhook_host,
            "filter_groups": filter_groups,
            "report_build_status": source.get("reportBuildStatus"),
            "auth_resource": auth.get("resource"),
            "webhook_present": webhook_present,
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "CodeBuild project "
                f"{resource.name or resource.external_id} accepts public triggers"
            ),
            summary=(
                "Webhook from a public repository lacks branch or path restrictions, "
                "allowing untrusted pushes to trigger builds."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
