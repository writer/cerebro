"""Producer for detecting M365 files shared externally."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import BaseFindingProducer, ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import (
    build_external_sharing_evidence,
    coerce_mapping,
    coerce_mapping_sequence,
    resolve_rule_id,
)


@register_producer
class M365FileSharedExternallyProducer(BaseFindingProducer):
    """Detects M365 files shared with external users."""

    @property
    def desired_sources(self) -> set[str]:
        return {"m365"}

    @property
    def resource_types(self) -> set[str]:
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
        return (
            "Review external sharing settings and ensure only authorized "
            "external access"
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-4"],
            "cwe": ["CWE-200"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate M365 resource for external sharing."""
        if resource.resource_type != "m365.sharepoint.site":
            return []

        data: Mapping[str, Any] = config.normalized_config or {}
        external_sharing = bool(data.get("external_sharing", False))
        if not external_sharing:
            return []

        permissions = coerce_mapping_sequence(data.get("permissions"))
        if not permissions:
            return []

        allowed_domains = (
            {domain.lower() for domain in context.organization_domains}
            if context and context.organization_domains
            else set()
        )
        external_users = [
            permission
            for permission in permissions
            if _is_external_user(permission, allowed_domains)
        ]

        if not external_users:
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        evidence = build_external_sharing_evidence(
            site_name=resource.name,
            site_url=data.get("web_url"),
            site_id=resource.external_id,
            sharing_capability=data.get("sharing_capability"),
            external_sharing_enabled=external_sharing,
            external_permissions=external_users,
        )

        summary = (
            "SharePoint site has external sharing enabled with "
            f"{len(external_users)} external users having access"
        )

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                f"SharePoint site {resource.name or resource.external_id} "
                f"shared with {len(external_users)} external users"
            ),
            summary=summary,
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]


def _is_external_user(
    permission: Mapping[str, Any],
    allowed_domains: set[str],
) -> bool:
    email = _extract_email(permission)
    if not email:
        return False
    lower_email = email.lower()
    if lower_email.endswith(("@gmail.com", "@yahoo.com", "@hotmail.com")):
        return True
    domain = lower_email.split("@")[-1] if "@" in lower_email else ""
    return bool(domain) and domain not in allowed_domains


def _extract_email(permission: Mapping[str, Any]) -> str | None:
    granted = coerce_mapping(permission.get("grantedToV2"))
    if granted is None:
        return None
    user = coerce_mapping(granted.get("user"))
    if user is None:
        return None
    email = user.get("email")
    return email if isinstance(email, str) else None
