"""Detect SharePoint sites with anonymous sharing links."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
    clip_sequence,
    coerce_mapping_sequence,
    resolve_rule_id,
)


def _has_anonymous_edit_link(permissions: Sequence[Mapping[str, Any]]) -> bool:
    for permission in permissions:
        link = permission.get("link")
        if not isinstance(link, Mapping):
            continue
        scope = link.get("scope")
        link_type = link.get("type")
        if scope == "anonymous" and link_type in {"edit", "write"}:
            return True
    return False


@register_producer
class M365SharePointAnonymousLinkProducer(BaseFindingProducer):
    """Flags SharePoint sites that expose anonymous editable links."""

    @property
    def desired_sources(self) -> set[str]:
        return {"m365"}

    @property
    def resource_types(self) -> set[str]:
        return {"m365.sharepoint.site"}

    @property
    def finding_name(self) -> str:
        return "Microsoft 365: SharePoint site exposes anonymous edit link"

    @property
    def rule_name(self) -> str:
        return "m365_sharepoint_anonymous_edit"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return "SharePoint site permits anyone with a link to edit content"

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-17"],
            "cis": ["1.1.18"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        normalized = config.normalized_config or {}
        permissions = coerce_mapping_sequence(normalized.get("permissions"))

        if not _has_anonymous_edit_link(permissions):
            return []

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        anonymous_links = [
            {
                "scope": permission.get("link", {}).get("scope"),
                "type": permission.get("link", {}).get("type"),
                "roles": permission.get("roles"),
            }
            for permission in permissions
            if permission.get("link", {}).get("scope") == "anonymous"
        ]

        evidence = {
            "site_url": normalized.get("web_url"),
            "sharing_capability": normalized.get("sharing_capability"),
            "anonymous_links": clip_sequence(anonymous_links, limit=5),
        }

        finding = self.create_finding(
            resource=resource,
            rule_id=rule_id,
            title=(
                "SharePoint site "
                f"{resource.name or resource.external_id} allows anonymous editing"
            ),
            summary=
            (
                "Anonymous edit links are enabled for this SharePoint site, allowing "
                "anyone with the link to modify content without authentication."
            ),
            evidence=evidence,
            severity=self.severity,
        )

        return [finding]
