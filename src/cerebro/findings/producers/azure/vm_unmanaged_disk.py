"""Producer for detecting Azure VMs with unmanaged disks."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseAzureProducer


@register_producer
class AzureVMUnmanagedDiskProducer(BaseAzureProducer):
    """Detect Azure VMs using unmanaged disks."""

    @property
    def resource_types(self) -> set[str]:
        return {"azure.compute.vm", "azure.vm"}

    @property
    def finding_name(self) -> str:
        return "Azure: VM Using Unmanaged Disk"

    @property
    def rule_name(self) -> str:
        return "azure_vm_unmanaged_disk"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return "Azure VM is using unmanaged disks instead of managed disks."

    @property
    def remediation(self) -> str:
        return (
            "Convert to managed disks for better reliability and security. "
            "Managed disks provide better encryption options and integration with RBAC."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-28"],
            "cwe": ["CWE-311"],
            "cis_azure": ["7.1"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate VM disk configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check for managed disk
        storage_profile = data.get("storage_profile", {}) or {}
        os_disk = storage_profile.get("os_disk", {}) or {}
        managed_disk = os_disk.get("managed_disk")

        # If managed_disk is set, it's using managed disks
        if managed_disk:
            return findings

        # Check for VHD (indicates unmanaged)
        vhd = os_disk.get("vhd")
        if not vhd:
            return findings  # Can't determine, skip

        disk_encryption = data.get("encryption_at_host_enabled", False)

        risk_factors: list[str] = ["unmanaged_disk"]
        if not disk_encryption:
            risk_factors.append("encryption_at_host_disabled")

        evidence = {
            "vm_name": resource.name,
            "vm_id": resource.external_id,
            "subscription_id": data.get("subscription_id"),
            "resource_group": data.get("resource_group"),
            "os_disk_vhd": vhd.get("uri") if isinstance(vhd, dict) else vhd,
            "encryption_at_host_enabled": disk_encryption,
            "vm_size": data.get("hardware_profile", {}).get("vm_size"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"VM {resource.name} uses unmanaged disk",
                summary="Using unmanaged VHD instead of managed disk",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
