"""Producer for detecting unencrypted EBS volumes."""

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

from .base import BaseAWSProducer


@register_producer
class EBSEncryptionDisabledProducer(BaseAWSProducer):
    """Detect EBS volumes without encryption enabled.

    Unencrypted EBS volumes expose data at rest, potentially violating
    compliance requirements and data protection policies.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.ec2.volume", "aws.ebs.volume"}

    @property
    def finding_name(self) -> str:
        return "AWS: EBS Volume Not Encrypted"

    @property
    def rule_name(self) -> str:
        return "aws_ebs_encryption_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return (
            "EBS volume does not have encryption enabled. "
            "Unencrypted volumes expose data at rest."
        )

    @property
    def remediation(self) -> str:
        return (
            "Create an encrypted snapshot of the volume and restore from it. "
            "Enable default EBS encryption at the account level. "
            "Use customer-managed KMS keys for additional control."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-28", "SC-28(1)"],
            "cwe": ["CWE-311"],
            "cis_aws": ["2.2.1"],
            "mitre_attack": ["T1530"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate EBS volume encryption status."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check encryption status
        encrypted = data.get("encrypted", False)

        if encrypted:
            return findings

        # Get volume details
        volume_state = data.get("state", "").lower()
        volume_type = data.get("volume_type", "")
        size_gib = data.get("size")

        # Skip volumes in certain states
        if volume_state in ["deleting", "deleted"]:
            return findings

        # Build risk factors
        risk_factors: list[str] = ["not_encrypted"]

        # Check if volume is attached
        attachments = data.get("attachments", []) or []
        if attachments:
            risk_factors.append("attached_to_instance")

        # Check volume size (larger volumes = more data at risk)
        if size_gib and size_gib > 100:
            risk_factors.append("large_volume")

        # Check for boot volume
        for attachment in attachments:
            device = attachment.get("Device", "") if isinstance(attachment, dict) else ""
            if "/dev/xvda" in device or "/dev/sda" in device:
                risk_factors.append("boot_volume")
                break

        # Determine severity
        severity = self.severity
        if "boot_volume" in risk_factors:
            severity = Severity.HIGH

        evidence = {
            "volume_id": resource.external_id,
            "volume_type": volume_type,
            "size_gib": size_gib,
            "state": volume_state,
            "encrypted": encrypted,
            "kms_key_id": data.get("kms_key_id"),
            "attachments": [
                {
                    "instance_id": a.get("InstanceId"),
                    "device": a.get("Device"),
                    "state": a.get("State"),
                }
                for a in attachments[:5]
                if isinstance(a, dict)
            ],
            "availability_zone": data.get("availability_zone"),
            "iops": data.get("iops"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"EBS volume {resource.external_id} is not encrypted",
                summary=(
                    f"Volume type: {volume_type}, Size: {size_gib}GB. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
