"""Producer for detecting KMS keys without automatic rotation."""

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
class KMSKeyRotationDisabledProducer(BaseAWSProducer):
    """Detect KMS Customer Master Keys without automatic rotation enabled.

    Key rotation limits the amount of data encrypted with a single key version,
    reducing the blast radius of key compromise.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.kms.key"}

    @property
    def finding_name(self) -> str:
        return "AWS: KMS Key Rotation Disabled"

    @property
    def rule_name(self) -> str:
        return "aws_kms_key_rotation_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return (
            "AWS KMS Customer Master Key does not have automatic key rotation enabled. "
            "Key rotation limits exposure from compromised keys."
        )

    @property
    def remediation(self) -> str:
        return (
            "Enable automatic key rotation for the KMS CMK. "
            "Note: Rotation is only available for symmetric CMKs. "
            "For asymmetric keys, implement manual rotation procedures."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["SC-12", "SC-12(1)", "SC-28"],
            "cwe": ["CWE-320"],
            "cis_aws": ["3.8"],
            "mitre_attack": ["T1552.004"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate KMS key rotation configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Only check customer-managed symmetric keys
        key_manager = data.get("key_manager", "").upper()
        key_state = data.get("key_state", "").lower()
        key_spec = data.get("key_spec", "")

        # Skip AWS managed keys
        if key_manager != "CUSTOMER":
            return findings

        # Skip disabled or pending deletion keys
        if key_state not in ["enabled", "Enabled"]:
            return findings

        # Only symmetric keys support rotation
        if "SYMMETRIC" not in key_spec.upper():
            return findings

        # Check rotation status
        rotation_enabled = data.get("key_rotation_enabled", False)

        if rotation_enabled:
            return findings

        # Build risk factors
        risk_factors: list[str] = ["rotation_disabled"]

        # Check key usage
        key_usage = data.get("key_usage", "")
        if key_usage == "ENCRYPT_DECRYPT":
            risk_factors.append("encryption_key")

        # Check for aliases suggesting production use
        aliases = data.get("aliases", []) or []
        alias_names = [a.get("alias_name", "") if isinstance(a, dict) else str(a) for a in aliases]
        if any("prod" in alias.lower() for alias in alias_names):
            risk_factors.append("production_key")

        evidence = {
            "key_id": data.get("key_id") or resource.external_id,
            "key_arn": resource.external_id,
            "key_manager": key_manager,
            "key_state": key_state,
            "key_spec": key_spec,
            "key_usage": key_usage,
            "rotation_enabled": rotation_enabled,
            "aliases": alias_names[:10],
            "creation_date": data.get("creation_date"),
            "description": data.get("description"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        key_id = data.get("key_id") or resource.name or resource.external_id

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"KMS key {key_id} does not have automatic rotation enabled",
                summary=(
                    f"Key type: {key_spec}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
