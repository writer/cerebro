"""Producer for detecting EC2 instances internet-facing with IAM roles."""

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
class EC2InternetFacingIAMProducer(BaseAWSProducer):
    """Detect EC2 instances that are internet-facing with IAM instance profiles.

    Internet-facing instances with IAM roles are high-risk because:
    - Compromise of the instance grants access to AWS APIs
    - Attackers can use instance credentials for lateral movement
    - IMDS can be exploited to steal credentials (SSRF attacks)
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.ec2.instance"}

    @property
    def finding_name(self) -> str:
        return "AWS: Internet-facing EC2 with IAM Role"

    @property
    def rule_name(self) -> str:
        return "aws_ec2_internet_facing_iam_role"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "EC2 instance is internet-facing and has an IAM instance profile attached. "
            "Compromise of this instance could grant attackers AWS API access."
        )

    @property
    def remediation(self) -> str:
        return (
            "Remove the public IP or place the instance behind a load balancer. "
            "Ensure IMDSv2 is enforced to mitigate SSRF credential theft. "
            "Apply least-privilege IAM policies to the instance profile."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-4", "SC-7", "AC-6"],
            "cwe": ["CWE-284", "CWE-918"],
            "mitre_attack": ["T1078.004", "T1552.005"],
            "cis_aws": ["2.3.3"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate EC2 instance for internet exposure with IAM role."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Skip terminated instances
        state = data.get("state", "").lower()
        if state == "terminated":
            return findings

        public_ip = data.get("public_ip") or data.get("public_ip_address")
        instance_profile = data.get("iam_instance_profile") or data.get("instance_profile")

        # Only flag if both public IP and instance profile exist
        if not public_ip or not instance_profile:
            return findings

        # Extract profile details
        profile_arn = (
            instance_profile.get("Arn")
            if isinstance(instance_profile, dict)
            else str(instance_profile)
        )

        # Check IMDSv2 status
        metadata_options = data.get("metadata_options", {}) or {}
        http_tokens = metadata_options.get("HttpTokens", "optional")
        imdsv2_enforced = http_tokens == "required"

        # Build risk factors
        risk_factors: list[str] = ["internet_facing", "has_iam_role"]

        if not imdsv2_enforced:
            risk_factors.append("imdsv1_enabled")

        # Check for admin-like policies
        attached_policies = data.get("attached_policies", []) or []
        admin_policy_keywords = ["admin", "fullaccess", "poweruser"]
        has_admin_policy = any(
            any(kw in str(p).lower() for kw in admin_policy_keywords)
            for p in attached_policies
        )
        if has_admin_policy:
            risk_factors.append("has_admin_policy")

        # Determine severity
        severity = self.severity
        if has_admin_policy:
            severity = Severity.CRITICAL
        elif not imdsv2_enforced:
            severity = Severity.HIGH

        evidence = {
            "instance_id": resource.external_id,
            "instance_name": resource.name,
            "public_ip": public_ip,
            "public_dns": data.get("public_dns_name"),
            "instance_profile_arn": profile_arn,
            "imdsv2_enforced": imdsv2_enforced,
            "http_tokens": http_tokens,
            "attached_policies": attached_policies[:10],
            "security_groups": data.get("security_groups", []),
            "vpc_id": data.get("vpc_id"),
            "subnet_id": data.get("subnet_id"),
            "risk_factors": risk_factors,
            "state": state,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"EC2 instance {resource.name or resource.external_id} is internet-facing with IAM role",
                summary=(
                    f"Instance at {public_ip} has IAM profile {profile_arn}. "
                    f"IMDSv2: {'enforced' if imdsv2_enforced else 'NOT enforced'}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
