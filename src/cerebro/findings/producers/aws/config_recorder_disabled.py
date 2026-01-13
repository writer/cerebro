"""Producer for detecting AWS Config recorder not enabled."""

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
class ConfigRecorderDisabledProducer(BaseAWSProducer):
    """Detect regions without AWS Config recorder enabled."""

    @property
    def resource_types(self) -> set[str]:
        return {"aws.config.recorder"}

    @property
    def finding_name(self) -> str:
        return "AWS: Config Recorder Not Enabled"

    @property
    def rule_name(self) -> str:
        return "aws_config_recorder_disabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return "AWS Config recorder is not enabled or is in failure state."

    @property
    def remediation(self) -> str:
        return (
            "Enable AWS Config recorder in all regions. "
            "Configure delivery channel to S3 bucket. "
            "Enable all resource types for recording."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["CM-8", "SI-4"],
            "cwe": ["CWE-778"],
            "cis_aws": ["3.5"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate AWS Config recorder configuration."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        recorder_name = data.get("name")
        recording = data.get("recording", False)
        last_status = data.get("last_status", "")

        # No issues if recording and not in failure
        if recording and last_status != "Failure":
            return findings

        risk_factors: list[str] = []
        if not recorder_name:
            risk_factors.append("no_recorder_configured")
        elif not recording:
            risk_factors.append("recorder_disabled")
        elif last_status == "Failure":
            risk_factors.append("recorder_in_failure")

        evidence = {
            "recorder_name": recorder_name,
            "region": data.get("region"),
            "recording": recording,
            "last_status": last_status,
            "all_supported": data.get("recording_group", {}).get("all_supported"),
            "include_global_resource_types": data.get("recording_group", {}).get("include_global_resource_types"),
            "role_arn": data.get("role_arn"),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        status_msg = "not configured" if not recorder_name else ("disabled" if not recording else f"in {last_status} state")

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"AWS Config recorder {status_msg} in {data.get('region', 'region')}",
                summary=f"Recording: {recording}. Status: {last_status or 'N/A'}",
                evidence=evidence,
                severity=self.severity,
            )
        )

        return findings
