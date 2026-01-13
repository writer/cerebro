"""Producer for detecting publicly accessible Lambda functions."""

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


def _is_policy_public(policy: dict[str, Any] | None, account_id: str | None) -> bool:
    """Check if a resource-based policy allows public access."""
    if not policy:
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})

        # Check for wildcard principal
        if principal == "*":
            # Check if there's a condition limiting access
            condition = statement.get("Condition", {})
            if not _has_account_condition(condition, account_id):
                return True

        if isinstance(principal, dict):
            aws_principal = principal.get("AWS", [])
            if isinstance(aws_principal, str):
                aws_principal = [aws_principal]

            for p in aws_principal:
                if p == "*":
                    condition = statement.get("Condition", {})
                    if not _has_account_condition(condition, account_id):
                        return True

    return False


def _has_account_condition(condition: dict[str, Any], account_id: str | None) -> bool:
    """Check if condition restricts to specific account."""
    if not condition or not account_id:
        return False

    for _condition_type, conditions in condition.items():
        if not isinstance(conditions, dict):
            continue

        for key, value in conditions.items():
            key_lower = key.lower()
            if "sourceaccount" in key_lower or "principalaccount" in key_lower:
                if isinstance(value, str) and value == account_id:
                    return True
                if isinstance(value, list) and account_id in value:
                    return True

    return False


@register_producer
class LambdaPublicAccessProducer(BaseAWSProducer):
    """Detect Lambda functions with public access.

    Lambda functions with public resource policies or public function URLs
    can be invoked by anyone, potentially exposing sensitive functionality.
    """

    @property
    def resource_types(self) -> set[str]:
        return {"aws.lambda.function"}

    @property
    def finding_name(self) -> str:
        return "AWS: Lambda Function Publicly Accessible"

    @property
    def rule_name(self) -> str:
        return "aws_lambda_public_access"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Lambda function is publicly accessible via resource policy or "
            "function URL without authentication."
        )

    @property
    def remediation(self) -> str:
        return (
            "Remove public access from the resource policy. "
            "For function URLs, use AWS_IAM auth type instead of NONE. "
            "Restrict access to specific AWS accounts or principals."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["AC-3", "AC-6", "SC-7"],
            "cwe": ["CWE-284", "CWE-668"],
            "cis_aws": ["2.1.3"],
            "mitre_attack": ["T1190"],
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Lambda function for public access."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Get function details
        function_name = data.get("function_name") or resource.name
        account_id = data.get("account_id")

        # Check for public resource policy
        policy = data.get("policy") or data.get("resource_policy")
        has_public_policy = False
        if policy:
            if isinstance(policy, str):
                import json
                try:
                    policy = json.loads(policy)
                except (json.JSONDecodeError, TypeError):
                    policy = None

            if policy:
                has_public_policy = _is_policy_public(policy, account_id)

        # Check for public function URL
        url_config = data.get("url_config") or data.get("function_url_config")
        has_public_url = False
        function_url = None

        if url_config:
            auth_type = url_config.get("AuthType") or url_config.get("auth_type", "")
            if auth_type.upper() == "NONE":
                has_public_url = True
                function_url = url_config.get("FunctionUrl") or url_config.get("url")

        # Only create finding if there's public access
        if not has_public_policy and not has_public_url:
            return findings

        # Build risk factors
        risk_factors: list[str] = []

        if has_public_policy:
            risk_factors.append("public_resource_policy")
        if has_public_url:
            risk_factors.append("public_function_url")

        # Check for sensitive indicators
        runtime = data.get("runtime", "")
        if data.get("environment", {}).get("Variables"):
            risk_factors.append("has_environment_variables")

        if data.get("vpc_config"):
            risk_factors.append("vpc_attached")

        # Determine severity
        severity = self.severity
        if has_public_policy and has_public_url:
            severity = Severity.CRITICAL

        evidence = {
            "function_name": function_name,
            "function_arn": resource.external_id,
            "runtime": runtime,
            "has_public_policy": has_public_policy,
            "has_public_url": has_public_url,
            "function_url": function_url,
            "url_auth_type": url_config.get("AuthType") if url_config else None,
            "vpc_config": bool(data.get("vpc_config")),
            "has_environment_vars": bool(data.get("environment", {}).get("Variables")),
            "risk_factors": risk_factors,
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        exposure_types = []
        if has_public_policy:
            exposure_types.append("resource policy")
        if has_public_url:
            exposure_types.append("function URL")

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Lambda function {function_name} is publicly accessible",
                summary=(
                    f"Public via: {', '.join(exposure_types)}. "
                    f"Runtime: {runtime}. "
                    f"Risk factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings
