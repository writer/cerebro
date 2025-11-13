"""Regression snapshots for complex producer scenarios."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cerebro.domain.entities import ConfigEntity, ResourceEntity
from cerebro.findings.producers.aws.load_balancer_target_exposure import (
    AwsLoadBalancerTargetExposureProducer,
)
from cerebro.findings.producers.azure.storage_secret_artifacts import (
    AzureStorageSecretArtifactProducer,
)
from cerebro.findings.producers.gcp.bucket_secret_artifacts import (
    GCPBucketSecretArtifactProducer,
)
from cerebro.findings.producers.github.runner_exposure import (
    GithubRunnerPublicExposureProducer,
)
from cerebro.findings.producers.kubernetes.service_public_exposure import (
    K8sServicePublicExposureProducer,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    "case_name",
    [
        "aws_alb_public_targets",
        "k8s_service_public_exposure",
        "azure_container_secret_artifacts",
        "gcp_bucket_secret_artifacts",
        "github_runner_public_exposure",
    ],
)
def test_producer_snapshot(case_name: str) -> None:
    """Ensure producers emit stable findings for real-world payloads."""

    producer_map = {
        "aws_alb_public_targets": AwsLoadBalancerTargetExposureProducer(),
        "k8s_service_public_exposure": K8sServicePublicExposureProducer(),
        "azure_container_secret_artifacts": AzureStorageSecretArtifactProducer(),
        "gcp_bucket_secret_artifacts": GCPBucketSecretArtifactProducer(),
        "github_runner_public_exposure": GithubRunnerPublicExposureProducer(),
    }

    input_path = FIXTURE_ROOT / f"{case_name}_input.json"
    expected_path = FIXTURE_ROOT / f"{case_name}_expected.json"

    payload = json.loads(input_path.read_text())
    expected = json.loads(expected_path.read_text())

    resource_data = payload["resource"]
    config_data = payload["config"]

    resource = ResourceEntity(
        external_id=resource_data["external_id"],
        resource_type=resource_data["resource_type"],
        provider=resource_data["provider"],
        name=resource_data.get("name"),
        metadata=resource_data.get("metadata", {}),
    )

    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime(2024, 1, 1, tzinfo=UTC),
        normalized_config=config_data,
    )

    producer = producer_map[case_name]
    findings = producer.evaluate(resource, config)

    assert findings, "Producer did not emit a finding for fixture"
    assert len(findings) == 1, "Fixture should yield exactly one finding"

    finding = findings[0]

    assert finding.title == expected["title"]
    assert finding.summary == expected["summary"]
    assert finding.severity.value == expected["severity"]
    assert finding.evidence == expected["evidence"]
