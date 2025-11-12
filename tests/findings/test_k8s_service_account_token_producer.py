"""Tests for Kubernetes service account token exposure producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.kubernetes.service_account_token import (
    K8sServiceAccountTokenExposureProducer,
)

SERVICE_ACCOUNT_MOUNT = "/var/run/secrets/kubernetes.io/serviceaccount"
SERVICE_ACCOUNT_MOUNT_TOKEN = f"{SERVICE_ACCOUNT_MOUNT}/token"


def _make_resource(external_id: str = "ns/pod") -> ResourceEntity:
    return ResourceEntity(
        external_id=external_id,
        resource_type="k8s.pod",
        provider="kubernetes",
        name=external_id.split("/", 1)[-1],
    )


def test_service_account_default_token_mount():
    producer = K8sServiceAccountTokenExposureProducer()

    resource = _make_resource("prod/api")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "namespace": "prod",
            "serviceAccount": None,
            "automountServiceAccountToken": None,
            "containers": [
                {
                    "name": "api",
                    "volumeMounts": [
                        {
                            "name": "token",
                            "mountPath": SERVICE_ACCOUNT_MOUNT,
                        }
                    ],
                }
            ],
            "volumes": [
                {
                    "name": "token",
                    "projectedSources": [
                        {
                            "type": "serviceAccountToken",
                            "audience": "api",
                            "expirationSeconds": 3600,
                            "path": "token",
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    exposure_types = {exp["type"] for exp in finding.evidence["exposures"]}
    assert {
        "default_service_account",
        "service_account_token_mount",
        "projected_service_account_token",
    }.issubset(exposure_types)


def test_service_account_custom_automount_disabled():
    producer = K8sServiceAccountTokenExposureProducer()

    resource = _make_resource("team/worker")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "namespace": "team",
            "serviceAccount": "ci-runner",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "worker",
                    "volumeMounts": [],
                }
            ],
            "volumes": [],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_service_account_projected_token_custom_account():
    producer = K8sServiceAccountTokenExposureProducer()

    resource = _make_resource("team/cron")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "namespace": "team",
            "serviceAccount": "cron-sa",
            "automountServiceAccountToken": True,
            "containers": [
                {
                    "name": "cron",
                    "volumeMounts": [
                        {
                            "name": "token",
                            "mountPath": SERVICE_ACCOUNT_MOUNT_TOKEN,
                        }
                    ],
                }
            ],
            "volumes": [
                {
                    "name": "token",
                    "projectedSources": [
                        {
                            "type": "serviceAccountToken",
                            "audience": "metrics",
                            "expirationSeconds": 900,
                            "path": "token",
                        }
                    ],
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    exposure_types = {exp["type"] for exp in finding.evidence["exposures"]}
    assert "service_account_token_mount" in exposure_types
