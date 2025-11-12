"""Tests for Kubernetes namespace network policy producer."""

from __future__ import annotations

from datetime import datetime

from cerebro.domain.entities import ConfigEntity, ResourceEntity, Severity
from cerebro.findings.producers.kubernetes.network_policy import (
    K8sNamespaceNetworkPolicyProducer,
)


def _make_namespace_resource(name: str) -> ResourceEntity:
    return ResourceEntity(
        external_id=name,
        resource_type="k8s.namespace",
        provider="kubernetes",
        name=name,
    )


def test_namespace_missing_all_network_policies() -> None:
    producer = K8sNamespaceNetworkPolicyProducer()

    resource = _make_namespace_resource("prod")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "name": "prod",
            "networkPolicies": [],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    exposure_types = {exposure["type"] for exposure in finding.evidence["exposures"]}
    assert exposure_types == {"missing_network_policies"}


def test_namespace_with_default_deny_policies() -> None:
    producer = K8sNamespaceNetworkPolicyProducer()

    resource = _make_namespace_resource("secure")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "name": "secure",
            "networkPolicies": [
                {
                    "name": "default-deny",
                    "policyTypes": ["Ingress", "Egress"],
                    "selectsAllPods": True,
                    "ingressRuleCount": 0,
                    "egressRuleCount": 0,
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert findings == []


def test_namespace_missing_egress_policy() -> None:
    producer = K8sNamespaceNetworkPolicyProducer()

    resource = _make_namespace_resource("apps")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "name": "apps",
            "networkPolicies": [
                {
                    "name": "deny-ingress",
                    "policyTypes": ["Ingress"],
                    "selectsAllPods": True,
                    "ingressRuleCount": 0,
                    "egressRuleCount": 0,
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    exposure_types = {exposure["type"] for exposure in finding.evidence["exposures"]}
    assert exposure_types == {"missing_egress_policy"}


def test_namespace_missing_default_deny_egress() -> None:
    producer = K8sNamespaceNetworkPolicyProducer()

    resource = _make_namespace_resource("team")
    config = ConfigEntity(
        resource_external_id=resource.external_id,
        captured_at=datetime.utcnow(),
        normalized_config={
            "name": "team",
            "networkPolicies": [
                {
                    "name": "allow-egress",
                    "policyTypes": ["Ingress", "Egress"],
                    "selectsAllPods": True,
                    "ingressRuleCount": 0,
                    "egressRuleCount": 1,
                }
            ],
        },
    )

    findings = producer.evaluate(resource, config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    exposure_types = {exposure["type"] for exposure in finding.evidence["exposures"]}
    assert exposure_types == {"missing_default_deny_egress"}
