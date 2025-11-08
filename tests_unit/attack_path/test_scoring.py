import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("KMS_PROVIDER", "aws")

from datetime import datetime

import pytest

from cerebro.attack_path.scoring import AttackGraphScoring
from cerebro.attack_path.service_identity import ServiceIdentityEdge, TrustMechanism


class DummyPrincipal:
    def __init__(self, principal_type="user", provider="internal", is_active=True):
        self.principal_type = principal_type
        self.provider = provider
        self.is_active = is_active


class DummyResource:
    def __init__(self, resource_type: str, metadata=None):
        self.resource_type = resource_type
        self.metadata = metadata or {}


def make_service_edge(**overrides):
    base = {
        "edge_id": "edge-1",
        "source_service": "github_actions_app",
        "target_service": "aws_role_deploy",
        "trust_mechanism": TrustMechanism.OIDC_FEDERATION,
        "provider_source": "github",
        "provider_target": "aws",
        "trust_policy": {},
        "allowed_repositories": ["repo"],
        "allowed_branches": ["main"],
        "conditions": ["oidc"],
        "risk_score": 0.6,
        "exploitability": "medium",
        "discovered_at": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
        "metadata": {"permission": "sts:AssumeRole"},
    }
    base.update(overrides)
    return ServiceIdentityEdge(**base)


def test_principal_risk_respects_service_account_bonus():
    scorer = AttackGraphScoring()
    user_risk = scorer.principal_risk(DummyPrincipal())
    sa_risk = scorer.principal_risk(DummyPrincipal(principal_type="service_account"))
    assert sa_risk > user_risk


def test_resource_risk_production_bonus():
    scorer = AttackGraphScoring()
    base = scorer.resource_risk(DummyResource("aws.s3.bucket"))
    prod = scorer.resource_risk(DummyResource("aws.s3.bucket", metadata={"environment": "production"}))
    assert prod > base


def test_edge_weight_uses_privilege_mapping():
    scorer = AttackGraphScoring()
    admin_weight = scorer.edge_weight("iam:AdminAccess", "aws")
    read_weight = scorer.edge_weight("s3:GetObject", "aws")
    assert admin_weight < read_weight


def test_service_edge_conversion_uses_mechanism_weight():
    scorer = AttackGraphScoring()
    edge = make_service_edge()
    weight = scorer.service_edge_weight(edge)
    assert 0 < weight <= 1
    assert scorer.service_edge_privilege(edge) >= 1


@pytest.mark.parametrize(
    "mechanism,expected_type",
    [
        (TrustMechanism.OIDC_FEDERATION, "oidc"),
        (TrustMechanism.WORKLOAD_IDENTITY, "workload"),
        (TrustMechanism.INSTANCE_METADATA, "instance"),
    ],
)
def test_service_edge_metadata_contains_mechanism(mechanism, expected_type):
    scorer = AttackGraphScoring()
    edge = make_service_edge(trust_mechanism=mechanism)
    metadata = scorer.service_edge_metadata(edge)
    assert metadata["trust_mechanism"].startswith(mechanism.value)
