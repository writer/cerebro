import os
from datetime import datetime

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("KMS_PROVIDER", "aws")

import pytest

from cerebro.attack_path.graph_model import AttackGraph, EdgeType, NodeType
from cerebro.attack_path.scoring import AttackGraphScoring
from cerebro.attack_path.service_identity import ServiceIdentityEdge, TrustMechanism


class StubServiceIdentityMapper:
    def __init__(self, edges):
        self.edges = edges
        self.calls = 0

    async def discover_service_identities(self, org_id: str):
        self.calls += 1
        return self.edges


def build_service_edge(
    edge_id="svc-1",
    mechanism=TrustMechanism.OIDC_FEDERATION,
):
    return ServiceIdentityEdge(
        edge_id=edge_id,
        source_service="github_actions_service",
        target_service="aws_deployment_role",
        trust_mechanism=mechanism,
        provider_source="github",
        provider_target="aws",
        trust_policy={},
        allowed_repositories=["repo"],
        allowed_branches=["main"],
        conditions=["oidc"],
        risk_score=0.6,
        exploitability="medium",
        discovered_at=datetime.utcnow(),
        last_verified=datetime.utcnow(),
        metadata={"note": "generated", "permission": "sts:AssumeRole"},
    )


@pytest.mark.asyncio
async def test_attack_graph_ingests_service_identity_edges():
    edge = build_service_edge()
    mapper = StubServiceIdentityMapper([edge])
    graph = AttackGraph(
        "org-1", scoring=AttackGraphScoring(), service_identity_mapper=mapper
    )

    await graph._add_service_identity_edges()

    assert mapper.calls == 1
    assert edge.edge_id in graph.edges
    attack_edge = graph.edges[edge.edge_id]
    assert attack_edge.edge_type == EdgeType.OIDC_FEDERATION
    assert (
        attack_edge.metadata["trust_mechanism"] == TrustMechanism.OIDC_FEDERATION.value
    )

    # Source node created as service type
    assert "github_actions_service" in graph.nodes
    node = graph.nodes["github_actions_service"]
    assert node.node_type == NodeType.SERVICE


@pytest.mark.asyncio
async def test_attack_graph_sets_service_edge_weights_from_scoring():
    custom_config = {
        "edge": {"mechanism_weights": {TrustMechanism.OIDC_FEDERATION.value: 0.1}},
        "privilege_levels": {"default": 5},
    }

    edge = build_service_edge(mechanism=TrustMechanism.WORKLOAD_IDENTITY)
    mapper = StubServiceIdentityMapper([edge])
    graph = AttackGraph(
        "org-1",
        scoring=AttackGraphScoring(custom_config),
        service_identity_mapper=mapper,
    )

    await graph._add_service_identity_edges()
    attack_edge = graph.edges[edge.edge_id]
    assert attack_edge.privilege_level == 5
    assert 0 < attack_edge.weight <= 1
