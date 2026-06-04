package findings

import (
	"context"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type stubRiskDeltaGraphStore struct {
	requests []ports.CypherQueryRequest
	rows     [][]ports.CypherRow
}

func (s *stubRiskDeltaGraphStore) Ping(context.Context) error { return nil }

func (s *stubRiskDeltaGraphStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, ports.ErrGraphEntityNotFound
}

func (s *stubRiskDeltaGraphStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	idx := len(s.requests) - 1
	if idx >= len(s.rows) {
		return nil, nil
	}
	return s.rows[idx], nil
}

func TestSimulateRiskDeltaWithGraphRemovePublicExposure(t *testing.T) {
	finding := compoundRiskFinding("cloud-public-prod-secrets", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_secret_store:prod-secrets", "public_network_ingress")
	finding.Attributes["internet_exposed"] = "true"
	finding.Attributes["crown_jewel"] = "true"
	store := &stubRiskDeltaGraphStore{
		rows: [][]ports.CypherRow{
			{
				riskDeltaGraphRow("cloud-public-prod-secrets", "urn:cerebro:writer:aws_secret_store:prod-secrets", "", ""),
				riskDeltaGraphRow("cloud-public-prod-secrets", "urn:cerebro:writer:aws_secret_store:prod-secrets", "urn:cerebro:writer:aws_public_principal:public_internet", "can_reach"),
			},
			{
				riskDeltaGraphRow("cloud-public-prod-secrets", "urn:cerebro:writer:aws_secret_store:prod-secrets", "", ""),
			},
		},
	}

	report, err := SimulateRiskDeltaWithGraph(context.Background(), []*ports.FindingRecord{finding}, store, RiskDeltaSimulationOptions{
		TenantID:       "writer",
		ScenarioType:   RiskDeltaScenarioRemovePublicExposure,
		TargetURN:      "urn:cerebro:writer:aws_secret_store:prod-secrets",
		Limit:          10,
		GraphPathLimit: 1,
	})
	if err != nil {
		t.Fatalf("SimulateRiskDeltaWithGraph() error = %v", err)
	}

	if len(store.requests) != 2 {
		t.Fatalf("ExecuteReadCypher calls = %d, want before and after path queries", len(store.requests))
	}
	beforeRemovedRelations, ok := store.requests[0].Params["removed_relations"].([]string)
	if !ok || len(beforeRemovedRelations) != 0 {
		t.Fatalf("before query removed_relations = %#v, want empty list", store.requests[0].Params["removed_relations"])
	}
	removedRelations, ok := store.requests[1].Params["removed_relations"].([]string)
	if !ok || len(removedRelations) != 1 || removedRelations[0] != "can_reach" {
		t.Fatalf("after query removed_relations = %#v, want can_reach", store.requests[1].Params["removed_relations"])
	}
	if report.RiskScoreReduction <= 0 {
		t.Fatalf("RiskScoreReduction = %d, want positive reduction", report.RiskScoreReduction)
	}
	if report.AttackPathCountReduction != 1 {
		t.Fatalf("AttackPathCountReduction = %d, want one graph path removed", report.AttackPathCountReduction)
	}
	if len(report.RemovedAttackPaths) != 1 || !riskSimulationAttackPathContainsRelation(report.RemovedAttackPaths, "can_reach") {
		t.Fatalf("RemovedAttackPaths = %#v, want removed can_reach path", report.RemovedAttackPaths)
	}
	if !stringSliceContains(report.Reasons, "graph_query_risk_delta_paths") {
		t.Fatalf("Reasons = %#v, want graph query reason", report.Reasons)
	}
}

func TestSimulateRiskDeltaWithGraphCompromiseIdentityUsesBlastRadius(t *testing.T) {
	finding := compoundRiskFinding("sensitive-data", dataSensitiveAssetRiskRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_secret_store:prod-secrets", "data_access")
	finding.Attributes["data_classification"] = "restricted"
	store := &stubRiskDeltaGraphStore{
		rows: [][]ports.CypherRow{
			{
				riskDeltaGraphRow("sensitive-data", "urn:cerebro:writer:aws_secret_store:prod-secrets", "", ""),
			},
			{
				{Values: map[string]any{
					"resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
					"privileged":   true,
				}},
			},
			{
				riskDeltaGraphRow("sensitive-data", "urn:cerebro:writer:aws_secret_store:prod-secrets", "", ""),
			},
		},
	}

	report, err := SimulateRiskDeltaWithGraph(context.Background(), []*ports.FindingRecord{finding}, store, RiskDeltaSimulationOptions{
		TenantID:       "writer",
		ScenarioType:   RiskDeltaScenarioCompromiseIdentity,
		TargetURN:      "urn:cerebro:writer:okta_user:admin@example.com",
		Limit:          10,
		GraphPathLimit: 1,
	})
	if err != nil {
		t.Fatalf("SimulateRiskDeltaWithGraph() error = %v", err)
	}

	if len(store.requests) != 3 {
		t.Fatalf("ExecuteReadCypher calls = %d, want before path, blast radius, after path queries", len(store.requests))
	}
	if !strings.Contains(store.requests[1].Query, "RELATION*1..3") {
		t.Fatalf("second query = %q, want graph blast-radius traversal", store.requests[1].Query)
	}
	if report.RiskScoreChange <= 0 {
		t.Fatalf("RiskScoreChange = %d, want positive compromise risk increase", report.RiskScoreChange)
	}
	if report.AttackPathScoreChange <= 0 {
		t.Fatalf("AttackPathScoreChange = %d, want path score increase from downstream risk", report.AttackPathScoreChange)
	}
	if len(report.AffectedFindings) != 1 || report.AffectedFindings[0].Reduction >= 0 {
		t.Fatalf("AffectedFindings = %#v, want one downstream risk increase", report.AffectedFindings)
	}
	if !stringSliceContains(report.Reasons, "modeled_identity_blast_radius") {
		t.Fatalf("Reasons = %#v, want modeled identity blast radius", report.Reasons)
	}
}

func riskDeltaGraphRow(findingID string, resourceURN string, upstreamURN string, upstreamRelation string) ports.CypherRow {
	values := map[string]any{
		"resource_urn":         resourceURN,
		"resource_entity_type": "aws.secret_store",
		"finding_id":           findingID,
		"finding_urn":          "urn:cerebro:writer:finding:" + findingID,
		"finding_entity_type":  "finding",
		"upstream_urn":         upstreamURN,
		"upstream_entity_type": "aws.public_principal",
		"upstream_relation":    upstreamRelation,
	}
	if strings.Contains(upstreamURN, "okta_user") {
		values["upstream_entity_type"] = "okta.user"
	}
	return ports.CypherRow{Values: values}
}
