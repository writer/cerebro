package findingdsl

import (
	"context"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type recordingPolicyGraphStore struct {
	entities []*ports.ProjectedEntity
	links    []*ports.ProjectedLink
	deleted  []string
	request  ports.CypherQueryRequest
	rows     []ports.CypherRow
}

func (s *recordingPolicyGraphStore) Ping(context.Context) error { return nil }
func (s *recordingPolicyGraphStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}
func (s *recordingPolicyGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	s.entities = append(s.entities, entity)
	return nil
}
func (s *recordingPolicyGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	s.links = append(s.links, link)
	return nil
}
func (s *recordingPolicyGraphStore) DeleteProjectedEntity(_ context.Context, urn string) error {
	s.deleted = append(s.deleted, urn)
	return nil
}
func (s *recordingPolicyGraphStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.request = request
	return s.rows, nil
}

func TestValidatePolicyGraphFixtureRequiresConnectedTwoEdgePath(t *testing.T) {
	suite := PolicyRuleTestSuite{APIVersion: APIVersion, Kind: KindPolicyFindingRuleTest, Cases: []PolicyRuleTestCase{{
		Name: "disconnected edges do not prove a multi-hop path", GraphFixture: &PolicyGraphFixture{
			TenantID: "fixture", Nodes: []PolicyGraphFixtureNode{
				{URN: "a", SourceID: "okta", EntityType: "okta.user"},
				{URN: "b", SourceID: "okta", EntityType: "okta.group"},
				{URN: "c", SourceID: "okta", EntityType: "okta.application"},
				{URN: "d", SourceID: "okta", EntityType: "okta.entitlement"},
			}, Edges: []PolicyGraphFixtureEdge{
				{FromURN: "a", ToURN: "b", SourceID: "okta", Relation: "member_of"},
				{FromURN: "c", ToURN: "d", SourceID: "okta", Relation: "grants_entitlement"},
			},
		}, WantFinding: false,
	}}}
	issues := ValidatePolicyRuleTestSuite(suite)
	if !issuesContain(issues, "must contain a connected path spanning two edges") {
		t.Fatalf("ValidatePolicyRuleTestSuite() issues = %#v, want connected-path issue", issues)
	}
}

func TestValidatePolicyGraphFixtureRequiresSingleEdgeMutationPair(t *testing.T) {
	nodes := []PolicyGraphFixtureNode{
		{URN: "a", SourceID: "okta", EntityType: "okta.user"},
		{URN: "b", SourceID: "okta", EntityType: "okta.group"},
		{URN: "c", SourceID: "okta", EntityType: "okta.application"},
	}
	edges := []PolicyGraphFixtureEdge{
		{FromURN: "a", ToURN: "b", SourceID: "okta", Relation: "member_of"},
		{FromURN: "b", ToURN: "c", SourceID: "okta", Relation: "assigned_to"},
	}
	suite := PolicyRuleTestSuite{APIVersion: APIVersion, Kind: KindPolicyFindingRuleTest, Cases: []PolicyRuleTestCase{
		{Name: "finding only", GraphFixture: &PolicyGraphFixture{TenantID: "fixture", Nodes: nodes, Edges: edges}, WantFinding: true},
	}}
	issues := ValidatePolicyRuleTestSuite(suite)
	if !issuesContain(issues, "exactly one policy-critical edge removed") {
		t.Fatalf("ValidatePolicyRuleTestSuite() issues = %#v, want mutation-pair issue", issues)
	}
}

func TestRunPolicyGraphFixtureProjectsTopologyAndExecutesPolicyCypher(t *testing.T) {
	rule := PolicyFindingRule{Spec: PolicyFindingRuleSpec{Graph: PolicyRuleGraphFinding{
		Query: "MATCH (a)-[:RELATION]->(b)-[:RELATION]->(c) RETURN a.urn AS primary_urn", RowLimit: 25,
		RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"},
	}}}
	fixture := &PolicyGraphFixture{TenantID: "fixture", Nodes: []PolicyGraphFixtureNode{
		{URN: "a", SourceID: "okta", EntityType: "okta.user"},
		{URN: "b", SourceID: "okta", EntityType: "okta.group"},
		{URN: "c", SourceID: "okta", EntityType: "okta.application"},
	}, Edges: []PolicyGraphFixtureEdge{
		{FromURN: "a", ToURN: "b", SourceID: "okta", Relation: "member_of"},
		{FromURN: "b", ToURN: "c", SourceID: "okta", Relation: "assigned_to"},
	}}
	store := &recordingPolicyGraphStore{rows: []ports.CypherRow{{Values: map[string]any{
		"primary_urn": "a", "fingerprint_key": "a|c", "summary": "multi-hop access", "resource_urns": []string{"a", "b", "c"},
	}}}}
	if err := runPolicyGraphFixture(context.Background(), store, rule, PolicyRuleTestCase{Name: "complete path", GraphFixture: fixture, WantFinding: true}); err != nil {
		t.Fatalf("runPolicyGraphFixture() error = %v", err)
	}
	if len(store.entities) != 3 || len(store.links) != 2 || len(store.deleted) != 3 {
		t.Fatalf("projection counts = nodes %d links %d deleted %d", len(store.entities), len(store.links), len(store.deleted))
	}
	if !strings.Contains(store.request.Query, "(a)-[:RELATION]->(b)-[:RELATION]->(c)") {
		t.Fatalf("executed query = %q, want policy Cypher", store.request.Query)
	}
	if store.request.Params["tenant_id"] != "fixture" || store.request.Params["row_limit"] != int64(25) {
		t.Fatalf("executed params = %#v", store.request.Params)
	}
}
