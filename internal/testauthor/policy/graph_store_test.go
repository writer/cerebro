package policy

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
)

type graphFixtureProjectionStub struct {
	entities []*ports.ProjectedEntity
	links    []*ports.ProjectedLink
	deleted  []string
}

func (s *graphFixtureProjectionStub) Ping(context.Context) error { return nil }
func (s *graphFixtureProjectionStub) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	s.entities = append(s.entities, entity)
	return nil
}
func (s *graphFixtureProjectionStub) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	s.links = append(s.links, link)
	return nil
}
func (s *graphFixtureProjectionStub) DeleteProjectedLink(context.Context, *ports.ProjectedLink) error {
	return nil
}
func (s *graphFixtureProjectionStub) DeleteProjectedEntity(_ context.Context, urn string) error {
	s.deleted = append(s.deleted, urn)
	return nil
}

type graphFixtureQueryStub struct {
	request ports.CypherQueryRequest
	rows    []ports.CypherRow
	err     error
}

func (s *graphFixtureQueryStub) Ping(context.Context) error { return s.err }
func (s *graphFixtureQueryStub) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.request = request
	return s.rows, s.err
}

func TestCompatibilityGraphTestStoreAdaptsTypedPolicyEvaluation(t *testing.T) {
	projection := &graphFixtureProjectionStub{}
	queries := &graphFixtureQueryStub{rows: []ports.CypherRow{{Values: map[string]any{"primary_urn": "urn:cerebro:fixture:resource:one"}}}}
	store := NewCompatibilityGraphTestStore(projection, queries)
	rule := findingdsl.PolicyFindingRule{Spec: findingdsl.PolicyFindingRuleSpec{Graph: findingdsl.PolicyRuleGraphFinding{
		Query:  "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS primary_urn LIMIT $row_limit",
		Params: map[string]any{"tenant_id": "untrusted", "row_limit": int64(999), "kind": "resource"}, RowLimit: 25,
	}}}
	rows, err := store.EvaluatePolicyGraph(context.Background(), findingdsl.PolicyGraphEvaluationRequest{Rule: rule, TenantID: " fixture "})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows, []map[string]any{{"primary_urn": "urn:cerebro:fixture:resource:one"}}) {
		t.Fatalf("rows = %#v", rows)
	}
	if queries.request.Query != rule.Spec.Graph.Query || queries.request.RowLimit != 25 {
		t.Fatalf("compatibility request = %#v", queries.request)
	}
	if queries.request.Params["tenant_id"] != "fixture" || queries.request.Params["row_limit"] != int64(25) || queries.request.Params["kind"] != "resource" {
		t.Fatalf("compatibility params = %#v", queries.request.Params)
	}
	entity := &ports.ProjectedEntity{URN: "urn:cerebro:fixture:resource:one"}
	if err := store.UpsertProjectedEntity(context.Background(), entity); err != nil {
		t.Fatal(err)
	}
	if len(projection.entities) != 1 || projection.entities[0] != entity {
		t.Fatalf("projected entities = %#v", projection.entities)
	}
}

func TestCompatibilityGraphTestStoreFailsClosedWithoutQueryAuthority(t *testing.T) {
	store := NewCompatibilityGraphTestStore(&graphFixtureProjectionStub{}, nil)
	_, err := store.EvaluatePolicyGraph(context.Background(), findingdsl.PolicyGraphEvaluationRequest{})
	if err == nil {
		t.Fatal("EvaluatePolicyGraph() error = nil")
	}
	queries := &graphFixtureQueryStub{err: errors.New("query unavailable")}
	store = NewCompatibilityGraphTestStore(&graphFixtureProjectionStub{}, queries)
	_, err = store.EvaluatePolicyGraph(context.Background(), findingdsl.PolicyGraphEvaluationRequest{TenantID: "fixture", Rule: findingdsl.PolicyFindingRule{Spec: findingdsl.PolicyFindingRuleSpec{Graph: findingdsl.PolicyRuleGraphFinding{Query: "RETURN 1", RowLimit: 1}}}})
	if !errors.Is(err, queries.err) {
		t.Fatalf("EvaluatePolicyGraph() error = %v, want query failure", err)
	}
}
