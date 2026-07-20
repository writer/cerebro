package complianceimpact

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
)

func TestGraphProjectorWritesExactFactAndDependencies(t *testing.T) {
	t.Parallel()
	policy := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", 1)
	plan := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", 3), edge(t, policy, "policy_input"))
	graph := &projectionGraphRecorder{}
	projector, err := NewGraphProjector(graph)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectFact(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(graph.entities) != 2 || len(graph.links) != 1 {
		t.Fatalf("projected entities=%d links=%d", len(graph.entities), len(graph.links))
	}
	if graph.entities[0].Attributes["revision_id"] != plan.Revision().RevisionID() || graph.entities[0].Attributes["content_digest"] != string(plan.Revision().Canonical().ContentDigest) {
		t.Fatalf("root attributes = %#v", graph.entities[0].Attributes)
	}
	link := graph.links[0]
	if link.Relation != impactDependencyRelation || link.Attributes["dependency_relation"] != "policy_input" || link.FromURN == link.ToURN {
		t.Fatalf("projected link = %#v", link)
	}
}

func TestProjectedGraphReadsExactFactAndPagesDependents(t *testing.T) {
	t.Parallel()
	policy := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", 1)
	plan := impactRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan-1", 3)
	policyEntity, err := projectedImpactEntity(policy)
	if err != nil {
		t.Fatal(err)
	}
	planEntity, err := projectedImpactEntity(plan)
	if err != nil {
		t.Fatal(err)
	}
	queryStore := &impactQueryStore{responses: map[string][]ports.CypherRow{
		getImpactFactQuery:           {{Values: map[string]any{"attributes": attributesJSON(t, planEntity.Attributes)}}},
		countImpactDependenciesQuery: {{Values: map[string]any{"dependency_count": int64(1)}}},
		listImpactDependenciesQuery: {{Values: map[string]any{
			"attributes": attributesJSON(t, policyEntity.Attributes), "edge_attributes": `{"dependency_relation":"policy_input"}`,
		}}},
		listImpactDependentsQuery: {
			{Values: map[string]any{"cursor": planEntity.URN, "attributes": attributesJSON(t, planEntity.Attributes)}},
			{Values: map[string]any{"cursor": planEntity.URN + "-next", "attributes": attributesJSON(t, planEntity.Attributes)}},
		},
	}}
	graph, err := NewProjectedGraph(queryStore)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := graph.GetComplianceImpactFact(context.Background(), "tenant-a", portRevision(plan))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fact.Revision, portRevision(plan)) || len(fact.Dependencies) != 1 || fact.Dependencies[0].Relation != "policy_input" || !reflect.DeepEqual(fact.Dependencies[0].Revision, portRevision(policy)) {
		t.Fatalf("fact = %#v", fact)
	}
	page, err := graph.ListComplianceImpactDependents(context.Background(), ports.ComplianceImpactDependentRequest{
		TenantID: "tenant-a", Dependency: portRevision(policy), Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Complete || page.NextCursor != planEntity.URN || len(page.Dependents) != 1 || !reflect.DeepEqual(page.Dependents[0], portRevision(plan)) {
		t.Fatalf("page = %#v", page)
	}
	last := queryStore.requests[len(queryStore.requests)-1]
	if last.RowLimit != 2 || last.Params["row_limit"] != 2 {
		t.Fatalf("dependent query bounds = %#v", last)
	}
}

func TestProjectedGraphRejectsOversizedFactAndTenantMismatch(t *testing.T) {
	t.Parallel()
	revision := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy-1", 1)
	entity, err := projectedImpactEntity(revision)
	if err != nil {
		t.Fatal(err)
	}
	queryStore := &impactQueryStore{responses: map[string][]ports.CypherRow{
		getImpactFactQuery:           {{Values: map[string]any{"attributes": attributesJSON(t, entity.Attributes)}}},
		countImpactDependenciesQuery: {{Values: map[string]any{"dependency_count": int64(maxFactDependencies + 1)}}},
	}}
	graph, err := NewProjectedGraph(queryStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graph.GetComplianceImpactFact(context.Background(), "tenant-a", portRevision(revision)); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("oversized fact error = %v", err)
	}
	if _, err := graph.GetComplianceImpactFact(context.Background(), "tenant-b", portRevision(revision)); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("tenant mismatch error = %v", err)
	}
}

func attributesJSON(t *testing.T, attributes map[string]string) string {
	t.Helper()
	value, err := json.Marshal(attributes)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

type projectionGraphRecorder struct {
	entities []*ports.ProjectedEntity
	links    []*ports.ProjectedLink
}

func (*projectionGraphRecorder) Ping(context.Context) error { return nil }
func (r *projectionGraphRecorder) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	r.entities = append(r.entities, entity)
	return nil
}
func (r *projectionGraphRecorder) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	r.links = append(r.links, link)
	return nil
}
func (r *projectionGraphRecorder) UpsertProjectedEntities(_ context.Context, entities []*ports.ProjectedEntity) error {
	r.entities = append(r.entities, entities...)
	return nil
}
func (r *projectionGraphRecorder) UpsertProjectedLinks(_ context.Context, links []*ports.ProjectedLink) error {
	r.links = append(r.links, links...)
	return nil
}

type impactQueryStore struct {
	responses map[string][]ports.CypherRow
	requests  []ports.CypherQueryRequest
}

func (*impactQueryStore) Ping(context.Context) error { return nil }
func (*impactQueryStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, ports.ErrGraphEntityNotFound
}
func (s *impactQueryStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	return append([]ports.CypherRow(nil), s.responses[request.Query]...), nil
}
