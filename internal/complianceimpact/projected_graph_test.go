package complianceimpact

import (
	"context"
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
