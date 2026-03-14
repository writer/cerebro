package entities

import (
	"testing"
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestGetEntityRecordDelegatesToGraphEntityReadModel(t *testing.T) {
	g := graph.New()
	now := time.Now().UTC()
	g.AddNode(&graph.Node{
		ID:        "service:payments",
		Kind:      graph.NodeKindService,
		Name:      "payments",
		CreatedAt: now,
	})

	record, ok := GetEntityRecord(g, "service:payments", now, now)
	if !ok {
		t.Fatal("expected entity record")
	}
	if record.ID != "service:payments" {
		t.Fatalf("unexpected record id %q", record.ID)
	}
	if record.Kind != graph.NodeKindService {
		t.Fatalf("unexpected record kind %q", record.Kind)
	}
}

func TestDefaultEntityFacetDefinitionsReturnsDefensiveCopy(t *testing.T) {
	defs := DefaultEntityFacetDefinitions()
	if len(defs) == 0 {
		t.Fatal("expected facet definitions")
	}
	originalID := defs[0].ID
	defs[0].ID = "mutated"
	if len(defs[0].ApplicableKinds) > 0 {
		defs[0].ApplicableKinds[0] = graph.NodeKindUser
	}

	again := DefaultEntityFacetDefinitions()
	if again[0].ID != originalID {
		t.Fatalf("expected defensive copy, got %q", again[0].ID)
	}
	if len(again[0].ApplicableKinds) > 0 && again[0].ApplicableKinds[0] == graph.NodeKindUser {
		t.Fatal("expected nested facet metadata to be copied defensively")
	}
}

func TestEntityFacetAppliesToNodeHonorsApplicableKinds(t *testing.T) {
	if !EntityFacetAppliesToNode(EntityFacetDefinition{}, graph.NodeKindService) {
		t.Fatal("expected empty applicable kinds to apply broadly")
	}
	def := EntityFacetDefinition{
		ID:              "bucket_only",
		ApplicableKinds: []graph.NodeKind{graph.NodeKindBucket},
	}
	if !EntityFacetAppliesToNode(def, graph.NodeKindBucket) {
		t.Fatal("expected facet to apply to listed kind")
	}
	if EntityFacetAppliesToNode(def, graph.NodeKindService) {
		t.Fatal("expected facet not to apply to unlisted kind")
	}
}
