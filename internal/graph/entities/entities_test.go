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

	again := DefaultEntityFacetDefinitions()
	if again[0].ID != originalID {
		t.Fatalf("expected defensive copy, got %q", again[0].ID)
	}
}
