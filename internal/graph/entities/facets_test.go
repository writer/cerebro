package entities

import (
	"testing"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestGetEntityFacetDefinitionReturnsDeepCopy(t *testing.T) {
	def, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition")
	}
	if len(def.ClaimPredicates) == 0 {
		t.Fatalf("expected cloned definition to retain claim predicates, got %#v", def)
	}
	original := def.ClaimPredicates[0]
	def.ClaimPredicates[0] = "mutated"

	again, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition on second lookup")
	}
	if again.ClaimPredicates[0] != original {
		t.Fatalf("expected registry definition to be isolated from caller mutation, got %#v", again)
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
