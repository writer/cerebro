package graphrebuild

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestMemoryGraphStorePreservesExistingLabelsForFallbackLabels(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	urn := "urn:cerebro:example:source:vanta:integration:integration-1"

	if err := scratch.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   "example",
		SourceID:   "grc",
		EntityType: "source",
		Label:      "GitHub Dependabot",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(named) error = %v", err)
	}
	if err := scratch.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   "example",
		SourceID:   "grc",
		EntityType: "source",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(fallback) error = %v", err)
	}

	if got := scratch.entities[urn].Label; got != "GitHub Dependabot" {
		t.Fatalf("memory graph label = %q, want GitHub Dependabot", got)
	}
}
