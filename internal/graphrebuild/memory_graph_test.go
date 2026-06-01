package graphrebuild

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

func TestMemoryGraphStorePreservesExistingLabelsForFallbackLabels(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	urn := "urn:cerebro:writer:source:vanta:integration:integration-1"

	if err := scratch.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   "writer",
		SourceID:   "grc",
		EntityType: "source",
		Label:      "GitHub Dependabot",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(named) error = %v", err)
	}
	if err := scratch.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   "writer",
		SourceID:   "grc",
		EntityType: "source",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(fallback) error = %v", err)
	}

	if got := scratch.entities[urn].Label; got != "GitHub Dependabot" {
		t.Fatalf("memory graph label = %q, want GitHub Dependabot", got)
	}
}

func TestMemoryGraphStoreIntegrityChecksLinkageGuardrails(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()

	for _, entity := range []*ports.ProjectedEntity{
		{
			URN:        "urn:cerebro:writer:github_code_repository:repo-1",
			TenantID:   "writer",
			SourceID:   "github",
			EntityType: "github.code.repository",
			Label:      "repo-1",
			Attributes: map[string]string{"owner_login": "org-1"},
		},
		{
			URN:        "urn:cerebro:writer:aws_network_interface:eni-1",
			TenantID:   "writer",
			SourceID:   "aws",
			EntityType: "aws.network.interface",
			Label:      "eni-1",
			Attributes: map[string]string{"attached_instance_id": "i-1"},
		},
		{
			URN:        "urn:cerebro:writer:github_code_repository:grc-repo-1",
			TenantID:   "writer",
			SourceID:   "grc",
			EntityType: "github.code.repository",
			Label:      "grc-repo-1",
			Attributes: map[string]string{"owner_login": "org-1"},
		},
	} {
		if err := scratch.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}

	checks, err := scratch.IntegrityChecks(ctx)
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	if got := memoryIntegrityActual(checks, "github_code_repositories_without_owner_link"); got != 1 {
		t.Fatalf("github_code_repositories_without_owner_link = %d, want 1", got)
	}
	if got := memoryIntegrityActual(checks, "aws_public_endpoints_without_instance_link"); got != 1 {
		t.Fatalf("aws_public_endpoints_without_instance_link = %d, want 1", got)
	}
}

func memoryIntegrityActual(checks []graphstore.IntegrityCheck, name string) int64 {
	for _, check := range checks {
		if check.Name == name {
			return check.Actual
		}
	}
	return -1
}
