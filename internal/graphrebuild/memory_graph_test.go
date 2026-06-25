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

func TestMemoryGraphStoreFlagsCrossKindIdentityFragmentation(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()

	for _, entity := range []*ports.ProjectedEntity{
		{
			URN:        "urn:cerebro:writer:doppler_project:proj-1",
			TenantID:   "writer",
			SourceID:   "doppler",
			EntityType: "doppler.project",
			Label:      "Platform",
		},
		{
			URN:        "urn:cerebro:writer:runtime_project:proj-1",
			TenantID:   "writer",
			SourceID:   "doppler",
			EntityType: "runtime.project",
			Label:      "proj-1",
		},
		{
			URN:        "urn:cerebro:writer:identifier:email:user@example.test",
			TenantID:   "writer",
			SourceID:   "vault",
			EntityType: "identifier.email",
			Label:      "user@example.test",
		},
		{
			URN:        "urn:cerebro:writer:identity:email:user@example.test",
			TenantID:   "writer",
			SourceID:   "vault",
			EntityType: "identity.email",
			Label:      "user@example.test",
		},
	} {
		if err := scratch.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}
	if err := scratch.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "vault",
		FromURN:  "urn:cerebro:writer:identifier:email:user@example.test",
		Relation: "represents_identity",
		ToURN:    "urn:cerebro:writer:identity:email:user@example.test",
	}); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}

	checks, err := scratch.IntegrityChecks(ctx)
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	if got := memoryIntegrityActual(checks, "cross_kind_identity_fragmentation"); got != 1 {
		t.Fatalf("cross_kind_identity_fragmentation = %d, want 1 (only the unlinked doppler/runtime pair, linked identifier/identity twins excluded)", got)
	}
}

func TestMemoryGraphStoreSuppressesBroadTwoHopPathSummaries(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()

	for _, entity := range []*ports.ProjectedEntity{
		{URN: "urn:target", TenantID: "writer", SourceID: "grc", EntityType: "grc.target", Label: "target"},
		{URN: "urn:source", TenantID: "writer", SourceID: "grc", EntityType: "source", Label: "source"},
		{URN: "urn:finding", TenantID: "writer", SourceID: "grc", EntityType: "finding", Label: "finding"},
		{URN: "urn:vulnerability", TenantID: "writer", SourceID: "grc", EntityType: "vulnerability", Label: "vulnerability"},
		{URN: "urn:actor", TenantID: "writer", SourceID: "github", EntityType: "github.user", Label: "actor"},
	} {
		if err := scratch.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}
	for _, link := range []*ports.ProjectedLink{
		{TenantID: "writer", SourceID: "grc", FromURN: "urn:target", Relation: "belongs_to", ToURN: "urn:source"},
		{TenantID: "writer", SourceID: "grc", FromURN: "urn:source", Relation: "has_finding", ToURN: "urn:finding"},
		{TenantID: "writer", SourceID: "grc", FromURN: "urn:target", Relation: "affected_by", ToURN: "urn:vulnerability"},
		{TenantID: "writer", SourceID: "grc", FromURN: "urn:vulnerability", Relation: "has_finding", ToURN: "urn:finding"},
		{TenantID: "writer", SourceID: "github", FromURN: "urn:actor", Relation: "acted_on", ToURN: "urn:source"},
	} {
		if err := scratch.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("UpsertProjectedLink(%s -> %s) error = %v", link.FromURN, link.ToURN, err)
		}
	}

	patterns, err := scratch.PathPatterns(ctx, 10)
	if err != nil {
		t.Fatalf("PathPatterns() error = %v", err)
	}
	if len(patterns) != 1 || patterns[0].FirstRelation != "affected_by" || patterns[0].SecondRelation != "has_finding" {
		t.Fatalf("PathPatterns() = %#v, want only direct vulnerability finding pattern", patterns)
	}

	traversals, err := scratch.SampleTraversals(ctx, 10)
	if err != nil {
		t.Fatalf("SampleTraversals() error = %v", err)
	}
	if len(traversals) != 1 || traversals[0].FirstRelation != "affected_by" || traversals[0].SecondRelation != "has_finding" {
		t.Fatalf("SampleTraversals() = %#v, want only direct vulnerability finding traversal", traversals)
	}
}

func TestMemoryGraphStoreSampleTraversalsKeepsLowestKeysWithinLimit(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()

	for _, entity := range []*ports.ProjectedEntity{
		{URN: "urn:a", TenantID: "writer", SourceID: "fixture", EntityType: "fixture.node", Label: "a"},
		{URN: "urn:b", TenantID: "writer", SourceID: "fixture", EntityType: "fixture.node", Label: "b"},
		{URN: "urn:c", TenantID: "writer", SourceID: "fixture", EntityType: "fixture.node", Label: "c"},
		{URN: "urn:via", TenantID: "writer", SourceID: "fixture", EntityType: "fixture.via", Label: "via"},
		{URN: "urn:z", TenantID: "writer", SourceID: "fixture", EntityType: "fixture.node", Label: "z"},
	} {
		if err := scratch.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}
	for _, link := range []*ports.ProjectedLink{
		{TenantID: "writer", SourceID: "fixture", FromURN: "urn:c", Relation: "connected_to", ToURN: "urn:via"},
		{TenantID: "writer", SourceID: "fixture", FromURN: "urn:b", Relation: "connected_to", ToURN: "urn:via"},
		{TenantID: "writer", SourceID: "fixture", FromURN: "urn:a", Relation: "connected_to", ToURN: "urn:via"},
		{TenantID: "writer", SourceID: "fixture", FromURN: "urn:via", Relation: "observes", ToURN: "urn:z"},
	} {
		if err := scratch.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("UpsertProjectedLink(%s -> %s) error = %v", link.FromURN, link.ToURN, err)
		}
	}

	traversals, err := scratch.SampleTraversals(ctx, 2)
	if err != nil {
		t.Fatalf("SampleTraversals() error = %v", err)
	}
	if len(traversals) != 2 {
		t.Fatalf("len(traversals) = %d, want 2", len(traversals))
	}
	if traversals[0].FromURN != "urn:a" || traversals[1].FromURN != "urn:b" {
		t.Fatalf("SampleTraversals() = %#v, want lowest traversal keys urn:a and urn:b", traversals)
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
