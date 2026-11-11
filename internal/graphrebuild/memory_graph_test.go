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

// TestMemoryGraphStoreReplaceProjectedLinkSetsGuardedSemantics proves
// Contract C9's core guard against the scratch dry-run store: narrowing a
// set retracts only the dropped link, a stale observation can neither
// retract nor restore anything, an authoritative empty set clears the
// whole scope, and another runtime's links on the same owner and relation
// are never touched.
func TestMemoryGraphStoreReplaceProjectedLinkSetsGuardedSemantics(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()

	owner := "urn:cerebro:writer:aws_role:principal"
	consumerA := "urn:cerebro:writer:kubernetes_service_account:ns/a"
	consumerB := "urn:cerebro:writer:kubernetes_service_account:ns/b"
	linkSet := func(runtimeID string, at string, consumers ...string) *ports.ProjectedLinkSet {
		links := make([]*ports.ProjectedLink, 0, len(consumers))
		for _, consumer := range consumers {
			links = append(links, &ports.ProjectedLink{
				TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
				FromURN: owner, ToURN: consumer, Relation: "associated_with",
			})
		}
		return &ports.ProjectedLinkSet{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner, Relation: "associated_with", Outgoing: true,
			Links: links, Observation: map[string]string{"at": at},
		}
	}
	hasLink := func(consumer string) bool {
		_, ok := scratch.links[linkKey(owner, "associated_with", consumer)]
		return ok
	}

	// {A,B} -> {A} retracts only B.
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T10:00:00Z", consumerA, consumerB),
	}); err != nil {
		t.Fatalf("initial link set: %v", err)
	}
	if !hasLink(consumerA) || !hasLink(consumerB) {
		t.Fatalf("initial set did not assert both links: A=%t B=%t", hasLink(consumerA), hasLink(consumerB))
	}
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T10:05:00Z", consumerA),
	}); err != nil {
		t.Fatalf("narrowed link set: %v", err)
	}
	if !hasLink(consumerA) {
		t.Fatal("link A was incorrectly removed by narrowing")
	}
	if hasLink(consumerB) {
		t.Fatal("link B survived narrowing the set to {A}")
	}

	// A stale observation must neither retract nor restore anything.
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T09:00:00Z"),
	}); err != nil {
		t.Fatalf("stale retract attempt: %v", err)
	}
	if !hasLink(consumerA) {
		t.Fatal("a stale observation retracted link A")
	}

	// An authoritative empty set clears the whole scope.
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T11:00:00Z"),
	}); err != nil {
		t.Fatalf("authoritative clear: %v", err)
	}
	if hasLink(consumerA) {
		t.Fatal("authoritative empty set left link A behind")
	}

	// Another runtime's link on the same owner and relation is never touched.
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-2", "2026-11-02T10:00:00Z", consumerB),
	}); err != nil {
		t.Fatalf("other runtime set: %v", err)
	}
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T12:00:00Z"),
	}); err != nil {
		t.Fatalf("our runtime clear: %v", err)
	}
	if !hasLink(consumerB) {
		t.Fatal("runtime-1's clear touched runtime-2's link B")
	}
}

// TestMemoryGraphStorePlainLinkAssertionsSurviveOtherRuntimeRetraction
// reproduces F06 in the scratch store directly: two runtimes assert the
// same logical link via plain UpsertProjectedLink, and narrowing one
// runtime's link set to retract its own assertion must never remove the
// other runtime's independent assertion. Exercises both write orders and
// proves the link disappears only once the last assertion is gone.
func TestMemoryGraphStorePlainLinkAssertionsSurviveOtherRuntimeRetraction(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()
	owner := "urn:cerebro:writer:aws_role:principal"
	consumer := "urn:cerebro:writer:kubernetes_service_account:ns/a"
	hasLink := func() bool {
		_, ok := scratch.links[linkKey(owner, "associated_with", consumer)]
		return ok
	}
	linkFor := func(runtimeID string) *ports.ProjectedLink {
		return &ports.ProjectedLink{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			FromURN: owner, ToURN: consumer, Relation: "associated_with",
		}
	}
	retract := func(runtimeID string) {
		t.Helper()
		if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner, Relation: "associated_with", Outgoing: true,
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}}); err != nil {
			t.Fatalf("retract runtime %s: %v", runtimeID, err)
		}
	}

	// Order 1: A asserts, then B asserts; retracting B leaves A's
	// assertion intact, and only retracting A finally clears the link.
	if err := scratch.UpsertProjectedLink(ctx, linkFor("runtime-a")); err != nil {
		t.Fatalf("upsert link runtime-a: %v", err)
	}
	if err := scratch.UpsertProjectedLink(ctx, linkFor("runtime-b")); err != nil {
		t.Fatalf("upsert link runtime-b: %v", err)
	}
	if !hasLink() {
		t.Fatal("link missing after both runtimes asserted it")
	}
	retract("runtime-b")
	if !hasLink() {
		t.Fatal("retracting runtime-b's assertion incorrectly removed runtime-a's")
	}
	retract("runtime-a")
	if hasLink() {
		t.Fatal("link survived after its last assertion was retracted")
	}

	// Order 2 (reversed): B asserts, then A asserts; retracting A first
	// this time must still leave B's assertion intact.
	if err := scratch.UpsertProjectedLink(ctx, linkFor("runtime-b")); err != nil {
		t.Fatalf("upsert link runtime-b (reorder): %v", err)
	}
	if err := scratch.UpsertProjectedLink(ctx, linkFor("runtime-a")); err != nil {
		t.Fatalf("upsert link runtime-a (reorder): %v", err)
	}
	retract("runtime-a")
	if !hasLink() {
		t.Fatal("retracting runtime-a's assertion incorrectly removed runtime-b's (reordered)")
	}
	retract("runtime-b")
	if hasLink() {
		t.Fatal("link survived after its last assertion was retracted (reordered)")
	}
}

// TestMemoryGraphStoreReplaceProjectedLinkSetsIncompleteKeepsPriorLinks
// reproduces the F04/G1 ordering scenario in the scratch store: v1 asserts
// a complete {A} set, v3 is accepted but Incomplete (advancing the guard
// without touching links), and a reordered replay of the older v2 with a
// complete {B} set must be rejected as stale, leaving {A} untouched.
func TestMemoryGraphStoreReplaceProjectedLinkSetsIncompleteKeepsPriorLinks(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()
	owner := "urn:cerebro:writer:aws_role:principal"
	consumerA := "urn:cerebro:writer:kubernetes_service_account:ns/a"
	consumerB := "urn:cerebro:writer:kubernetes_service_account:ns/b"
	hasLink := func(consumer string) bool {
		_, ok := scratch.links[linkKey(owner, "associated_with", consumer)]
		return ok
	}

	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: consumerA, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}}); err != nil {
		t.Fatalf("apply v1 {A}: %v", err)
	}
	if !hasLink(consumerA) {
		t.Fatal("v1 {A} was not asserted")
	}

	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Incomplete:  true,
		Observation: map[string]string{"at": "2026-11-02T12:00:00Z"},
	}}); err != nil {
		t.Fatalf("apply v3 incomplete: %v", err)
	}
	if !hasLink(consumerA) {
		t.Fatal("accepted incomplete observation retracted link A")
	}

	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: consumerB, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T11:00:00Z"},
	}}); err != nil {
		t.Fatalf("apply stale v2 {B}: %v", err)
	}
	if !hasLink(consumerA) {
		t.Fatal("reordered stale v2 {B} replaced link A")
	}
	if hasLink(consumerB) {
		t.Fatal("reordered stale v2 {B} was incorrectly applied")
	}
}

// TestMemoryGraphStoreReplaceProjectedLinkSetsIncompleteRejectsLinks proves
// an Incomplete set carrying links is rejected (G1): Links MUST be empty
// when Incomplete is set.
func TestMemoryGraphStoreReplaceProjectedLinkSetsIncompleteRejectsLinks(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	err = scratch.ReplaceProjectedLinkSets(context.Background(), []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: "urn:cerebro:writer:aws_role:principal", Relation: "associated_with", Outgoing: true,
		Incomplete: true,
		Links: []*ports.ProjectedLink{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: "urn:cerebro:writer:aws_role:principal", ToURN: "urn:cerebro:writer:kubernetes_service_account:ns/a", Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}})
	if err == nil {
		t.Fatal("ReplaceProjectedLinkSets() error = nil, want rejection of Incomplete set carrying links")
	}
}

// TestMemoryGraphStoreReplaceProjectedLinkSetsEndpointsGuardedMaterialization
// pins R06 against the scratch store: a stale or losing link-set
// observation must never materialize its Endpoints (neither a complete
// stale replay nor a reordered stale set after an accepted Incomplete
// observation), an accepted set still creates a genuinely missing
// endpoint, a provider-first entity sharing an endpoint's URN is left
// untouched, and later ordinary provider enrichment for that URN still
// applies normally.
func TestMemoryGraphStoreReplaceProjectedLinkSetsEndpointsGuardedMaterialization(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()
	owner := "urn:cerebro:writer:aws_role:principal"
	consumerB := "urn:cerebro:writer:kubernetes_service_account:ns/b"

	// v3-empty accepted, then stale v2{B} must create neither B's entity
	// nor its link.
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "3"},
	}}); err != nil {
		t.Fatalf("v3 empty: %v", err)
	}
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: consumerB, Relation: "associated_with",
		}},
		Endpoints:   []*ports.ProjectedEntity{{URN: consumerB, TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-1", EntityType: "kubernetes.service_account", Label: "b", CreateOnly: true}},
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "2"},
	}}); err != nil {
		t.Fatalf("stale v2 with B: %v", err)
	}
	if _, exists := scratch.entities[consumerB]; exists {
		t.Fatal("a stale link-set replay materialized consumer B's entity")
	}

	// An accepted set still creates a genuinely missing endpoint; a
	// provider-first entity sharing an endpoint's URN is untouched; later
	// provider enrichment still applies.
	providerOwned := "urn:cerebro:writer:kubernetes_service_account:ns/provider-owned"
	missingEndpoint := "urn:cerebro:writer:kubernetes_service_account:ns/missing"
	if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: providerOwned, TenantID: "writer", SourceID: "kubernetes", EntityType: "kubernetes.service_account",
		Label: "provider-label", Attributes: map[string]string{"owner": "platform-team"},
	}); err != nil {
		t.Fatalf("seed provider entity: %v", err)
	}
	if err := scratch.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-2",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{
			{TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-2", FromURN: owner, ToURN: providerOwned, Relation: "associated_with"},
			{TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-2", FromURN: owner, ToURN: missingEndpoint, Relation: "associated_with"},
		},
		Endpoints: []*ports.ProjectedEntity{
			{URN: providerOwned, TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-2", EntityType: "kubernetes.service_account", Label: "stub-label", CreateOnly: true},
			{URN: missingEndpoint, TenantID: "writer", SourceID: "vulnview", RuntimeID: "runtime-2", EntityType: "kubernetes.service_account", Label: "missing-stub", CreateOnly: true},
		},
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "1"},
	}}); err != nil {
		t.Fatalf("accepted set: %v", err)
	}
	if _, exists := scratch.entities[missingEndpoint]; !exists {
		t.Fatal("an accepted observation did not create its genuinely missing endpoint")
	}
	if got := scratch.entities[providerOwned]; got.SourceID != "kubernetes" || got.Label != "provider-label" {
		t.Fatalf("provider-owned entity was touched by the CreateOnly stub: %#v", got)
	}
	if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: missingEndpoint, TenantID: "writer", SourceID: "kubernetes", EntityType: "kubernetes.service_account",
		Label: "enriched-label", Attributes: map[string]string{"owner": "platform-team"},
	}); err != nil {
		t.Fatalf("enrich stub entity: %v", err)
	}
	if got := scratch.entities[missingEndpoint]; got.SourceID != "kubernetes" || got.Label != "enriched-label" {
		t.Fatalf("later provider enrichment did not apply: %#v", got)
	}
}

// TestMemoryGraphStoreUpsertProjectedEntityCreateOnly exercises both
// CreateOnly orderings (G1): a provider-owned entity's richer facts are
// never overwritten by a later stub, and a stub entity is fully replaced
// by a subsequent ordinary (provider) observation.
func TestMemoryGraphStoreUpsertProjectedEntityCreateOnly(t *testing.T) {
	ctx := context.Background()

	t.Run("provider-first-then-stub", func(t *testing.T) {
		store, err := newMemoryGraphStore()
		if err != nil {
			t.Fatalf("newMemoryGraphStore() error = %v", err)
		}
		scratch := store.(*memoryGraphStore)
		urn := "urn:cerebro:writer:gcp_service_account:provider-first"
		if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: "writer", SourceID: "gcp", RuntimeID: "gcp-runtime", EntityType: "gcp.service_account", Label: "real-account",
			Attributes: map[string]string{"domain": "example.com"},
		}); err != nil {
			t.Fatalf("upsert provider entity: %v", err)
		}
		if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: "writer", SourceID: "vulnview", RuntimeID: "vulnview-runtime", EntityType: "gcp.service_account", Label: "stub",
			Attributes: map[string]string{"stub": "true"},
			CreateOnly: true,
		}); err != nil {
			t.Fatalf("upsert create-only stub over provider entity: %v", err)
		}
		stored := scratch.entities[urn]
		if stored.SourceID != "gcp" || stored.RuntimeID != "gcp-runtime" || stored.Label != "real-account" {
			t.Fatalf("create-only stub overwrote provider ownership/label: %#v", stored)
		}
		if _, present := stored.Attributes["stub"]; present {
			t.Fatalf("create-only stub contributed attributes to an existing entity: %#v", stored.Attributes)
		}
		if stored.Attributes["domain"] != "example.com" {
			t.Fatalf("provider attributes lost: %#v", stored.Attributes)
		}
	})

	t.Run("stub-first-then-provider", func(t *testing.T) {
		store, err := newMemoryGraphStore()
		if err != nil {
			t.Fatalf("newMemoryGraphStore() error = %v", err)
		}
		scratch := store.(*memoryGraphStore)
		urn := "urn:cerebro:writer:gcp_service_account:stub-first"
		if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: "writer", SourceID: "vulnview", RuntimeID: "vulnview-runtime", EntityType: "gcp.service_account", Label: "stub",
			CreateOnly: true,
		}); err != nil {
			t.Fatalf("upsert create-only stub: %v", err)
		}
		if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: "writer", SourceID: "gcp", RuntimeID: "gcp-runtime", EntityType: "gcp.service_account", Label: "real-account",
			Attributes: map[string]string{"domain": "example.com"},
		}); err != nil {
			t.Fatalf("upsert provider entity over stub: %v", err)
		}
		stored := scratch.entities[urn]
		if stored.SourceID != "gcp" || stored.RuntimeID != "gcp-runtime" || stored.Label != "real-account" {
			t.Fatalf("ordinary observation did not replace stub ownership/label: %#v", stored)
		}
		if stored.Attributes["domain"] != "example.com" {
			t.Fatalf("provider attributes missing after replacing stub: %#v", stored.Attributes)
		}
	})
}

// TestMemoryGraphStoreUpsertProjectedEntityObservationPrecedence exercises
// G1's strict observation precedence: a stale replay changes nothing at
// all, and an accepted newer observation applies RetractedAttributes while
// never removing a key the observation still carries.
func TestMemoryGraphStoreUpsertProjectedEntityObservationPrecedence(t *testing.T) {
	store, err := newMemoryGraphStore()
	if err != nil {
		t.Fatalf("newMemoryGraphStore() error = %v", err)
	}
	scratch := store.(*memoryGraphStore)
	ctx := context.Background()
	urn := "urn:cerebro:writer:vulnview_finding:finding-1"
	if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v2",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "2",
			"triage_state":           "accepted",
			"triage_reason":          "known-risk",
		},
	}); err != nil {
		t.Fatalf("upsert v2: %v", err)
	}
	if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v1-replay",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "1",
			"triage_state":           "none",
		},
		RetractedAttributes: []string{"triage_reason"},
	}); err != nil {
		t.Fatalf("upsert stale v1 replay: %v", err)
	}
	stale := scratch.entities[urn]
	if stale.Label != "v2" || stale.Attributes["triage_state"] != "accepted" || stale.Attributes["triage_reason"] != "known-risk" {
		t.Fatalf("stale strict replay changed the entity: %#v", stale)
	}

	if err := scratch.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v3",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "3",
			"triage_state":           "none",
		},
		RetractedAttributes: []string{"triage_reason"},
	}); err != nil {
		t.Fatalf("upsert accepted v3: %v", err)
	}
	accepted := scratch.entities[urn]
	if _, present := accepted.Attributes["triage_reason"]; present {
		t.Fatalf("accepted observation left retracted key: %#v", accepted.Attributes)
	}
	if accepted.Attributes["triage_state"] != "none" || accepted.Label != "v3" {
		t.Fatalf("accepted observation did not apply: %#v", accepted)
	}
}
