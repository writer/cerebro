package postgres

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestUpsertProjectedEntityRejectsNilEntity(t *testing.T) {
	store := &Store{}
	if err := store.UpsertProjectedEntity(context.Background(), nil); err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want non-nil")
	}
}

func TestUpsertProjectedEntityRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
	})
	if err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want non-nil")
	}
}

func TestUpsertProjectedEntityRejectsCrossTenantCerebroURNBeforeDatabase(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        "urn:cerebro:victim:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
	})
	if err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want cross-tenant Cerebro URN error")
	}
	if got := err.Error(); !strings.Contains(got, "urn:cerebro:victim:github_user:alice") || !strings.Contains(got, "not projection tenant") {
		t.Fatalf("UpsertProjectedEntity() error = %q", got)
	}
}

func TestUpsertProjectedLinkRejectsMissingRelation(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedLink(context.Background(), &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		FromURN:  "urn:cerebro:writer:github_user:alice",
		ToURN:    "urn:cerebro:writer:github_code_repository:writer/cerebro",
	})
	if err == nil {
		t.Fatal("UpsertProjectedLink() error = nil, want non-nil")
	}
}

func TestUpsertProjectedLinkRejectsCrossTenantCerebroURNBeforeDatabase(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedLink(context.Background(), &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		FromURN:  "urn:cerebro:writer:github_user:alice",
		ToURN:    "urn:cerebro:victim:github_code_repository:writer/cerebro",
		Relation: "owns",
	})
	if err == nil {
		t.Fatal("UpsertProjectedLink() error = nil, want cross-tenant Cerebro URN error")
	}
	if got := err.Error(); !strings.Contains(got, "urn:cerebro:victim:github_code_repository:writer/cerebro") || !strings.Contains(got, "not projection tenant") {
		t.Fatalf("UpsertProjectedLink() error = %q", got)
	}
}

func TestProjectionEnsureStatementsIndexReverseLinkLookups(t *testing.T) {
	for _, statement := range ensureProjectionStatements {
		if strings.Contains(statement, "entity_links_to_urn_idx") && strings.Contains(statement, "ON entity_links (to_urn)") {
			return
		}
	}
	t.Fatalf("ensureProjectionStatements missing entity_links to_urn index: %#v", ensureProjectionStatements)
}

func TestProjectionEnsureStatementsIndexRuntimeEvidenceSourceEvents(t *testing.T) {
	for _, statement := range ensureProjectionStatements {
		if strings.Contains(statement, "entities_runtime_evidence_source_event_idx") &&
			strings.Contains(statement, "tenant_id, runtime_id") &&
			strings.Contains(statement, "source_event_id") &&
			strings.Contains(statement, "runtime.evidence") {
			return
		}
	}
	t.Fatalf("ensureProjectionStatements missing runtime evidence source event index: %#v", ensureProjectionStatements)
}

// TestProjectionEnsureStatementsAddAssertionModel proves the F06 schema
// migration is additive only: a new entity_link_assertions table plus two
// new entity_links columns, every statement guarded so it is safe to
// re-run against a database that already has the pre-F06 tables.
func TestProjectionEnsureStatementsAddAssertionModel(t *testing.T) {
	joined := strings.Join(ensureProjectionStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS entity_link_assertions",
		"PRIMARY KEY (from_urn, relation, to_urn, tenant_id, source_id, runtime_id)",
		"ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS assertion_managed BOOLEAN NOT NULL DEFAULT false",
		"ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS assertion_quarantined BOOLEAN NOT NULL DEFAULT false",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("ensureProjectionStatements missing %q: %#v", want, ensureProjectionStatements)
		}
	}
}

func TestProjectedRuntimeEvidenceBySourceEventSQLUsesStableSourceTuple(t *testing.T) {
	query := projectedRuntimeEvidenceBySourceEventSQL()
	for _, want := range []string{
		"tenant_id = $1",
		"entity_type = 'runtime.evidence'",
		"runtime_id = $2",
		"attributes_json ->> 'source_runtime_id' = $2",
		"attributes_json ->> 'source_event_id' = $3",
		"LIMIT 1",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("runtime evidence source event SQL missing %q:\n%s", want, query)
		}
	}
}

func TestProjectedEntityCleanupSQLRequiresScope(t *testing.T) {
	if _, _, err := projectedEntityCleanupCandidatesSQL(ports.ProjectionCleanupRequest{OnlyIsolated: true}); err == nil {
		t.Fatal("projectedEntityCleanupCandidatesSQL() error = nil, want non-nil")
	}
}

// TestProjectedEntityCleanupCandidatesSQLIncludesScopedFilters proves the
// candidate-selection SQL (deletion itself is orchestrated in Go by
// CleanupProjectedEntities, see the integration test below) scopes by every
// requested filter and, for OnlyIsolated, requires both no materialized
// link and no surviving assertion (F06) before an entity is even a
// candidate for removal.
func TestProjectedEntityCleanupCandidatesSQLIncludesScopedFilters(t *testing.T) {
	query, args, err := projectedEntityCleanupCandidatesSQL(ports.ProjectionCleanupRequest{
		TenantID:     "writer",
		SourceID:     "okta",
		RuntimeID:    "okta-audit-runtime",
		EntityTypes:  []string{"okta.resource"},
		URNPrefixes:  []string{"urn:cerebro:writer:okta_resource:access_token:"},
		OnlyIsolated: true,
		Limit:        25,
	})
	if err != nil {
		t.Fatalf("projectedEntityCleanupCandidatesSQL() error = %v", err)
	}
	for _, want := range []string{
		"e.tenant_id = $1",
		"e.source_id = $2",
		"e.runtime_id = $3",
		"e.entity_type IN ($4)",
		"LEFT(e.urn, LENGTH($5)) = $5",
		"NOT EXISTS (SELECT 1 FROM entity_links l WHERE l.from_urn = e.urn OR l.to_urn = e.urn)",
		"NOT EXISTS (SELECT 1 FROM entity_link_assertions a WHERE a.from_urn = e.urn OR a.to_urn = e.urn)",
		// GraphReview issue 3: candidates a quarantined legacy row or
		// another source/runtime's own coverage will still block sort
		// after the ones this pass can actually finish, so bounded
		// pagination keeps making real progress.
		"l.assertion_quarantined OR l.tenant_id <> $6 OR l.source_id <> $7 OR l.runtime_id <> $8",
		"a.tenant_id <> $6 OR a.source_id <> $7 OR a.runtime_id <> $8",
		"ORDER BY (",
		"LIMIT $9",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("cleanup candidates SQL missing %q:\n%s", want, query)
		}
	}
	if strings.Contains(query, "DELETE FROM") {
		t.Fatalf("cleanup candidates SQL must not delete; deletion is orchestrated in Go:\n%s", query)
	}
	if len(args) != 9 {
		t.Fatalf("cleanup candidates SQL args = %d, want 9", len(args))
	}
	if args[4] != "urn:cerebro:writer:okta_resource:access_token:" {
		t.Fatalf("cleanup prefix arg = %#v, want literal access_token prefix", args[4])
	}
	if args[5] != "writer" || args[6] != "okta" || args[7] != "okta-audit-runtime" {
		t.Fatalf("cleanup ordering scope args = %#v, want tenant/source/runtime", args[5:8])
	}
	if args[8] != uint32(25) {
		t.Fatalf("cleanup limit arg = %#v, want uint32(25)", args[8])
	}
}

func TestProjectedEndpointOwnerIDLinkCleanupSQLRequiresTenant(t *testing.T) {
	if _, _, err := projectedEndpointOwnerIDLinkCleanupSQL(ports.ProjectionLinkCleanupRequest{DryRun: true}); err == nil {
		t.Fatal("projectedEndpointOwnerIDLinkCleanupSQL() error = nil, want tenant scope requirement")
	}
}

func TestProjectedEndpointOwnerIDLinkCleanupSQLScopesToReplacementIdentifiers(t *testing.T) {
	query, args, err := projectedEndpointOwnerIDLinkCleanupSQL(ports.ProjectionLinkCleanupRequest{
		TenantID: "writer",
		SourceID: "kolide",
		DryRun:   true,
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("projectedEndpointOwnerIDLinkCleanupSQL() error = %v", err)
	}
	for _, want := range []string{
		"l.tenant_id = $1",
		"e.entity_type IN ('kolide.device', 'kandji.device')",
		"l.relation IN ('owned_by', 'represents_identity', 'has_identifier')",
		"replacement.relation = 'has_identifier'",
		"SELECT COUNT(*) AS links_matched, 0 AS links_deleted",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("endpoint owner-id cleanup SQL missing %q:\n%s", want, query)
		}
	}
	argsText := fmt.Sprint(args)
	for _, want := range []string{
		"urn:cerebro:writer:identity:login:",
		"urn:cerebro:writer:identifier:login:",
		"urn:cerebro:writer:endpoint_identifier:kolide_owner_id:",
		"urn:cerebro:writer:endpoint_identifier:kolide_user_id:",
	} {
		if !strings.Contains(argsText, want) {
			t.Fatalf("endpoint owner-id cleanup args missing %q: %#v", want, args)
		}
	}
	if strings.Contains(query, "DELETE FROM entity_link_assertions") {
		t.Fatalf("dry-run endpoint owner-id cleanup SQL deletes rows:\n%s", query)
	}
	if len(args) == 0 || args[len(args)-1] != uint32(50) {
		t.Fatalf("cleanup SQL limit arg = %#v, want trailing uint32(50)", args)
	}
}

func TestProjectedEndpointOwnerIDLinkCleanupSQLRuntimeScopesOnlyStaleLinks(t *testing.T) {
	query, _, err := projectedEndpointOwnerIDLinkCleanupSQL(ports.ProjectionLinkCleanupRequest{
		TenantID:  "writer",
		SourceID:  "kolide",
		RuntimeID: "runtime-a",
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("projectedEndpointOwnerIDLinkCleanupSQL() error = %v", err)
	}
	if !strings.Contains(query, "l.runtime_id = $") {
		t.Fatalf("endpoint owner-id cleanup SQL missing stale runtime scope:\n%s", query)
	}
	if strings.Contains(query, "replacement.runtime_id") {
		t.Fatalf("endpoint owner-id cleanup SQL incorrectly scopes replacement runtime:\n%s", query)
	}
}

func TestPostgresCleanupEndpointOwnerIDLinksIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run Postgres projection cleanup integration test")
	}
	ctx := context.Background()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()
	tenantID := fmt.Sprintf("writer-cleanup-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupPostgresProjectionTenant(store, tenantID) })

	endpointURN := fmt.Sprintf("urn:cerebro:%s:kolide_device:device-1", tenantID)
	identityURN := fmt.Sprintf("urn:cerebro:%s:identity:login:user-1", tenantID)
	identifierURN := fmt.Sprintf("urn:cerebro:%s:identifier:login:user-1", tenantID)
	emailIdentityURN := fmt.Sprintf("urn:cerebro:%s:identity:email:alice@example.com", tenantID)
	unmigratedIdentityURN := fmt.Sprintf("urn:cerebro:%s:identity:login:user-2", tenantID)
	replacementURN := fmt.Sprintf("urn:cerebro:%s:endpoint_identifier:kolide_user_id:user-1", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: endpointURN, TenantID: tenantID, SourceID: "kolide", EntityType: "kolide.device", Label: "device-1"},
		{URN: identityURN, TenantID: tenantID, SourceID: "kolide", EntityType: "identity.login", Label: "user-1"},
		{URN: identifierURN, TenantID: tenantID, SourceID: "kolide", EntityType: "identifier.login", Label: "user-1"},
		{URN: emailIdentityURN, TenantID: tenantID, SourceID: "kolide", EntityType: "identity.email", Label: "alice@example.com"},
		{URN: unmigratedIdentityURN, TenantID: tenantID, SourceID: "kolide", EntityType: "identity.login", Label: "user-2"},
		{URN: replacementURN, TenantID: tenantID, SourceID: "kolide", EntityType: "endpoint.identifier", Label: "user-1"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	staleLinks := []*ports.ProjectedLink{
		{TenantID: tenantID, SourceID: "kolide", FromURN: endpointURN, Relation: "owned_by", ToURN: identityURN},
		{TenantID: tenantID, SourceID: "kolide", FromURN: endpointURN, Relation: "represents_identity", ToURN: identityURN},
		{TenantID: tenantID, SourceID: "kolide", FromURN: endpointURN, Relation: "has_identifier", ToURN: identifierURN},
	}
	preservedLinks := []*ports.ProjectedLink{
		{TenantID: tenantID, SourceID: "kolide", FromURN: endpointURN, Relation: "owned_by", ToURN: emailIdentityURN},
		{TenantID: tenantID, SourceID: "kolide", FromURN: endpointURN, Relation: "owned_by", ToURN: unmigratedIdentityURN},
		{TenantID: tenantID, SourceID: "kolide", FromURN: endpointURN, Relation: "has_identifier", ToURN: replacementURN},
	}
	for _, link := range append(staleLinks, preservedLinks...) {
		if err := store.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("upsert link %s %s %s: %v", link.FromURN, link.Relation, link.ToURN, err)
		}
	}
	request := ports.ProjectionLinkCleanupRequest{TenantID: tenantID, SourceID: "kolide", DryRun: true}
	result, err := store.CleanupEndpointOwnerIDLinks(ctx, request)
	if err != nil {
		t.Fatalf("dry-run cleanup endpoint owner-id links: %v", err)
	}
	if result.LinksMatched != uint32FromTestLen(len(staleLinks)) || result.LinksDeleted != 0 {
		t.Fatalf("dry-run cleanup result = %#v, want %d matches and no deletes", result, len(staleLinks))
	}
	for _, link := range staleLinks {
		assertPostgresProjectedLinkExists(t, ctx, store, link)
	}
	request.DryRun = false
	result, err = store.CleanupEndpointOwnerIDLinks(ctx, request)
	if err != nil {
		t.Fatalf("cleanup endpoint owner-id links: %v", err)
	}
	if result.LinksMatched != uint32FromTestLen(len(staleLinks)) || result.LinksDeleted != uint32FromTestLen(len(staleLinks)) {
		t.Fatalf("cleanup result = %#v, want %d deletes", result, len(staleLinks))
	}
	for _, link := range staleLinks {
		assertPostgresProjectedLinkMissing(t, ctx, store, link)
	}
	for _, link := range preservedLinks {
		assertPostgresProjectedLinkExists(t, ctx, store, link)
	}
}

func uint32FromTestLen(value int) uint32 {
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value) // #nosec G115 -- helper clamps test slice lengths before narrowing.
}

func assertPostgresProjectedLinkExists(t *testing.T, ctx context.Context, store *Store, link *ports.ProjectedLink) {
	t.Helper()
	if !postgresProjectedLinkExists(t, ctx, store, link) {
		t.Fatalf("projected link missing: %s %s %s", link.FromURN, link.Relation, link.ToURN)
	}
}

func assertPostgresProjectedLinkMissing(t *testing.T, ctx context.Context, store *Store, link *ports.ProjectedLink) {
	t.Helper()
	if postgresProjectedLinkExists(t, ctx, store, link) {
		t.Fatalf("projected link still exists: %s %s %s", link.FromURN, link.Relation, link.ToURN)
	}
}

func postgresProjectedLinkExists(t *testing.T, ctx context.Context, store *Store, link *ports.ProjectedLink) bool {
	t.Helper()
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_links WHERE from_urn = $1 AND relation = $2 AND to_urn = $3`, link.FromURN, link.Relation, link.ToURN).Scan(&count); err != nil {
		t.Fatalf("query projected link: %v", err)
	}
	return count > 0
}

func cleanupPostgresProjectionTenant(store *Store, tenantID string) {
	ctx := context.Background()
	_, _ = store.db.ExecContext(ctx, `DELETE FROM entity_link_assertions WHERE tenant_id = $1`, tenantID)
	_, _ = store.db.ExecContext(ctx, `DELETE FROM entity_links WHERE tenant_id = $1`, tenantID)
	_, _ = store.db.ExecContext(ctx, `DELETE FROM link_set_observations WHERE tenant_id = $1`, tenantID)
	_, _ = store.db.ExecContext(ctx, `DELETE FROM entities WHERE tenant_id = $1`, tenantID)
}

func openPostgresProjectionTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run Postgres projection integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	tenantID := fmt.Sprintf("writer-f06-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupPostgresProjectionTenant(store, tenantID) })
	return store, tenantID
}

// TestPostgresProjectedLinkAssertionsIndependentAcrossWriteOrdersAndRetraction
// reproduces F06 directly: runtime A asserts an edge, runtime B asserts the
// same edge, and B replacing/retracting its own assertion must never
// remove A's. Exercises both write orders and proves the logical edge is
// only removed once the last relevant assertion is gone.
func TestPostgresProjectedLinkAssertionsIndependentAcrossWriteOrdersAndRetraction(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: consumer, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	linkFor := func(runtimeID string) *ports.ProjectedLink {
		return &ports.ProjectedLink{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: runtimeID,
			FromURN: owner, ToURN: consumer, Relation: "associated_with",
		}
	}

	// Order 1: A asserts, then B asserts; B retracts, A's assertion survives.
	if err := store.UpsertProjectedLink(ctx, linkFor("runtime-a")); err != nil {
		t.Fatalf("upsert link runtime-a: %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, linkFor("runtime-b")); err != nil {
		t.Fatalf("upsert link runtime-b: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, linkFor(""))
	if err := store.DeleteProjectedLink(ctx, linkFor("runtime-b")); err != nil {
		t.Fatalf("delete link runtime-b: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, linkFor(""))
	if err := store.DeleteProjectedLink(ctx, linkFor("runtime-a")); err != nil {
		t.Fatalf("delete link runtime-a: %v", err)
	}
	assertPostgresProjectedLinkMissing(t, ctx, store, linkFor(""))

	// Order 2 (reversed write order): B asserts, then A asserts; A retracts
	// first this time, B's assertion must still survive, and only removing
	// B's own assertion finally clears the logical edge.
	if err := store.UpsertProjectedLink(ctx, linkFor("runtime-b")); err != nil {
		t.Fatalf("upsert link runtime-b (reorder): %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, linkFor("runtime-a")); err != nil {
		t.Fatalf("upsert link runtime-a (reorder): %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, linkFor(""))
	if err := store.DeleteProjectedLink(ctx, linkFor("runtime-a")); err != nil {
		t.Fatalf("delete link runtime-a (reorder): %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, linkFor(""))
	if err := store.DeleteProjectedLink(ctx, linkFor("runtime-b")); err != nil {
		t.Fatalf("delete link runtime-b (reorder): %v", err)
	}
	assertPostgresProjectedLinkMissing(t, ctx, store, linkFor(""))
}

// TestPostgresProjectedLinkUpsertReplayIsIdempotent proves replaying the
// exact same assertion twice changes nothing observable and never disturbs
// another runtime's independent assertion of the same edge.
func TestPostgresProjectedLinkUpsertReplayIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: consumer, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	link := &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-a",
		FromURN: owner, ToURN: consumer, Relation: "associated_with",
		Attributes: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}
	otherRuntimeLink := &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-b",
		FromURN: owner, ToURN: consumer, Relation: "associated_with",
	}
	if err := store.UpsertProjectedLink(ctx, otherRuntimeLink); err != nil {
		t.Fatalf("upsert other runtime link: %v", err)
	}
	for i := range 2 {
		if err := store.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("replay upsert link attempt %d: %v", i, err)
		}
	}
	var assertionCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_link_assertions WHERE from_urn = $1 AND relation = $2 AND to_urn = $3 AND source_id = $4 AND runtime_id = $5`,
		owner, "associated_with", consumer, "vulnview", "runtime-a").Scan(&assertionCount); err != nil {
		t.Fatalf("count assertion rows: %v", err)
	}
	if assertionCount != 1 {
		t.Fatalf("assertion rows for runtime-a = %d, want exactly 1 after replay", assertionCount)
	}
	if err := store.DeleteProjectedLink(ctx, link); err != nil {
		t.Fatalf("delete replayed link: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumer})
}

// TestPostgresLegacyLinkAssertionCoveragePolicy exercises the bounded,
// conservative legacy-row policy (F06): a pre-existing entity_links row
// with no assertion coverage is counted missing, a new conflicting
// assertion never overwrites its provenance (only raises
// assertion_quarantined), and MigrateProjectedLinkAssertions quarantines
// it without inventing assertion_managed coverage — real coverage requires
// a full rebuild.
func TestPostgresLegacyLinkAssertionCoveragePolicy(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:legacy-principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/legacy", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "legacy-principal"},
		{URN: consumer, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "legacy"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	// Simulate a pre-F06 logical row written directly, bypassing the
	// assertion model entirely (assertion_managed defaults to false).
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json)
VALUES ($1, 'associated_with', $2, $3, 'legacy-source', 'legacy-runtime', '{"legacy":"true"}'::jsonb)`,
		owner, consumer, tenantID); err != nil {
		t.Fatalf("seed legacy entity_links row: %v", err)
	}

	missing, err := store.CountProjectedLinksMissingAssertions(ctx, tenantID, []string{"associated_with"})
	if err != nil {
		t.Fatalf("CountProjectedLinksMissingAssertions() error = %v", err)
	}
	if missing != 1 {
		t.Fatalf("CountProjectedLinksMissingAssertions() = %d, want 1 uncovered legacy row", missing)
	}

	// A new, independent assertion must never overwrite the legacy row's
	// provenance or attributes.
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-new",
		FromURN: owner, ToURN: consumer, Relation: "associated_with",
		Attributes: map[string]string{"fresh": "true"},
	}); err != nil {
		t.Fatalf("upsert conflicting assertion over legacy row: %v", err)
	}
	var sourceID, runtimeID string
	var quarantined, managed bool
	var attributesRaw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT source_id, runtime_id, assertion_managed, assertion_quarantined, attributes_json FROM entity_links WHERE from_urn=$1 AND relation='associated_with' AND to_urn=$2`, owner, consumer).
		Scan(&sourceID, &runtimeID, &managed, &quarantined, &attributesRaw); err != nil {
		t.Fatalf("read legacy entity_links row: %v", err)
	}
	if sourceID != "legacy-source" || runtimeID != "legacy-runtime" {
		t.Fatalf("legacy row provenance overwritten: source_id=%q runtime_id=%q, want legacy-source/legacy-runtime", sourceID, runtimeID)
	}
	if !strings.Contains(string(attributesRaw), "legacy") {
		t.Fatalf("legacy row attributes overwritten: %s", attributesRaw)
	}
	if managed {
		t.Fatal("legacy row became assertion_managed from a plain conflicting upsert; only MigrateProjectedLinkAssertions/rebuild may change coverage")
	}
	if !quarantined {
		t.Fatal("legacy row with a conflicting new assertion was not flagged assertion_quarantined")
	}

	// MigrateProjectedLinkAssertions quarantines the row without inventing
	// assertion_managed coverage.
	migrateResult, err := store.MigrateProjectedLinkAssertions(ctx, ports.ProjectionAssertionMigrationRequest{TenantID: tenantID, Relations: []string{"associated_with"}})
	if err != nil {
		t.Fatalf("MigrateProjectedLinkAssertions() error = %v", err)
	}
	if migrateResult.LinksMatched != 1 || migrateResult.LinksQuarantined != 1 {
		t.Fatalf("MigrateProjectedLinkAssertions() = %#v, want 1 matched and quarantined", migrateResult)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT assertion_managed, assertion_quarantined FROM entity_links WHERE from_urn=$1 AND relation='associated_with' AND to_urn=$2`, owner, consumer).
		Scan(&managed, &quarantined); err != nil {
		t.Fatalf("read migrated legacy row: %v", err)
	}
	if managed {
		t.Fatal("MigrateProjectedLinkAssertions must never invent assertion_managed coverage for a legacy row")
	}
	if !quarantined {
		t.Fatal("MigrateProjectedLinkAssertions did not quarantine the legacy row")
	}
	// Coverage is still measurably missing: only a full rebuild (not this
	// bounded migration) can establish real coverage.
	missing, err = store.CountProjectedLinksMissingAssertions(ctx, tenantID, []string{"associated_with"})
	if err != nil {
		t.Fatalf("CountProjectedLinksMissingAssertions() after migration error = %v", err)
	}
	if missing != 1 {
		t.Fatalf("CountProjectedLinksMissingAssertions() after migration = %d, want still 1 (quarantine is not coverage)", missing)
	}
}

// TestPostgresProjectionSchemaUpgradeIsIdempotentOnExistingTables proves the
// F06 migration applies cleanly to a database that already has the
// pre-assertion-model entities/entity_links/link_set_observations tables,
// and that re-running it afterward is a safe no-op.
func TestPostgresProjectionSchemaUpgradeIsIdempotentOnExistingTables(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run Postgres projection schema upgrade integration test")
	}
	ctx := context.Background()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()
	preF06Statements := []string{
		`CREATE TABLE IF NOT EXISTS entities (
  urn TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  application_workspace_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  entity_type TEXT NOT NULL,
  label TEXT NOT NULL,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
		`CREATE TABLE IF NOT EXISTS entity_links (
  from_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  to_urn TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  application_workspace_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (from_urn, relation, to_urn)
)`,
		`CREATE TABLE IF NOT EXISTS link_set_observations (
  owner_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  outgoing BOOLEAN NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  observation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (owner_urn, relation, outgoing, tenant_id, source_id, runtime_id)
)`,
	}
	for _, statement := range preF06Statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("seed pre-F06 schema: %v", err)
		}
	}
	tenantID := fmt.Sprintf("writer-upgrade-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupPostgresProjectionTenant(store, tenantID) })

	// First call through the real store triggers ensureProjectionStatements
	// against the already-existing pre-F06 tables.
	entity := &ports.ProjectedEntity{URN: fmt.Sprintf("urn:cerebro:%s:aws_role:upgrade", tenantID), TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "upgrade"}
	if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
		t.Fatalf("upsert entity against upgraded schema: %v", err)
	}
	for _, column := range []string{"assertion_managed", "assertion_quarantined"} {
		var exists bool
		if err := store.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'entity_links' AND column_name = $1)`, column).Scan(&exists); err != nil {
			t.Fatalf("check entity_links column %s: %v", column, err)
		}
		if !exists {
			t.Fatalf("entity_links missing migrated column %s after upgrade", column)
		}
	}
	var assertionsTableExists bool
	if err := store.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'entity_link_assertions')`).Scan(&assertionsTableExists); err != nil {
		t.Fatalf("check entity_link_assertions table: %v", err)
	}
	if !assertionsTableExists {
		t.Fatal("entity_link_assertions table was not created by the upgrade")
	}

	// Re-running the ensure path (a fresh Store against the same DSN, so
	// the in-process "already ensured" flag does not short-circuit it)
	// must be a safe no-op that does not error on the now-migrated schema.
	secondStore, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("reopen postgres store: %v", err)
	}
	defer func() { _ = secondStore.Close() }()
	if err := secondStore.UpsertProjectedEntity(ctx, entity); err != nil {
		t.Fatalf("re-running projection schema migration errored: %v", err)
	}
}

// TestPostgresUpsertProjectedEntityStaleStrictObservationChangesNothing and
// the accepted-observation case below exercise G1 directly against the
// real store: a stale strict-precedence observation changes nothing at
// all, while an accepted newer observation applies RetractedAttributes.
func TestPostgresUpsertProjectedEntityStaleStrictObservationChangesNothing(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	urn := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:finding-1", tenantID)
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: tenantID, SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v2",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "2",
			"triage_state":           "accepted",
			"triage_reason":          "known-risk",
		},
	}); err != nil {
		t.Fatalf("upsert v2: %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: tenantID, SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v1-replay",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "1",
			"triage_state":           "none",
		},
		RetractedAttributes: []string{"triage_reason"},
	}); err != nil {
		t.Fatalf("upsert stale v1 replay: %v", err)
	}
	stored, err := store.GetProjectedEntity(ctx, urn)
	if err != nil {
		t.Fatalf("GetProjectedEntity() error = %v", err)
	}
	if stored == nil {
		t.Fatal("GetProjectedEntity() = nil, want the v2 entity")
	}
	if stored.Label != "v2" {
		t.Fatalf("stale replay changed label to %q, want v2 preserved", stored.Label)
	}
	if stored.Attributes["triage_state"] != "accepted" || stored.Attributes["triage_reason"] != "known-risk" {
		t.Fatalf("stale strict replay changed attributes: %#v", stored.Attributes)
	}
}

func TestPostgresUpsertProjectedEntityAcceptedObservationRemovesRetractedAttributes(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	urn := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:finding-2", tenantID)
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: tenantID, SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v1",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "1",
			"triage_state":           "accepted",
			"triage_reason":          "known-risk",
			"asset_name":             "web-app",
		},
	}); err != nil {
		t.Fatalf("upsert v1: %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: urn, TenantID: tenantID, SourceID: "vulnview", EntityType: "vulnview.finding", Label: "v2",
		Attributes: map[string]string{
			"observation_precedence": "strict",
			"observation_version":    "2",
			"triage_state":           "none",
			"asset_name":             "web-app",
		},
		RetractedAttributes: []string{"triage_reason"},
	}); err != nil {
		t.Fatalf("upsert accepted v2: %v", err)
	}
	stored, err := store.GetProjectedEntity(ctx, urn)
	if err != nil {
		t.Fatalf("GetProjectedEntity() error = %v", err)
	}
	if stored == nil {
		t.Fatal("GetProjectedEntity() = nil, want the v2 entity")
	}
	if _, present := stored.Attributes["triage_reason"]; present {
		t.Fatalf("accepted observation left retracted key: %#v", stored.Attributes)
	}
	if stored.Attributes["triage_state"] != "none" || stored.Attributes["asset_name"] != "web-app" {
		t.Fatalf("accepted observation did not preserve unrelated/updated keys: %#v", stored.Attributes)
	}
}

// TestPostgresUpsertProjectedEntityCreateOnly exercises both CreateOnly
// orderings (G1): a provider-owned entity's richer facts are never
// overwritten by a later stub, and a stub entity is fully replaced by a
// subsequent ordinary (provider) observation.
func TestPostgresUpsertProjectedEntityCreateOnly(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)

	t.Run("provider-first-then-stub", func(t *testing.T) {
		urn := fmt.Sprintf("urn:cerebro:%s:gcp_service_account:provider-first", tenantID)
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: tenantID, SourceID: "gcp", RuntimeID: "gcp-runtime", EntityType: "gcp.service_account", Label: "real-account",
			Attributes: map[string]string{"domain": "example.com"},
		}); err != nil {
			t.Fatalf("upsert provider entity: %v", err)
		}
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "vulnview-runtime", EntityType: "gcp.service_account", Label: "stub",
			Attributes: map[string]string{"stub": "true"},
			CreateOnly: true,
		}); err != nil {
			t.Fatalf("upsert create-only stub over provider entity: %v", err)
		}
		stored, err := store.GetProjectedEntity(ctx, urn)
		if err != nil {
			t.Fatalf("GetProjectedEntity() error = %v", err)
		}
		if stored == nil {
			t.Fatal("GetProjectedEntity() = nil")
		}
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
		urn := fmt.Sprintf("urn:cerebro:%s:gcp_service_account:stub-first", tenantID)
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "vulnview-runtime", EntityType: "gcp.service_account", Label: "stub",
			CreateOnly: true,
		}); err != nil {
			t.Fatalf("upsert create-only stub: %v", err)
		}
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN: urn, TenantID: tenantID, SourceID: "gcp", RuntimeID: "gcp-runtime", EntityType: "gcp.service_account", Label: "real-account",
			Attributes: map[string]string{"domain": "example.com"},
		}); err != nil {
			t.Fatalf("upsert provider entity over stub: %v", err)
		}
		stored, err := store.GetProjectedEntity(ctx, urn)
		if err != nil {
			t.Fatalf("GetProjectedEntity() error = %v", err)
		}
		if stored == nil {
			t.Fatal("GetProjectedEntity() = nil")
		}
		if stored.SourceID != "gcp" || stored.RuntimeID != "gcp-runtime" || stored.Label != "real-account" {
			t.Fatalf("ordinary observation did not replace stub ownership/label: %#v", stored)
		}
		if stored.Attributes["domain"] != "example.com" {
			t.Fatalf("provider attributes missing after replacing stub: %#v", stored.Attributes)
		}
	})
}

// TestPostgresReplaceProjectedLinkSetsIntegration proves Contract C9's
// guard through the real store: narrowing a set retracts only the dropped
// link, a stale observation is a no-op, an authoritative empty set clears
// the whole scope, and another runtime's row on the exact same owner and
// relation is never touched.
func TestPostgresReplaceProjectedLinkSetsIntegration(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)

	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumerA := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	consumerB := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/b", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: consumerA, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
		{URN: consumerB, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "b"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	linkSet := func(runtimeID string, at string, consumers ...string) *ports.ProjectedLinkSet {
		links := make([]*ports.ProjectedLink, 0, len(consumers))
		for _, consumer := range consumers {
			links = append(links, &ports.ProjectedLink{
				TenantID: tenantID, SourceID: "vulnview", RuntimeID: runtimeID,
				FromURN: owner, ToURN: consumer, Relation: "associated_with",
			})
		}
		return &ports.ProjectedLinkSet{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner, Relation: "associated_with", Outgoing: true,
			Links: links, Observation: map[string]string{"at": at},
		}
	}

	// {A,B} -> {A} retracts only B.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T10:00:00Z", consumerA, consumerB),
	}); err != nil {
		t.Fatalf("initial link set: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerB})
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T10:05:00Z", consumerA),
	}); err != nil {
		t.Fatalf("narrowed link set: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})
	assertPostgresProjectedLinkMissing(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerB})

	// A stale observation must neither retract nor restore anything.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T09:00:00Z"),
	}); err != nil {
		t.Fatalf("stale retract attempt: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})

	// An authoritative empty set clears the whole scope.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T11:00:00Z"),
	}); err != nil {
		t.Fatalf("authoritative clear: %v", err)
	}
	assertPostgresProjectedLinkMissing(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})

	// Another runtime's row on the same owner and relation is never touched.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-2", "2026-11-02T10:00:00Z", consumerB),
	}); err != nil {
		t.Fatalf("other runtime set: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet("runtime-1", "2026-11-02T12:00:00Z", consumerA),
	}); err != nil {
		t.Fatalf("our runtime set: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerB})
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})
}

// TestPostgresReplaceProjectedLinkSetsIncompleteKeepsPriorLinks reproduces
// the F04/G1 ordering scenario end to end: v1 asserts a complete {A} set,
// v3 is accepted but Incomplete (so it advances the guard without touching
// links), and a reordered replay of the older v2 with a complete {B} set
// must be rejected as stale, leaving {A} untouched.
func TestPostgresReplaceProjectedLinkSetsIncompleteKeepsPriorLinks(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumerA := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	consumerB := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/b", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: consumerA, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
		{URN: consumerB, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "b"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}

	// v1: complete set {A}.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: consumerA, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}}); err != nil {
		t.Fatalf("apply v1 {A}: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})

	// v3: accepted but Incomplete (no links). Advances the guard only.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Incomplete:  true,
		Observation: map[string]string{"at": "2026-11-02T12:00:00Z"},
	}}); err != nil {
		t.Fatalf("apply v3 incomplete: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})

	// v2: reordered replay with complete {B}, older than v3's guard. Must
	// be rejected as stale: {A} stays exactly as it was.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: consumerB, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T11:00:00Z"},
	}}); err != nil {
		t.Fatalf("apply stale v2 {B}: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerA})
	assertPostgresProjectedLinkMissing(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumerB})
}

// TestPostgresReplaceProjectedLinkSetsIncompleteRejectsLinks proves an
// Incomplete set carrying links is rejected rather than silently accepted
// (G1): Links MUST be empty when Incomplete is set.
func TestPostgresReplaceProjectedLinkSetsIncompleteRejectsLinks(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Incomplete: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: consumer, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}})
	if err == nil {
		t.Fatal("ReplaceProjectedLinkSets() error = nil, want rejection of Incomplete set carrying links")
	}
}

// TestPostgresCleanupProjectedEntitiesPreservesOtherSourceAssertion proves
// F06's cleanup safety directly: cleaning up one source/runtime's scope
// retracts only that scope's own assertions, and an entity/edge still
// asserted by a different source survives both the assertion retraction
// and the isolated-entity deletion step.
func TestPostgresCleanupProjectedEntitiesPreservesOtherSourceAssertion(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "vulnview-runtime", EntityType: "aws_role", Label: "principal"},
		{URN: consumer, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "vulnview-runtime", EntityType: "kubernetes_service_account", Label: "a"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	// Two independent sources assert the exact same edge.
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "vulnview-runtime",
		FromURN: owner, ToURN: consumer, Relation: "associated_with",
	}); err != nil {
		t.Fatalf("upsert vulnview assertion: %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "legacy-source", RuntimeID: "legacy-runtime",
		FromURN: owner, ToURN: consumer, Relation: "associated_with",
	}); err != nil {
		t.Fatalf("upsert legacy-source assertion: %v", err)
	}

	result, err := store.CleanupProjectedEntities(ctx, ports.ProjectionCleanupRequest{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "vulnview-runtime",
	})
	if err != nil {
		t.Fatalf("CleanupProjectedEntities() error = %v", err)
	}
	if result.EntitiesMatched != 2 {
		t.Fatalf("CleanupProjectedEntities() entities matched = %d, want 2", result.EntitiesMatched)
	}
	if result.LinksMatched == 0 || result.LinksDeleted == 0 {
		t.Fatalf("CleanupProjectedEntities() = %#v, want the vulnview assertion retracted", result)
	}
	// The legacy-source assertion and the shared logical edge it still
	// covers must survive.
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumer})
	var remainingAssertions int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_link_assertions WHERE from_urn=$1 AND relation='associated_with' AND to_urn=$2`, owner, consumer).Scan(&remainingAssertions); err != nil {
		t.Fatalf("count remaining assertions: %v", err)
	}
	if remainingAssertions != 1 {
		t.Fatalf("remaining assertions = %d, want exactly 1 (legacy-source)", remainingAssertions)
	}
	// Both entities must survive too: they are still referenced by the
	// surviving legacy-source assertion/logical edge.
	if stored, err := store.GetProjectedEntity(ctx, owner); err != nil || stored == nil {
		t.Fatalf("owner entity was deleted despite a surviving assertion: err=%v stored=%#v", err, stored)
	}
	if stored, err := store.GetProjectedEntity(ctx, consumer); err != nil || stored == nil {
		t.Fatalf("consumer entity was deleted despite a surviving assertion: err=%v stored=%#v", err, stored)
	}
}

// TestPostgresConcurrentFirstProjectedLinkAssertionsBothPersist proves the
// reconcileProjectedLink advisory lock fix: two transactions racing to
// assert the very first (previously unseen) assertion of the same edge
// from different source/runtimes must never fail with a unique-violation
// on the shared entity_links row. Both independent assertions must land
// and exactly one materialized logical row must result. Run over many
// iterations/goroutine pairs to make the race likely without being flaky
// (either ordering is a pass; only an error or a missing assertion fails).
func TestPostgresConcurrentFirstProjectedLinkAssertionsBothPersist(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: consumer, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	const iterations = 20
	for i := range iterations {
		fromURN := fmt.Sprintf("urn:cerebro:%s:aws_role:principal-%d", tenantID, i)
		toURN := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a-%d", tenantID, i)
		for _, entity := range []*ports.ProjectedEntity{
			{URN: fromURN, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
			{URN: toURN, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
		} {
			if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
				t.Fatalf("iteration %d: upsert entity %s: %v", i, entity.URN, err)
			}
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for runtimeIndex, runtimeID := range []string{"runtime-a", "runtime-b"} {
			wg.Add(1)
			go func(index int, runtimeID string) {
				defer wg.Done()
				errs[index] = store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
					TenantID: tenantID, SourceID: "vulnview", RuntimeID: runtimeID,
					FromURN: fromURN, ToURN: toURN, Relation: "associated_with",
				})
			}(runtimeIndex, runtimeID)
		}
		wg.Wait()
		for index, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d: concurrent first assertion %d failed: %v", i, index, err)
			}
		}
		var assertionCount int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_link_assertions WHERE from_urn=$1 AND relation='associated_with' AND to_urn=$2`, fromURN, toURN).Scan(&assertionCount); err != nil {
			t.Fatalf("iteration %d: count assertions: %v", i, err)
		}
		if assertionCount != 2 {
			t.Fatalf("iteration %d: assertion rows = %d, want both runtime-a and runtime-b to persist", i, assertionCount)
		}
		var logicalCount int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_links WHERE from_urn=$1 AND relation='associated_with' AND to_urn=$2`, fromURN, toURN).Scan(&logicalCount); err != nil {
			t.Fatalf("iteration %d: count logical rows: %v", i, err)
		}
		if logicalCount != 1 {
			t.Fatalf("iteration %d: logical rows = %d, want exactly 1 materialized edge", i, logicalCount)
		}
	}
}
