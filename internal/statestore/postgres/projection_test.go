package postgres

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
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

func TestProjectionUpsertsMergeAttributes(t *testing.T) {
	entitySQL := projectedEntityUpsertSQL()
	if !strings.Contains(entitySQL, "attributes_json = entities.attributes_json || EXCLUDED.attributes_json") {
		t.Fatalf("entity upsert does not merge attributes:\n%s", entitySQL)
	}
	linkSQL := projectedLinkUpsertSQL()
	if !strings.Contains(linkSQL, "attributes_json = entity_links.attributes_json || EXCLUDED.attributes_json") {
		t.Fatalf("link upsert does not merge attributes:\n%s", linkSQL)
	}
}

func TestProjectionUpsertsPreserveExistingLabelsForFallbackLabels(t *testing.T) {
	entitySQL := projectedEntityUpsertSQL()
	if !strings.Contains(entitySQL, "label = CASE WHEN EXCLUDED.label = EXCLUDED.urn THEN entities.label ELSE EXCLUDED.label END") {
		t.Fatalf("entity upsert does not preserve existing labels for fallback labels:\n%s", entitySQL)
	}
}

func TestProjectedLinkDeleteUsesPrimaryKey(t *testing.T) {
	linkSQL := projectedLinkDeleteSQL()
	if !strings.Contains(linkSQL, "WHERE from_urn = $1 AND relation = $2 AND to_urn = $3") {
		t.Fatalf("link delete does not use entity_links primary key:\n%s", linkSQL)
	}
	if strings.Contains(linkSQL, "tenant_id") || strings.Contains(linkSQL, "source_id") {
		t.Fatalf("link delete includes non-primary-key filters:\n%s", linkSQL)
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
	if _, _, err := projectedEntityCleanupSQL(ports.ProjectionCleanupRequest{OnlyIsolated: true}); err == nil {
		t.Fatal("projectedEntityCleanupSQL() error = nil, want non-nil")
	}
}

func TestProjectedEntityCleanupSQLIncludesScopedFilters(t *testing.T) {
	query, args, err := projectedEntityCleanupSQL(ports.ProjectionCleanupRequest{
		TenantID:     "writer",
		SourceID:     "okta",
		RuntimeID:    "okta-audit-runtime",
		EntityTypes:  []string{"okta.resource"},
		URNPrefixes:  []string{"urn:cerebro:writer:okta_resource:access_token:"},
		OnlyIsolated: true,
		Limit:        25,
	})
	if err != nil {
		t.Fatalf("projectedEntityCleanupSQL() error = %v", err)
	}
	for _, want := range []string{
		"e.tenant_id = $1",
		"e.source_id = $2",
		"e.runtime_id = $3",
		"e.entity_type IN ($4)",
		"LEFT(e.urn, LENGTH($5)) = $5",
		"NOT EXISTS (SELECT 1 FROM entity_links l WHERE l.from_urn = e.urn OR l.to_urn = e.urn)",
		"LIMIT $6",
		"DELETE FROM entity_links",
		"DELETE FROM entities",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("cleanup SQL missing %q:\n%s", want, query)
		}
	}
	if len(args) != 6 {
		t.Fatalf("cleanup SQL args = %d, want 6", len(args))
	}
	if args[4] != "urn:cerebro:writer:okta_resource:access_token:" {
		t.Fatalf("cleanup prefix arg = %#v, want literal access_token prefix", args[4])
	}
	if args[5] != uint32(25) {
		t.Fatalf("cleanup limit arg = %#v, want uint32(25)", args[5])
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
	if strings.Contains(query, "DELETE FROM entity_links") {
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
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM entity_links WHERE tenant_id = $1`, tenantID)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM entities WHERE tenant_id = $1`, tenantID)
	})

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
