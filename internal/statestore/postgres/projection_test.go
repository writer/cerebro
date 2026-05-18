package postgres

import (
	"context"
	"strings"
	"testing"

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
		ToURN:    "urn:cerebro:writer:github_repo:writer/cerebro",
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
