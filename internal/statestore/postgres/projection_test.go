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
