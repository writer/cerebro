package kuzu

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestUpsertProjectedEntityAndLink(t *testing.T) {
	store, err := Open(config.GraphStoreConfig{
		Driver:   config.GraphStoreDriverKuzu,
		KuzuPath: filepath.Join(t.TempDir(), "graph"),
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}()

	ctx := context.Background()
	user := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
		Label:      "Alice",
		Attributes: map[string]string{"login": "alice"},
	}
	repo := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_repo:writer/cerebro",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.repo",
		Label:      "writer/cerebro",
	}
	if err := store.UpsertProjectedEntity(ctx, user); err != nil {
		t.Fatalf("UpsertProjectedEntity(user) error = %v", err)
	}
	updatedUser := *user
	updatedUser.Label = "Alice Example"
	if err := store.UpsertProjectedEntity(ctx, &updatedUser); err != nil {
		t.Fatalf("UpsertProjectedEntity(updatedUser) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, repo); err != nil {
		t.Fatalf("UpsertProjectedEntity(repo) error = %v", err)
	}
	link := &ports.ProjectedLink{
		TenantID:   "writer",
		SourceID:   "github",
		FromURN:    user.URN,
		ToURN:      repo.URN,
		Relation:   "belongs_to",
		Attributes: map[string]string{"event_id": "evt-1"},
	}
	if err := store.UpsertProjectedLink(ctx, link); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, link); err != nil {
		t.Fatalf("UpsertProjectedLink(idempotent) error = %v", err)
	}

	var label string
	if err := store.db.QueryRowContext(
		ctx,
		fmt.Sprintf("MATCH (e:entity {urn: %s}) RETURN e.label", cypherString(user.URN)),
	).Scan(&label); err != nil {
		t.Fatalf("query projected entity label: %v", err)
	}
	if label != "Alice Example" {
		t.Fatalf("projected entity label = %q, want %q", label, "Alice Example")
	}

	var linkCount int64
	if err := store.db.QueryRowContext(
		ctx,
		"MATCH (:entity)-[r:relation]->(:entity) RETURN COUNT(r)",
	).Scan(&linkCount); err != nil {
		t.Fatalf("query projected link count: %v", err)
	}
	if linkCount != 1 {
		t.Fatalf("projected link count = %d, want 1", linkCount)
	}
}

func TestUpsertProjectedEntityRejectsNilEntity(t *testing.T) {
	store := &Store{}
	if err := store.UpsertProjectedEntity(context.Background(), nil); err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want non-nil")
	}
}

func TestUpsertProjectedLinkRejectsMissingFromURN(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedLink(context.Background(), &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		Relation: "belongs_to",
		ToURN:    "urn:cerebro:writer:github_repo:writer/cerebro",
	})
	if err == nil {
		t.Fatal("UpsertProjectedLink() error = nil, want non-nil")
	}
}
