package kuzu

import (
	"context"
	"database/sql"
	"encoding/json"
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
	enrichedUser := *user
	enrichedUser.Attributes = map[string]string{"resource_type": "user"}
	if err := store.UpsertProjectedEntity(ctx, &enrichedUser); err != nil {
		t.Fatalf("UpsertProjectedEntity(enrichedUser) error = %v", err)
	}
	var attributesJSON string
	if err := store.db.QueryRowContext(
		ctx,
		fmt.Sprintf("MATCH (e:entity {urn: %s}) RETURN e.attributes_json", cypherString(user.URN)),
	).Scan(&attributesJSON); err != nil {
		t.Fatalf("query projected entity attributes: %v", err)
	}
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
		t.Fatalf("unmarshal projected entity attributes: %v", err)
	}
	if got := attributes["login"]; got != "alice" {
		t.Fatalf("projected entity login attribute = %q, want alice", got)
	}
	if got := attributes["resource_type"]; got != "user" {
		t.Fatalf("projected entity resource_type attribute = %q, want user", got)
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

func TestUpsertProjectedLinkMergesMissingEndpoints(t *testing.T) {
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
	link := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		FromURN:  "urn:cerebro:writer:github_user:alice",
		ToURN:    "urn:cerebro:writer:github_repo:writer/cerebro",
		Relation: "belongs_to",
	}
	if err := store.UpsertProjectedLink(ctx, link); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, link); err != nil {
		t.Fatalf("UpsertProjectedLink(idempotent) error = %v", err)
	}

	var linkCount int64
	if err := store.db.QueryRowContext(ctx, "MATCH (:entity)-[r:relation]->(:entity) RETURN COUNT(r)").Scan(&linkCount); err != nil {
		t.Fatalf("query projected link count: %v", err)
	}
	if linkCount != 1 {
		t.Fatalf("projected link count = %d, want 1", linkCount)
	}
	for _, urn := range []string{link.FromURN, link.ToURN} {
		var nodeCount int64
		if err := store.db.QueryRowContext(
			ctx,
			fmt.Sprintf("MATCH (e:entity {urn: %s}) RETURN COUNT(e)", cypherString(urn)),
		).Scan(&nodeCount); err != nil {
			t.Fatalf("query endpoint %q: %v", urn, err)
		}
		if nodeCount != 1 {
			t.Fatalf("endpoint %q count = %d, want 1", urn, nodeCount)
		}
	}
	entity := &ports.ProjectedEntity{
		URN:        link.FromURN,
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
		Label:      "Alice",
		Attributes: map[string]string{"login": "alice"},
	}
	if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
		t.Fatalf("UpsertProjectedEntity(endpoint after link) error = %v", err)
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

func TestUpsertProjectedLinkPreservesAttributesOnRepeatedUpserts(t *testing.T) {
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
	first := &ports.ProjectedLink{
		TenantID:   "writer",
		SourceID:   "github",
		FromURN:    "urn:cerebro:writer:github_user:alice",
		ToURN:      "urn:cerebro:writer:github_repo:writer/cerebro",
		Relation:   "belongs_to",
		Attributes: map[string]string{"role": "admin"},
	}
	second := &ports.ProjectedLink{
		TenantID:   "writer",
		SourceID:   "github",
		FromURN:    first.FromURN,
		ToURN:      first.ToURN,
		Relation:   first.Relation,
		Attributes: map[string]string{"team": "platform"},
	}
	if err := store.UpsertProjectedLink(ctx, first); err != nil {
		t.Fatalf("UpsertProjectedLink(first) error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, second); err != nil {
		t.Fatalf("UpsertProjectedLink(second) error = %v", err)
	}
	var raw sql.NullString
	if err := store.db.QueryRowContext(ctx, fmt.Sprintf(
		"MATCH (src:entity {urn: %s})-[r:relation {relation: %s}]->(dst:entity {urn: %s}) RETURN r.attributes_json",
		cypherString(first.FromURN), cypherString(first.Relation), cypherString(first.ToURN),
	)).Scan(&raw); err != nil {
		t.Fatalf("query projected link attributes: %v", err)
	}
	got := map[string]string{}
	if err := json.Unmarshal([]byte(raw.String), &got); err != nil {
		t.Fatalf("decode attributes_json: %v", err)
	}
	if got["role"] != "admin" {
		t.Fatalf("attributes role = %q, want admin (lost on repeated upsert)", got["role"])
	}
	if got["team"] != "platform" {
		t.Fatalf("attributes team = %q, want platform", got["team"])
	}
}
