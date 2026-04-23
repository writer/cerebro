package kuzu

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

func TestUpsertProjectedEntityAndLink(t *testing.T) {
	store := newTestStore(t)
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

	label := queryGraphString(t, store, fmt.Sprintf("MATCH (e:entity {urn: %s}) RETURN e.label", cypherString(user.URN)))
	if label != "Alice Example" {
		t.Fatalf("projected entity label = %q, want %q", label, "Alice Example")
	}

	linkCount := queryGraphCount(t, store, "MATCH (:entity)-[r:relation]->(:entity) RETURN COUNT(r)")
	if linkCount != 1 {
		t.Fatalf("projected link count = %d, want 1", linkCount)
	}
}

func TestProjectorBuildsTraversableLocalGraph(t *testing.T) {
	store := newTestStore(t)
	projectEvents(t, store,
		&cerebrov1.EventEnvelope{
			Id:       "github-pr-447",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.pull_request",
			Payload: mustJSON(t, map[string]any{
				"title": "Add local graph tests",
			}),
			Attributes: map[string]string{
				"author":      "alice",
				"owner":       "writer",
				"pull_number": "447",
				"repository":  "writer/cerebro",
				"state":       "open",
			},
		},
		&cerebrov1.EventEnvelope{
			Id:       "github-audit-1",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"actor":         "alice",
				"org":           "writer",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
			},
		},
	)

	pathCount := queryGraphCount(t, store, fmt.Sprintf(
		"MATCH (author:entity {urn: %s})-[authored:relation]->(pr:entity)-[pr_repo:relation]->(repo:entity)-[repo_org:relation]->(org:entity {urn: %s}) "+
			"WHERE authored.relation = 'authored' AND pr_repo.relation = 'belongs_to' AND repo_org.relation = 'belongs_to' RETURN COUNT(pr)",
		cypherString("urn:cerebro:writer:github_user:alice"),
		cypherString("urn:cerebro:writer:github_org:writer"),
	))
	if pathCount != 1 {
		t.Fatalf("authored pull-request path count = %d, want 1", pathCount)
	}

	traversals, err := store.SampleTraversals(context.Background(), 10)
	if err != nil {
		t.Fatalf("SampleTraversals() error = %v", err)
	}
	if !containsTraversal(traversals,
		"urn:cerebro:writer:github_user:alice",
		"authored",
		"urn:cerebro:writer:github_pull_request:writer/cerebro#447",
		"belongs_to",
		"urn:cerebro:writer:github_repo:writer/cerebro",
	) {
		t.Fatalf("SampleTraversals() missing authored path: %#v", traversals)
	}

	checks, err := store.IntegrityChecks(context.Background())
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	if failedIntegrityChecks(checks) != 0 {
		t.Fatalf("IntegrityChecks() failed = %d, want 0: %#v", failedIntegrityChecks(checks), checks)
	}

	patterns, err := store.PathPatterns(context.Background(), 10)
	if err != nil {
		t.Fatalf("PathPatterns() error = %v", err)
	}
	if !containsPathPattern(patterns, "github.user", "authored", "github.pull_request", "belongs_to", "github.repo", 1) {
		t.Fatalf("PathPatterns() missing authored pattern: %#v", patterns)
	}
}

func TestProjectorKeepsLocalGraphIdentityLinksTenantScoped(t *testing.T) {
	store := newTestStore(t)
	projectEvents(t, store,
		&cerebrov1.EventEnvelope{
			Id:       "github-audit-1",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"actor":         "alice@writer.com",
				"org":           "writer",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
			},
		},
		&cerebrov1.EventEnvelope{
			Id:       "okta-user-1",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.user",
			Attributes: map[string]string{
				"domain":  "writer.okta.com",
				"email":   "alice@writer.com",
				"login":   "alice@writer.com",
				"status":  "ACTIVE",
				"user_id": "00u1",
			},
		},
		&cerebrov1.EventEnvelope{
			Id:       "okta-user-2",
			TenantId: "writer-next",
			SourceId: "okta",
			Kind:     "okta.user",
			Attributes: map[string]string{
				"domain":  "writer.okta.com",
				"email":   "alice@writer.com",
				"login":   "alice@writer.com",
				"status":  "ACTIVE",
				"user_id": "00u2",
			},
		},
	)

	sharedIdentifierPathCount := queryGraphCount(t, store, fmt.Sprintf(
		"MATCH (github_user:entity {urn: %s})-[github_identifier:relation]->(identifier:entity {urn: %s})<-[okta_identifier:relation]-(okta_user:entity {urn: %s}) "+
			"WHERE github_identifier.relation = 'has_identifier' AND okta_identifier.relation = 'has_identifier' RETURN COUNT(identifier)",
		cypherString("urn:cerebro:writer:github_user:alice@writer.com"),
		cypherString("urn:cerebro:writer:identifier:email:alice@writer.com"),
		cypherString("urn:cerebro:writer:okta_user:00u1"),
	))
	if sharedIdentifierPathCount != 1 {
		t.Fatalf("shared identifier path count = %d, want 1", sharedIdentifierPathCount)
	}

	identifierCount := queryGraphCount(t, store,
		"MATCH (identifier:entity) WHERE identifier.entity_type = 'identifier.email' AND identifier.label = 'alice@writer.com' RETURN COUNT(identifier)",
	)
	if identifierCount != 2 {
		t.Fatalf("identifier count = %d, want 2", identifierCount)
	}
}

func TestIntegrityChecksDetectTenantMismatch(t *testing.T) {
	store := newTestStore(t)
	projectEvents(t, store,
		&cerebrov1.EventEnvelope{
			Id:       "github-pr-447",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.pull_request",
			Attributes: map[string]string{
				"author":      "alice",
				"owner":       "writer",
				"pull_number": "447",
				"repository":  "writer/cerebro",
			},
		},
	)

	if _, err := store.db.ExecContext(context.Background(), fmt.Sprintf(
		"MATCH (e:entity {urn: %s}) SET e.tenant_id = %s",
		cypherString("urn:cerebro:writer:github_repo:writer/cerebro"),
		cypherString("writer-mismatch"),
	)); err != nil {
		t.Fatalf("ExecContext() error = %v", err)
	}

	checks, err := store.IntegrityChecks(context.Background())
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	if actual := integrityCheckActual(checks, "tenant_mismatched_relations"); actual != 2 {
		t.Fatalf("tenant_mismatched_relations = %d, want 2", actual)
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

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(config.GraphStoreConfig{
		Driver:   config.GraphStoreDriverKuzu,
		KuzuPath: filepath.Join(t.TempDir(), "graph"),
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	})
	return store
}

func projectEvents(t *testing.T, store *Store, events ...*cerebrov1.EventEnvelope) {
	t.Helper()
	projector := sourceprojection.New(nil, store)
	for _, event := range events {
		if _, err := projector.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}
}

func queryGraphCount(t *testing.T, store *Store, query string) int64 {
	t.Helper()
	var count int64
	if err := store.db.QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatalf("QueryRowContext(%q) error = %v", query, err)
	}
	return count
}

func queryGraphString(t *testing.T, store *Store, query string) string {
	t.Helper()
	var value string
	if err := store.db.QueryRowContext(context.Background(), query).Scan(&value); err != nil {
		t.Fatalf("QueryRowContext(%q) error = %v", query, err)
	}
	return value
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return payload
}

func containsTraversal(traversals []Traversal, fromURN string, firstRelation string, viaURN string, secondRelation string, toURN string) bool {
	for _, traversal := range traversals {
		if traversal.FromURN == fromURN &&
			traversal.FirstRelation == firstRelation &&
			traversal.ViaURN == viaURN &&
			traversal.SecondRelation == secondRelation &&
			traversal.ToURN == toURN {
			return true
		}
	}
	return false
}

func failedIntegrityChecks(checks []IntegrityCheck) int {
	failed := 0
	for _, check := range checks {
		if !check.Passed {
			failed++
		}
	}
	return failed
}

func integrityCheckActual(checks []IntegrityCheck, name string) int64 {
	for _, check := range checks {
		if check.Name == name {
			return check.Actual
		}
	}
	return -1
}

func containsPathPattern(patterns []PathPattern, fromType string, firstRelation string, viaType string, secondRelation string, toType string, count int64) bool {
	for _, pattern := range patterns {
		if pattern.FromType == fromType &&
			pattern.FirstRelation == firstRelation &&
			pattern.ViaType == viaType &&
			pattern.SecondRelation == secondRelation &&
			pattern.ToType == toType &&
			pattern.Count == count {
			return true
		}
	}
	return false
}
