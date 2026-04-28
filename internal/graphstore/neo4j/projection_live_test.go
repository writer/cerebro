package neo4j

import (
	"context"
	"encoding/json"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

func TestLiveUpsertProjectedEntityAndLink(t *testing.T) {
	store, tenantID := newLiveTestStore(t)
	ctx := context.Background()
	user := &ports.ProjectedEntity{
		URN:        "urn:cerebro:" + tenantID + ":github_user:alice",
		TenantID:   tenantID,
		SourceID:   "github",
		EntityType: "github.user",
		Label:      "Alice",
		Attributes: map[string]string{"login": "alice"},
	}
	repo := &ports.ProjectedEntity{
		URN:        "urn:cerebro:" + tenantID + ":github_repo:writer/cerebro",
		TenantID:   tenantID,
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
		TenantID:   tenantID,
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

	label := queryGraphString(t, store,
		"MATCH (e:entity {urn: $urn}) RETURN e.label AS value",
		map[string]any{"urn": user.URN},
	)
	if label != "Alice Example" {
		t.Fatalf("projected entity label = %q, want %q", label, "Alice Example")
	}

	linkCount := queryGraphCount(t, store,
		"MATCH (:entity {tenant_id: $tenant_id})-[r:relation]->(:entity {tenant_id: $tenant_id}) RETURN count(r) AS count",
		map[string]any{"tenant_id": tenantID},
	)
	if linkCount != 1 {
		t.Fatalf("projected link count = %d, want 1", linkCount)
	}
}

func TestLiveProjectorBuildsTraversableGraph(t *testing.T) {
	store, tenantID := newLiveTestStore(t)
	projectEvents(t, store,
		&cerebrov1.EventEnvelope{
			Id:       "github-pr-447",
			TenantId: tenantID,
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
			TenantId: tenantID,
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

	pathCount := queryGraphCount(t, store,
		"MATCH (author:entity {urn: $author_urn})-[authored:relation]->(pr:entity)-[pr_repo:relation]->(repo:entity)-[repo_org:relation]->(org:entity {urn: $org_urn}) "+
			"WHERE authored.relation = 'authored' AND pr_repo.relation = 'belongs_to' AND repo_org.relation = 'belongs_to' RETURN count(pr) AS count",
		map[string]any{
			"author_urn": "urn:cerebro:" + tenantID + ":github_user:alice",
			"org_urn":    "urn:cerebro:" + tenantID + ":github_org:writer",
		},
	)
	if pathCount != 1 {
		t.Fatalf("authored pull-request path count = %d, want 1", pathCount)
	}

	traversals, err := store.SampleTraversals(context.Background(), 10)
	if err != nil {
		t.Fatalf("SampleTraversals() error = %v", err)
	}
	if !containsTraversal(traversals,
		"urn:cerebro:"+tenantID+":github_user:alice",
		"authored",
		"urn:cerebro:"+tenantID+":github_pull_request:writer/cerebro#447",
		"belongs_to",
		"urn:cerebro:"+tenantID+":github_repo:writer/cerebro",
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

	topology, err := store.Topology(context.Background())
	if err != nil {
		t.Fatalf("Topology() error = %v", err)
	}
	if topology.Isolated != 0 || topology.SourcesOnly != 1 || topology.SinksOnly != 2 || topology.Intermediates != 3 {
		t.Fatalf("Topology() = %#v, want isolated=0 sources=1 sinks=2 intermediates=3", topology)
	}
}

func TestLiveProjectorKeepsGraphIdentityLinksTenantScoped(t *testing.T) {
	store, tenantID := newLiveTestStore(t)
	otherTenantID := tenantID + "-other"
	projectEvents(t, store,
		&cerebrov1.EventEnvelope{
			Id:       "github-audit-1",
			TenantId: tenantID,
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
			TenantId: tenantID,
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
			TenantId: otherTenantID,
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
	t.Cleanup(func() {
		cleanupLiveTestData(t, store, otherTenantID)
	})

	sharedIdentifierPathCount := queryGraphCount(t, store,
		"MATCH (github_user:entity {urn: $github_urn})-[github_identifier:relation]->(identifier:entity {urn: $identifier_urn})<-[okta_identifier:relation]-(okta_user:entity {urn: $okta_urn}) "+
			"WHERE github_identifier.relation = 'has_identifier' AND okta_identifier.relation = 'has_identifier' RETURN count(identifier) AS count",
		map[string]any{
			"github_urn":     "urn:cerebro:" + tenantID + ":github_user:alice@writer.com",
			"identifier_urn": "urn:cerebro:" + tenantID + ":identifier:email:alice@writer.com",
			"okta_urn":       "urn:cerebro:" + tenantID + ":okta_user:00u1",
		},
	)
	if sharedIdentifierPathCount != 1 {
		t.Fatalf("shared identifier path count = %d, want 1", sharedIdentifierPathCount)
	}

	sharedIdentityPathCount := queryGraphCount(t, store,
		"MATCH (github_user:entity {urn: $github_urn})-[github_identity:relation]->(identity:entity {urn: $identity_urn})<-[okta_identity:relation]-(okta_user:entity {urn: $okta_urn}) "+
			"WHERE github_identity.relation = 'represents_identity' AND okta_identity.relation = 'represents_identity' RETURN count(identity) AS count",
		map[string]any{
			"github_urn":   "urn:cerebro:" + tenantID + ":github_user:alice@writer.com",
			"identity_urn": "urn:cerebro:" + tenantID + ":identity:email:alice@writer.com",
			"okta_urn":     "urn:cerebro:" + tenantID + ":okta_user:00u1",
		},
	)
	if sharedIdentityPathCount != 1 {
		t.Fatalf("shared identity path count = %d, want 1", sharedIdentityPathCount)
	}

	identifierCount := queryGraphCount(t, store,
		"MATCH (identifier:entity) WHERE identifier.entity_type = 'identifier.email' AND identifier.label = 'alice@writer.com' AND identifier.tenant_id IN [$tenant_id, $other_tenant_id] RETURN count(identifier) AS count",
		map[string]any{"tenant_id": tenantID, "other_tenant_id": otherTenantID},
	)
	if identifierCount != 2 {
		t.Fatalf("identifier count = %d, want 2", identifierCount)
	}
}

func TestLiveIntegrityChecksDetectTenantMismatch(t *testing.T) {
	store, tenantID := newLiveTestStore(t)
	projectEvents(t, store,
		&cerebrov1.EventEnvelope{
			Id:       "github-pr-447",
			TenantId: tenantID,
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

	if err := store.write(context.Background(),
		"MATCH (e:entity {urn: $repo_urn}) SET e.tenant_id = $tenant_id",
		map[string]any{
			"repo_urn":  "urn:cerebro:" + tenantID + ":github_repo:writer/cerebro",
			"tenant_id": tenantID + "-mismatch",
		},
	); err != nil {
		t.Fatalf("write mismatch error = %v", err)
	}

	checks, err := store.IntegrityChecks(context.Background())
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	if actual := integrityCheckActual(checks, "tenant_mismatched_relations"); actual != 2 {
		t.Fatalf("tenant_mismatched_relations = %d, want 2", actual)
	}
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

func queryGraphCount(t *testing.T, store *Store, query string, params map[string]any) int64 {
	t.Helper()
	records, err := store.readRecords(context.Background(), query, params)
	if err != nil {
		t.Fatalf("readRecords(%q) error = %v", query, err)
	}
	if len(records) == 0 {
		return 0
	}
	return recordInt64(records[0], "count")
}

func queryGraphString(t *testing.T, store *Store, query string, params map[string]any) string {
	t.Helper()
	records, err := store.readRecords(context.Background(), query, params)
	if err != nil {
		t.Fatalf("readRecords(%q) error = %v", query, err)
	}
	if len(records) == 0 {
		t.Fatalf("readRecords(%q) returned no rows", query)
	}
	return recordString(records[0], "value")
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
