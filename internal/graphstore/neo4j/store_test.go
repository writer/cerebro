package neo4j

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"

	"github.com/writer/cerebro/internal/ports"
)

func TestOpenRejectsIncompleteConfig(t *testing.T) {
	if _, err := Open(config.GraphStoreConfig{}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
	if _, err := Open(config.GraphStoreConfig{Neo4jURI: "bolt://127.0.0.1:7687"}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
	if _, err := Open(config.GraphStoreConfig{Neo4jURI: "bolt://127.0.0.1:7687", Neo4jUsername: "neo4j"}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
}

func TestProjectedEntityMergePreservesExistingLabelsForFallbackLabels(t *testing.T) {
	if !strings.Contains(mergeEntityAndLoadAttributesQuery, "e.label = CASE WHEN $label <> $urn THEN $label ELSE coalesce(e.label, $label) END") {
		t.Fatalf("entity merge does not preserve existing labels for fallback labels:\n%s", mergeEntityAndLoadAttributesQuery)
	}
}

func TestEndpointOwnerIDLinkCleanupQueryOrdersLimitedBatch(t *testing.T) {
	_, conditions, err := endpointOwnerIDLinkCleanupParams(ports.ProjectionLinkCleanupRequest{
		TenantID: "writer",
		SourceID: "kolide",
		Limit:    25,
	})
	if err != nil {
		t.Fatalf("endpointOwnerIDLinkCleanupParams() error = %v", err)
	}
	query := endpointOwnerIDLinkCleanupQuery(conditions, false)
	orderIndex := strings.Index(query, "ORDER BY e.urn, stale.relation, target.urn, elementId(stale)")
	limitIndex := strings.Index(query, "LIMIT $limit")
	if orderIndex == -1 {
		t.Fatalf("endpointOwnerIDLinkCleanupQuery() missing deterministic ORDER BY:\n%s", query)
	}
	if limitIndex == -1 {
		t.Fatalf("endpointOwnerIDLinkCleanupQuery() missing LIMIT:\n%s", query)
	}
	if orderIndex > limitIndex {
		t.Fatalf("endpointOwnerIDLinkCleanupQuery() orders after limiting:\n%s", query)
	}
}

func TestValidateReadOnlyCypherRejectsMutatingClauses(t *testing.T) {
	for _, query := range []string{
		"MATCH (n) SET n.seen = true RETURN n",
		"MATCH (n) DETACH DELETE n",
		"MERGE (n:Entity {urn: $urn}) RETURN n",
		"CALL db.labels()",
	} {
		if err := validateReadOnlyCypher(query); err == nil {
			t.Fatalf("validateReadOnlyCypher(%q) error = nil, want non-nil", query)
		}
	}
	for _, query := range []string{
		"MATCH (asset:Entity) RETURN asset",
		"MATCH (n) RETURN n.tenant_id AS tenant_id",
		"// SET in a comment\nMATCH (n) RETURN n",
		"/* CREATE and REMOVE inside a block comment */\nMATCH (n) RETURN n",
		"MATCH (n) RETURN 'SET password remediation by creating a ticket' AS remediation",
		`MATCH (n) RETURN "DELETE stale permissions" AS remediation`,
		"MATCH (n) RETURN `CREATE` AS quoted_identifier",
	} {
		if err := validateReadOnlyCypher(query); err != nil {
			t.Fatalf("validateReadOnlyCypher(%q) error = %v, want nil", query, err)
		}
	}
}

func TestIntegrityChecksIncludeOpenFindingPrimaryAnchorInvariant(t *testing.T) {
	checks, queries := integrityCheckDefinitions()
	if len(checks) != len(queries) {
		t.Fatalf("integrity check definitions have %d checks and %d queries", len(checks), len(queries))
	}
	for i, check := range checks {
		if check.Name != "open_findings_missing_primary_has_finding_edge" {
			continue
		}
		query := queries[i]
		for _, expected := range []string{
			"\"status\":\"open\"",
			"\"primary_resource_urn\":\"",
			"has_finding",
			"NOT EXISTS",
		} {
			if !strings.Contains(query, expected) {
				t.Fatalf("primary anchor integrity query missing %q:\n%s", expected, query)
			}
		}
		return
	}
	t.Fatalf("integrity checks missing open finding primary anchor invariant: %#v", checks)
}

func TestIntegrityChecksIncludeHostedWorkflowRunnerAssetInvariant(t *testing.T) {
	checks, queries := integrityCheckDefinitions()
	if len(checks) != len(queries) {
		t.Fatalf("integrity check definitions have %d checks and %d queries", len(checks), len(queries))
	}
	for i, check := range checks {
		if check.Name != "github_workflow_job_runners_projected_as_assets" {
			continue
		}
		query := queries[i]
		for _, expected := range []string{
			"github.runner",
			"\"action\":\"workflows.",
			"RETURN count(e)",
		} {
			if !strings.Contains(query, expected) {
				t.Fatalf("hosted workflow runner integrity query missing %q:\n%s", expected, query)
			}
		}
		return
	}
	t.Fatalf("integrity checks missing hosted workflow runner asset invariant: %#v", checks)
}

func TestIntegrityChecksIncludeSentinelOneActivityAssetInvariant(t *testing.T) {
	checks, queries := integrityCheckDefinitions()
	if len(checks) != len(queries) {
		t.Fatalf("integrity check definitions have %d checks and %d queries", len(checks), len(queries))
	}
	for i, check := range checks {
		if check.Name != "sentinelone_activity_events_projected_as_assets" {
			continue
		}
		query := queries[i]
		for _, expected := range []string{
			"sentinelone.activity",
			"RETURN count(e)",
		} {
			if !strings.Contains(query, expected) {
				t.Fatalf("sentinelone activity integrity query missing %q:\n%s", expected, query)
			}
		}
		return
	}
	t.Fatalf("integrity checks missing sentinelone activity asset invariant: %#v", checks)
}

func TestIntegrityChecksIncludeGenericEphemeralEventInvariant(t *testing.T) {
	checks, queries := integrityCheckDefinitions()
	if len(checks) != len(queries) {
		t.Fatalf("integrity check definitions have %d checks and %d queries", len(checks), len(queries))
	}
	for i, check := range checks {
		if check.Name != "ephemeral_event_entities_projected_as_inventory" {
			continue
		}
		query := queries[i]
		for _, expected := range []string{
			"projection_class",
			"ephemeral_event",
			"RETURN count(e)",
		} {
			if !strings.Contains(query, expected) {
				t.Fatalf("ephemeral event integrity query missing %q:\n%s", expected, query)
			}
		}
		return
	}
	t.Fatalf("integrity checks missing generic ephemeral event invariant: %#v", checks)
}

func TestNeo4jDockerProjectionAndQueries(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-test-%d", time.Now().UnixNano())
	password := "test-password"
	image := os.Getenv("CEREBRO_NEO4J_DOCKER_IMAGE")
	if image == "" {
		image = "neo4j:5"
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--name", name, // #nosec G204 G702 -- integration test invokes fixed docker binary with generated container arguments.
		"-e", "NEO4J_AUTH=neo4j/"+password,
		"-p", fmt.Sprintf("127.0.0.1:%d:7687", port),
		image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run neo4j: %v\n%s", err, string(output))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run() // #nosec G204 -- integration test cleanup invokes fixed docker binary with generated container name.
	})

	store := waitForStore(t, ctx, config.GraphStoreConfig{
		Neo4jURI:      fmt.Sprintf("bolt://127.0.0.1:%d", port),
		Neo4jUsername: "neo4j",
		Neo4jPassword: password,
	})
	defer func() { _ = store.CloseContext(context.Background()) }()

	user := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github_user",
		Label:      "alice",
		Attributes: map[string]string{"login": "alice"},
	}
	repo := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_code_repository:writer/cerebro",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github_code_repository",
		Label:      "writer/cerebro",
	}
	issue := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_issue:writer/cerebro#1",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github_issue",
		Label:      "writer/cerebro#1",
	}
	if err := store.UpsertProjectedEntity(ctx, user); err != nil {
		t.Fatalf("UpsertProjectedEntity(user) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, repo); err != nil {
		t.Fatalf("UpsertProjectedEntity(repo) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, issue); err != nil {
		t.Fatalf("UpsertProjectedEntity(issue) error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: "writer", SourceID: "github", FromURN: user.URN, Relation: "maintains", ToURN: repo.URN,
		Attributes: map[string]string{"role": "admin"},
	}); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}
	secondStore := waitForStore(t, ctx, config.GraphStoreConfig{
		Neo4jURI:      fmt.Sprintf("bolt://127.0.0.1:%d", port),
		Neo4jUsername: "neo4j",
		Neo4jPassword: password,
	})
	defer func() { _ = secondStore.CloseContext(context.Background()) }()
	updates := make(chan error, 2)
	updatedUser := *user
	updatedUser.Attributes = map[string]string{"team": "security"}
	go func() { updates <- store.UpsertProjectedEntity(ctx, &updatedUser) }()
	updatedUserAgain := *user
	updatedUserAgain.Attributes = map[string]string{"email": "alice@example.com"}
	go func() { updates <- secondStore.UpsertProjectedEntity(ctx, &updatedUserAgain) }()
	for range 2 {
		if err := <-updates; err != nil {
			t.Fatalf("concurrent UpsertProjectedEntity() error = %v", err)
		}
	}
	userAttributes := projectedEntityAttributes(t, ctx, store, user.URN)
	for key, want := range map[string]string{"login": "alice", "team": "security", "email": "alice@example.com"} {
		if userAttributes[key] != want {
			t.Fatalf("projected user attributes[%q] = %q, want %q in %#v", key, userAttributes[key], want, userAttributes)
		}
	}

	issueLink := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "github", FromURN: repo.URN, Relation: "tracks", ToURN: issue.URN,
	}
	linkUpdates := make(chan error, 2)
	issueLinkWithPriority := *issueLink
	issueLinkWithPriority.Attributes = map[string]string{"priority": "high"}
	go func() { linkUpdates <- store.UpsertProjectedLink(ctx, &issueLinkWithPriority) }()
	issueLinkWithState := *issueLink
	issueLinkWithState.Attributes = map[string]string{"state": "open"}
	go func() { linkUpdates <- secondStore.UpsertProjectedLink(ctx, &issueLinkWithState) }()
	for range 2 {
		if err := <-linkUpdates; err != nil {
			t.Fatalf("concurrent UpsertProjectedLink() error = %v", err)
		}
	}
	issueLinkAttributes := projectedLinkAttributes(t, ctx, store, issueLink)
	for key, want := range map[string]string{"priority": "high", "state": "open"} {
		if issueLinkAttributes[key] != want {
			t.Fatalf("projected issue link attributes[%q] = %q, want %q in %#v", key, issueLinkAttributes[key], want, issueLinkAttributes)
		}
	}

	counts, err := store.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if counts.Nodes != 3 || counts.Relations != 2 {
		t.Fatalf("Counts() = %#v, want 3 nodes and 2 relations", counts)
	}
	relationCounts, err := store.RelationCounts(ctx, []string{"maintains", "tracks", "missing"})
	if err != nil {
		t.Fatalf("RelationCounts() error = %v", err)
	}
	if relationCounts["maintains"] != 1 || relationCounts["tracks"] != 1 || relationCounts["missing"] != 0 {
		t.Fatalf("RelationCounts() = %#v, want maintains=1 tracks=1 missing=0", relationCounts)
	}
	neighborhood, err := store.GetEntityNeighborhood(ctx, user.URN, 5)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if neighborhood.Root == nil || neighborhood.Root.URN != user.URN || len(neighborhood.Neighbors) != 1 || len(neighborhood.Relations) != 1 {
		t.Fatalf("GetEntityNeighborhood() = %#v", neighborhood)
	}
	target := &ports.ProjectedEntity{URN: "urn:cerebro:writer:grc_target:target-1", TenantID: "writer", SourceID: "grc", EntityType: "grc.target", Label: "target-1"}
	source := &ports.ProjectedEntity{URN: "urn:cerebro:writer:source:grc", TenantID: "writer", SourceID: "grc", EntityType: "source", Label: "grc"}
	finding := &ports.ProjectedEntity{URN: "urn:cerebro:writer:finding:finding-1", TenantID: "writer", SourceID: "grc", EntityType: "finding", Label: "finding-1"}
	for _, entity := range []*ports.ProjectedEntity{target, source, finding} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}
	for _, link := range []*ports.ProjectedLink{
		{TenantID: "writer", SourceID: "grc", FromURN: target.URN, Relation: "belongs_to", ToURN: source.URN},
		{TenantID: "writer", SourceID: "grc", FromURN: source.URN, Relation: "has_finding", ToURN: finding.URN},
		{TenantID: "writer", SourceID: "github", FromURN: user.URN, Relation: "acted_on", ToURN: source.URN},
	} {
		if err := store.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("UpsertProjectedLink(%s -> %s) error = %v", link.FromURN, link.ToURN, err)
		}
	}
	patterns, err := store.PathPatterns(ctx, 5)
	if err != nil {
		t.Fatalf("PathPatterns() error = %v", err)
	}
	if len(patterns) != 1 || patterns[0].FirstRelation != "maintains" || patterns[0].SecondRelation != "tracks" {
		t.Fatalf("PathPatterns() = %#v, want authored two-hop pattern", patterns)
	}
	traversals, err := store.SampleTraversals(ctx, 5)
	if err != nil {
		t.Fatalf("SampleTraversals() error = %v", err)
	}
	if len(traversals) != 1 || traversals[0].FirstRelation != "maintains" || traversals[0].SecondRelation != "tracks" {
		t.Fatalf("SampleTraversals() = %#v, want authored two-hop traversal", traversals)
	}
	topology, err := store.Topology(ctx)
	if err != nil {
		t.Fatalf("Topology() error = %v", err)
	}
	if topology.SourcesOnly != 2 || topology.Intermediates != 2 || topology.SinksOnly != 2 {
		t.Fatalf("Topology() = %#v, want two source-only, two intermediate, and two sink-only nodes", topology)
	}
	checks, err := store.IntegrityChecks(ctx)
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	for _, check := range checks {
		if !check.Passed {
			t.Fatalf("IntegrityChecks() contains failure: %#v", checks)
		}
	}

	checkpoint := graphstore.IngestCheckpoint{ID: "checkpoint-1", SourceID: "github", TenantID: "writer", Completed: true, PagesRead: 2}
	if err := store.PutIngestCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("PutIngestCheckpoint() error = %v", err)
	}
	gotCheckpoint, ok, err := store.GetIngestCheckpoint(ctx, checkpoint.ID)
	if err != nil || !ok || gotCheckpoint.ID != checkpoint.ID || !gotCheckpoint.Completed {
		t.Fatalf("GetIngestCheckpoint() = %#v, %v, %v", gotCheckpoint, ok, err)
	}
	run := graphstore.IngestRun{ID: "run-1", RuntimeID: "runtime", Status: graphstore.IngestRunStatusCompleted, StartedAt: "2026-05-01T00:00:00Z"}
	if err := store.PutIngestRun(ctx, run); err != nil {
		t.Fatalf("PutIngestRun() error = %v", err)
	}
	runs, err := store.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeID: "runtime", Status: graphstore.IngestRunStatusCompleted, Limit: 10})
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("ListIngestRuns() = %#v, %v", runs, err)
	}
	if err := store.DeleteProjectedLink(ctx, issueLink); err != nil {
		t.Fatalf("DeleteProjectedLink() error = %v", err)
	}
	counts, err = store.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts(after delete) error = %v", err)
	}
	if counts.Relations != 1 {
		t.Fatalf("Counts(after delete) = %#v, want 1 relation", counts)
	}

	endpointURN := "urn:cerebro:writer:kolide_device:device-1"
	identityURN := "urn:cerebro:writer:identity:login:user-1"
	identifierURN := "urn:cerebro:writer:identifier:login:user-1"
	emailIdentityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	unmigratedIdentityURN := "urn:cerebro:writer:identity:login:user-2"
	replacementURN := "urn:cerebro:writer:endpoint_identifier:kolide_user_id:user-1"
	for _, entity := range []*ports.ProjectedEntity{
		{URN: endpointURN, TenantID: "writer", SourceID: "kolide", EntityType: "kolide.device", Label: "device-1"},
		{URN: identityURN, TenantID: "writer", SourceID: "kolide", EntityType: "identity.login", Label: "user-1"},
		{URN: identifierURN, TenantID: "writer", SourceID: "kolide", EntityType: "identifier.login", Label: "user-1"},
		{URN: emailIdentityURN, TenantID: "writer", SourceID: "kolide", EntityType: "identity.email", Label: "alice@example.com"},
		{URN: unmigratedIdentityURN, TenantID: "writer", SourceID: "kolide", EntityType: "identity.login", Label: "user-2"},
		{URN: replacementURN, TenantID: "writer", SourceID: "kolide", EntityType: "endpoint.identifier", Label: "user-1"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}
	staleLinks := []*ports.ProjectedLink{
		{TenantID: "writer", SourceID: "kolide", FromURN: endpointURN, Relation: "owned_by", ToURN: identityURN},
		{TenantID: "writer", SourceID: "kolide", FromURN: endpointURN, Relation: "represents_identity", ToURN: identityURN},
		{TenantID: "writer", SourceID: "kolide", FromURN: endpointURN, Relation: "has_identifier", ToURN: identifierURN},
	}
	preservedLinks := []*ports.ProjectedLink{
		{TenantID: "writer", SourceID: "kolide", FromURN: endpointURN, Relation: "owned_by", ToURN: emailIdentityURN},
		{TenantID: "writer", SourceID: "kolide", FromURN: endpointURN, Relation: "owned_by", ToURN: unmigratedIdentityURN},
		{TenantID: "writer", SourceID: "kolide", FromURN: endpointURN, Relation: "has_identifier", ToURN: replacementURN},
	}
	for _, link := range append(staleLinks, preservedLinks...) {
		if err := store.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("UpsertProjectedLink(%s %s %s) error = %v", link.FromURN, link.Relation, link.ToURN, err)
		}
	}
	cleanupRequest := ports.ProjectionLinkCleanupRequest{TenantID: "writer", SourceID: "kolide", DryRun: true}
	cleanupResult, err := store.CleanupEndpointOwnerIDLinks(ctx, cleanupRequest)
	if err != nil {
		t.Fatalf("CleanupEndpointOwnerIDLinks(dry-run) error = %v", err)
	}
	wantStaleLinks := uint32(len(staleLinks)) // #nosec G115 -- test fixture slice is statically bounded.
	if cleanupResult.LinksMatched != wantStaleLinks || cleanupResult.LinksDeleted != 0 {
		t.Fatalf("dry-run CleanupEndpointOwnerIDLinks() = %#v, want %d matches and no deletes", cleanupResult, len(staleLinks))
	}
	cleanupRequest.DryRun = false
	cleanupResult, err = store.CleanupEndpointOwnerIDLinks(ctx, cleanupRequest)
	if err != nil {
		t.Fatalf("CleanupEndpointOwnerIDLinks() error = %v", err)
	}
	if cleanupResult.LinksMatched != wantStaleLinks || cleanupResult.LinksDeleted != wantStaleLinks {
		t.Fatalf("CleanupEndpointOwnerIDLinks() = %#v, want %d deletes", cleanupResult, len(staleLinks))
	}
	for _, link := range staleLinks {
		if neo4jProjectedLinkExists(t, ctx, store, link) {
			t.Fatalf("stale link still exists: %s %s %s", link.FromURN, link.Relation, link.ToURN)
		}
	}
	for _, link := range preservedLinks {
		if !neo4jProjectedLinkExists(t, ctx, store, link) {
			t.Fatalf("preserved link missing: %s %s %s", link.FromURN, link.Relation, link.ToURN)
		}
	}
}

func projectedEntityAttributes(t *testing.T, ctx context.Context, store *Store, urn string) map[string]string {
	t.Helper()
	value, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		return queryOneValue(ctx, tx, "MATCH (e:Entity {urn: $urn}) RETURN e.attributes_json", map[string]any{"urn": urn})
	})
	if err != nil {
		t.Fatalf("query projected entity attributes: %v", err)
	}
	attributes, err := graphAttributesFromJSON(stringValue(value))
	if err != nil {
		t.Fatalf("decode projected entity attributes: %v", err)
	}
	return attributes
}

func projectedLinkAttributes(t *testing.T, ctx context.Context, store *Store, link *ports.ProjectedLink) map[string]string {
	t.Helper()
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (:Entity {urn: $from_urn})-[r:RELATION {relation: $relation}]->(:Entity {urn: $to_urn})
RETURN count(r), collect(r.attributes_json)`, map[string]any{
			"from_urn": link.FromURN,
			"relation": link.Relation,
			"to_urn":   link.ToURN,
		})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		return result.Record().Values, result.Err()
	})
	if err != nil {
		t.Fatalf("query projected link attributes: %v", err)
	}
	recordValues, ok := values.([]any)
	if !ok || len(recordValues) != 2 || toInt64(recordValues[0]) != 1 {
		t.Fatalf("projected link query returned %#v, want one relation", values)
	}
	rawValues, ok := recordValues[1].([]any)
	if !ok || len(rawValues) != 1 {
		t.Fatalf("projected link attributes returned %#v", recordValues[1])
	}
	attributes, err := graphAttributesFromJSON(stringValue(rawValues[0]))
	if err != nil {
		t.Fatalf("decode projected link attributes: %v", err)
	}
	return attributes
}

func neo4jProjectedLinkExists(t *testing.T, ctx context.Context, store *Store, link *ports.ProjectedLink) bool {
	t.Helper()
	value, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		return queryOneValue(ctx, tx, `MATCH (:Entity {urn: $from_urn})-[r:RELATION {relation: $relation}]->(:Entity {urn: $to_urn}) RETURN count(r)`, map[string]any{
			"from_urn": link.FromURN,
			"relation": link.Relation,
			"to_urn":   link.ToURN,
		})
	})
	if err != nil {
		t.Fatalf("query projected link: %v", err)
	}
	return toInt64(value) > 0
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

// Some sources (notably GitHub audit) page newest-first and replay each batch
// sequentially, so an older batch can be merged after a newer one. Last-write-wins
// would let that older batch overwrite the newer `at` timestamp on a relation,
// and the deprovisioned-Okta-active-in-GitHub rule's recency check would then read
// an actively-used edge as stale. mergeGraphAttributes must therefore keep the
// chronological max for `at`.
func TestMergeGraphAttributesKeepsLatestAtAcrossOutOfOrderUpserts(t *testing.T) {
	older := time.Date(2025, time.March, 1, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2025, time.March, 5, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)

	cases := []struct {
		name       string
		existing   map[string]string
		incoming   map[string]string
		wantAt     string
		wantAction string
	}{
		{
			name:       "older incoming after newer existing keeps newer observation",
			existing:   map[string]string{"at": newer, "action": "git.clone"},
			incoming:   map[string]string{"at": older, "action": "workflows.completed_workflow_run"},
			wantAt:     newer,
			wantAction: "git.clone",
		},
		{
			name:       "newer incoming after older existing wins",
			existing:   map[string]string{"at": older, "action": "git.clone"},
			incoming:   map[string]string{"at": newer, "action": "git.push"},
			wantAt:     newer,
			wantAction: "git.push",
		},
		{
			name:       "missing existing at takes incoming",
			existing:   map[string]string{"action": "git.clone"},
			incoming:   map[string]string{"at": newer, "action": "git.push"},
			wantAt:     newer,
			wantAction: "git.push",
		},
		{
			name:       "missing incoming at preserves existing observation",
			existing:   map[string]string{"at": newer, "action": "git.clone"},
			incoming:   map[string]string{"action": "git.push"},
			wantAt:     newer,
			wantAction: "git.clone",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged := mergeGraphAttributes(tc.existing, tc.incoming)
			if got := merged["at"]; got != tc.wantAt {
				t.Fatalf("merged at = %q, want %q (rule recency check depends on chronological max)", got, tc.wantAt)
			}
			if got := merged["action"]; got != tc.wantAction {
				t.Fatalf("merged action = %q, want %q (action must stay coupled to the winning at timestamp)", got, tc.wantAction)
			}
		})
	}
}

func TestMergeGraphAttributesKeepsObservationMetadataCoupledToLatestAt(t *testing.T) {
	older := time.Date(2025, time.March, 1, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2025, time.March, 5, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	merged := mergeGraphAttributes(
		map[string]string{
			"at":                       newer,
			"action":                   "git.clone",
			"event_type":               "user.lifecycle.update",
			"event_id":                 "newer-event",
			"outcome_result":           "SUCCESS",
			"programmatic_access_type": "Fine-grained personal access token",
			"source_runtime_id":        "writer-github-audit",
			"transaction_id":           "newer-txn",
		},
		map[string]string{
			"at":                       older,
			"action":                   "workflows.completed_workflow_run",
			"event_type":               "user.session.start",
			"event_id":                 "older-event",
			"outcome_result":           "FAILURE",
			"programmatic_access_type": "GitHub App server-to-server token",
			"source_runtime_id":        "writer-github-audit-writerinternal",
			"transaction_id":           "older-txn",
		},
	)
	for key, want := range map[string]string{
		"at":                       newer,
		"action":                   "git.clone",
		"event_type":               "user.lifecycle.update",
		"event_id":                 "newer-event",
		"outcome_result":           "SUCCESS",
		"programmatic_access_type": "Fine-grained personal access token",
		"source_runtime_id":        "writer-github-audit",
		"transaction_id":           "newer-txn",
	} {
		if got := merged[key]; got != want {
			t.Fatalf("merged[%s] = %q, want %q", key, got, want)
		}
	}
}

func TestMergeGraphAttributesClearsOlderObservationMetadataMissingFromNewerAt(t *testing.T) {
	older := time.Date(2025, time.March, 1, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2025, time.March, 5, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	merged := mergeGraphAttributes(
		map[string]string{
			"at":             older,
			"event_id":       "older-event",
			"outcome_reason": "older reason",
			"transaction_id": "older-txn",
			"target":         "repo",
		},
		map[string]string{
			"at":       newer,
			"event_id": "newer-event",
		},
	)
	for key, want := range map[string]string{
		"at":       newer,
		"event_id": "newer-event",
		"target":   "repo",
	} {
		if got := merged[key]; got != want {
			t.Fatalf("merged[%s] = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"outcome_reason", "transaction_id"} {
		if got, exists := merged[key]; exists {
			t.Fatalf("merged[%s] = %q, want missing because newer observation omitted it", key, got)
		}
	}
}

// Non-observation keys must keep the default last-write-wins semantics so the
// special-case for event metadata does not silently change merge behavior elsewhere.
func TestMergeGraphAttributesKeepsLastWriteWinsForOtherKeys(t *testing.T) {
	merged := mergeGraphAttributes(
		map[string]string{"action": "git.clone", "actor": "alice"},
		map[string]string{"action": "git.push"},
	)
	if got, want := merged["action"], "git.push"; got != want {
		t.Fatalf("merged action = %q, want %q (non-`at` keys must remain last-write-wins)", got, want)
	}
	if got, want := merged["actor"], "alice"; got != want {
		t.Fatalf("merged actor = %q, want %q (existing keys not in incoming must survive)", got, want)
	}
}

// If either side carries an unparseable `at` (e.g. a future projector bug or a
// downgrade from a different format), fall back to last-write-wins so we never
// crash or silently freeze the timestamp at a malformed value.
func TestMergeGraphAttributesFallsBackToLastWriteWinsWhenAtUnparseable(t *testing.T) {
	merged := mergeGraphAttributes(
		map[string]string{"at": "yesterday"},
		map[string]string{"at": "2025-03-05T09:00:00Z"},
	)
	if got, want := merged["at"], "2025-03-05T09:00:00Z"; got != want {
		t.Fatalf("merged at = %q, want %q (unparseable existing falls back to incoming)", got, want)
	}
	merged = mergeGraphAttributes(
		map[string]string{"at": "2025-03-05T09:00:00Z"},
		map[string]string{"at": "tomorrow"},
	)
	if got, want := merged["at"], "tomorrow"; got != want {
		t.Fatalf("merged at = %q, want %q (unparseable incoming wins to avoid freezing)", got, want)
	}
}

func waitForStore(t *testing.T, ctx context.Context, cfg config.GraphStoreConfig) *Store {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		store, err := Open(cfg)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if err := store.Ping(ctx); err == nil {
			return store
		} else {
			lastErr = err
		}
		_ = store.CloseContext(ctx)
		select {
		case <-ctx.Done():
			t.Fatalf("context done waiting for neo4j: %v", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr == nil || errors.Is(lastErr, context.DeadlineExceeded) || strings.TrimSpace(lastErr.Error()) == "" {
		t.Fatal("neo4j did not become ready")
	}
	t.Fatalf("neo4j did not become ready: %v", lastErr)
	return nil
}
