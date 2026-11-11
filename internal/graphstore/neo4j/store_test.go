package neo4j

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/projectionmeta"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"

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

func TestScanIngestRunRecordIncludesCheckpointTerminalState(t *testing.T) {
	record := &neo4jdriver.Record{Values: []any{
		"run-1", "runtime-1", "github", "writer", "checkpoint-1", "page-2", false,
		graphstore.IngestRunStatusCompleted, "api", int64(1), int64(10), int64(8), int64(4),
		int64(2), int64(1), int64(10), int64(5), "2026-07-14T10:00:00Z", "2026-07-14T10:01:00Z", "",
	}}
	run, err := scanIngestRunRecord(record)
	if err != nil {
		t.Fatalf("scanIngestRunRecord() error = %v", err)
	}
	if run.CheckpointID != "checkpoint-1" || run.CheckpointCursor != "page-2" || run.CheckpointComplete || !run.CheckpointCompleteKnown {
		t.Fatalf("scanIngestRunRecord() checkpoint = %#v", run)
	}
}

func TestScanIngestRunRecordPreservesMissingLegacyCheckpointTerminalState(t *testing.T) {
	record := &neo4jdriver.Record{Values: []any{
		"run-legacy", "runtime-1", "github", "writer", "", "", nil,
		graphstore.IngestRunStatusCompleted, "api", int64(1), int64(10), int64(8), int64(4),
		int64(2), int64(1), int64(10), int64(5), "2026-07-14T10:00:00Z", "2026-07-14T10:01:00Z", "",
	}}
	run, err := scanIngestRunRecord(record)
	if err != nil {
		t.Fatalf("scanIngestRunRecord() error = %v", err)
	}
	if run.CheckpointComplete || run.CheckpointCompleteKnown {
		t.Fatalf("scanIngestRunRecord() checkpoint = %#v, want legacy terminal state absent", run)
	}
}

func TestIngestRunListQueryBoundsLatestRunsByRequestedRuntime(t *testing.T) {
	query, params, err := ingestRunListQuery(graphstore.IngestRunFilter{
		RuntimeIDs:      []string{"runtime-b", "runtime-a", "runtime-b"},
		Status:          graphstore.IngestRunStatusCompleted,
		LatestByRuntime: true,
	}, 2)
	if err != nil {
		t.Fatalf("ingestRunListQuery() error = %v", err)
	}
	for _, want := range []string{
		"UNWIND $runtime_ids AS runtime_id",
		"MATCH (r:IngestRun {runtime_id: runtime_id})",
		"WHERE r.status = $status",
		"ORDER BY r.started_at DESC, r.id DESC",
		"LIMIT 1",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("ingestRunListQuery() missing %q:\n%s", want, query)
		}
	}
	for _, rejected := range []string{"collect(r)[0]", "r.runtime_id IN $runtime_ids"} {
		if strings.Contains(query, rejected) {
			t.Fatalf("ingestRunListQuery() contains unbounded shape %q:\n%s", rejected, query)
		}
	}
	gotRuntimeIDs, ok := params["runtime_ids"].([]string)
	if !ok || strings.Join(gotRuntimeIDs, ",") != "runtime-b,runtime-a" {
		t.Fatalf("runtime_ids = %#v, want normalized stable input order", params["runtime_ids"])
	}
	if params["status"] != graphstore.IngestRunStatusCompleted {
		t.Fatalf("status = %#v, want %q", params["status"], graphstore.IngestRunStatusCompleted)
	}
}

func TestIngestRunListQueryDoesNotMutateRuntimeIDBackingArray(t *testing.T) {
	backing := []string{"runtime-a", "runtime-b", "next-batch-runtime"}
	runtimeIDs := backing[:2]

	_, params, err := ingestRunListQuery(graphstore.IngestRunFilter{
		RuntimeIDs:      runtimeIDs,
		LatestByRuntime: true,
	}, 2)
	if err != nil {
		t.Fatalf("ingestRunListQuery() error = %v", err)
	}
	if backing[2] != "next-batch-runtime" {
		t.Fatalf("ingestRunListQuery() mutated caller backing array: %#v", backing)
	}
	gotRuntimeIDs, ok := params["runtime_ids"].([]string)
	if !ok || strings.Join(gotRuntimeIDs, ",") != "runtime-a,runtime-b" {
		t.Fatalf("runtime_ids = %#v, want caller values only", params["runtime_ids"])
	}
}

func TestNeo4jSchemaIndexesIngestRunLookupShape(t *testing.T) {
	statements := strings.Join(neo4jSchemaStatements(), "\n")
	for _, want := range []string{
		"cerebro_ingest_run_runtime IF NOT EXISTS FOR (r:IngestRun) ON (r.runtime_id)",
		"cerebro_ingest_run_runtime_started IF NOT EXISTS FOR (r:IngestRun) ON (r.runtime_id, r.started_at)",
	} {
		if !strings.Contains(statements, want) {
			t.Fatalf("neo4jSchemaStatements() missing %q:\n%s", want, statements)
		}
	}
}

func TestNeo4jSchemaIndexesApplicationWorkspaceCatalogShape(t *testing.T) {
	statements := strings.Join(neo4jSchemaStatements(), "\n")
	want := "cerebro_entity_tenant_application_workspace_type IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.application_workspace_id, e.entity_type)"
	if !strings.Contains(statements, want) {
		t.Fatalf("neo4jSchemaStatements() missing %q:\n%s", want, statements)
	}
}

func TestUpsertProjectedEntityRejectsCrossTenantCerebroURNBeforeConnection(t *testing.T) {
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
	requireProjectedTenantScopeError(t, err, "projected entity urn", "urn:cerebro:victim:github_user:alice")
}

func TestUpsertProjectedLinkRejectsCrossTenantCerebroURNBeforeConnection(t *testing.T) {
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
	requireProjectedTenantScopeError(t, err, "projected link to urn", "urn:cerebro:victim:github_code_repository:writer/cerebro")
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
	orderIndex := strings.Index(query, "ORDER BY e.urn, relation, target.urn, elementId(stale)")
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

func TestMigrateProjectedLinkAssertionsValidatesScopeBeforeConnection(t *testing.T) {
	store := &Store{}
	for _, request := range []ports.ProjectionAssertionMigrationRequest{
		{Relations: []string{"can_reach"}},
		{TenantID: "writer"},
	} {
		_, err := store.MigrateProjectedLinkAssertions(context.Background(), request)
		if !errors.Is(err, errProjectionAssertionMigrationScopeRequired) {
			t.Fatalf("MigrateProjectedLinkAssertions(%#v) error = %v, want scope validation", request, err)
		}
	}
}

func TestValidateReadOnlyCypherRejectsMutatingClauses(t *testing.T) {
	for _, query := range []string{
		"MATCH (n) SET n.seen = true RETURN n",
		"MATCH (n) DETACH DELETE n",
		"MERGE (n:Entity {urn: $urn}) RETURN n",
		"CALL db.labels()",
		"CALL apoc.periodic.iterate('MATCH (n)', 'RETURN n', {})",
		"CALL apoc.path.expandConfig(n, {}) YIELD path RETURN path",
		"CALL apoc.algo.dijkstra(n, m, 'RELATION', 'weight') YIELD path RETURN path",
		"CALL apoc.convert.toTree([n]) YIELD value RETURN value",
		"CALL `apoc.coll.elements`([], 1, 0) YIELD value RETURN value",
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
		"MATCH (n) CALL apoc.coll.elements(n.items, 25, 0) YIELD value RETURN value",
		"MATCH (n) CALL/* read transform */apoc.paths.toJsonTree([n]) YIELD value RETURN value",
	} {
		if err := validateReadOnlyCypher(query); err != nil {
			t.Fatalf("validateReadOnlyCypher(%q) error = %v, want nil", query, err)
		}
	}
}

func TestValidateReadOnlyCypherAllowsBoundedTenantScopedAPOCTraversal(t *testing.T) {
	for _, query := range []string{
		"MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.path.expandConfig(start, {relationshipFilter: 'RELATION>', labelFilter: '+Entity', minLevel: 1, maxLevel: 6, bfs: true, uniqueness: 'NODE_GLOBAL', filterStartNode: true, limit: 25}) YIELD path WHERE all(node IN nodes(path) WHERE node.tenant_id = $tenant_id) AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id) RETURN path LIMIT 25",
		"MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.path.subgraphNodes(start, {relationshipFilter: 'RELATION', labelFilter: '+Entity', minLevel: 0, maxLevel: 4, bfs: true, uniqueness: 'NODE_GLOBAL', filterStartNode: true, limit: 50}) YIELD node WHERE node.tenant_id = $tenant_id WITH node RETURN node LIMIT 50",
		"MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.neighbors.athop(start, 'RELATION>', 3) YIELD node WHERE node.tenant_id = $tenant_id RETURN node LIMIT 25",
		"MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.neighbors.byhop(start, '<RELATION', 2) YIELD nodes WHERE all(node IN nodes WHERE node.tenant_id = $tenant_id) RETURN nodes LIMIT 25",
	} {
		if err := validateReadOnlyCypher(query); err != nil {
			t.Fatalf("validateReadOnlyCypher(%q) error = %v, want nil", query, err)
		}
	}
}

func TestValidateReadOnlyCypherRejectsUnsafeAPOCTraversalVariants(t *testing.T) {
	base := "MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.path.expandConfig(start, {%s}) YIELD path WHERE %s RETURN path LIMIT 25"
	guard := "all(node IN nodes(path) WHERE node.tenant_id = $tenant_id) AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id)"
	validConfig := "relationshipFilter: 'RELATION>', labelFilter: '+Entity', minLevel: 1, maxLevel: 6, bfs: true, uniqueness: 'NODE_GLOBAL', filterStartNode: true, limit: 25"
	for _, query := range []string{
		fmt.Sprintf(base, strings.Replace(validConfig, "maxLevel: 6", "maxLevel: 7", 1), guard),
		fmt.Sprintf(base, strings.Replace(validConfig, "maxLevel: 6", "maxLevel: $hops", 1), guard),
		fmt.Sprintf(base, strings.Replace(validConfig, "limit: 25", "limit: $row_limit", 1), guard),
		fmt.Sprintf(base, strings.Replace(validConfig, "RELATION>", "*", 1), guard),
		fmt.Sprintf(base, strings.Replace(validConfig, "+Entity", "+Finding", 1), guard),
		fmt.Sprintf(base, strings.Replace(validConfig, "NODE_GLOBAL", "RELATIONSHIP_GLOBAL", 1), guard),
		fmt.Sprintf(base, validConfig, "all(node IN nodes(path) WHERE node.tenant_id = $tenant_id)"),
		fmt.Sprintf(base, validConfig, guard+" OR true"),
		"MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.neighbors.athop.count(start, 'RELATION', 2) YIELD value RETURN value LIMIT 25",
		"MATCH (start:Entity {tenant_id: $tenant_id}) CALL apoc.neighbors.tohop(start, 'RELATION', 7) YIELD node WHERE node.tenant_id = $tenant_id RETURN node LIMIT 25",
	} {
		if err := validateReadOnlyCypher(query); err == nil {
			t.Fatalf("validateReadOnlyCypher(%q) error = nil, want non-nil", query)
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

func TestIntegrityChecksIncludeMissingTypedPropertiesInvariant(t *testing.T) {
	checks, queries := integrityCheckDefinitions()
	if len(checks) != len(queries) {
		t.Fatalf("integrity check definitions have %d checks and %d queries", len(checks), len(queries))
	}
	for i, check := range checks {
		if check.Name != "entities_missing_typed_properties" {
			continue
		}
		query := queries[i]
		for _, expected := range []string{
			projectionmeta.PropertyInternetExposed + " IS NULL",
			projectionmeta.PropertyPrivilegedIdentity + " IS NULL",
			projectionmeta.PropertyMFADisabled + " IS NULL",
		} {
			if !strings.Contains(query, expected) {
				t.Fatalf("missing typed properties integrity query missing %q:\n%s", expected, query)
			}
		}
		return
	}
	t.Fatalf("integrity checks missing typed property backfill invariant: %#v", checks)
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
	run := graphstore.IngestRun{ID: "run-1", RuntimeID: "runtime", CheckpointID: "checkpoint-1", CheckpointComplete: true, Status: graphstore.IngestRunStatusCompleted, StartedAt: "2026-05-01T00:00:00Z"}
	if err := store.PutIngestRun(ctx, run); err != nil {
		t.Fatalf("PutIngestRun() error = %v", err)
	}
	runs, err := store.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeID: "runtime", Status: graphstore.IngestRunStatusCompleted, Limit: 10})
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID || runs[0].CheckpointID != run.CheckpointID || !runs[0].CheckpointComplete || runs[0].CheckpointCursor != "" {
		t.Fatalf("ListIngestRuns() = %#v, %v", runs, err)
	}
	if err := store.DeleteProjectedLink(ctx, issueLink); err != nil {
		t.Fatalf("DeleteProjectedLink() error = %v", err)
	}
	counts, err = store.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts(after delete) error = %v", err)
	}
	if counts.Relations != 4 {
		t.Fatalf("Counts(after delete) = %#v, want 4 relations", counts)
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

	runAuthoredPolicyGraphFixtures(t, ctx, store)
}

func TestNeo4jDockerBackfillEntityTypedProperties(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-backfill-%d", time.Now().UnixNano())
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

	seeds := []struct {
		urn        string
		entityType string
		attributes map[string]string
		want       projectionmeta.EntityTypedProperties
	}{
		{"urn:cerebro:writer:aws_network_interface:eni", "aws.network.interface", map[string]string{"internet_exposed": "true"}, projectionmeta.EntityTypedProperties{InternetExposed: true}},
		{"urn:cerebro:writer:aws_user:admin", "aws.user", map[string]string{"is_admin": "true"}, projectionmeta.EntityTypedProperties{PrivilegedIdentity: true}},
		{"urn:cerebro:writer:okta_user:nomfa", "okta.user", map[string]string{"mfa_enrolled": "false"}, projectionmeta.EntityTypedProperties{MFADisabled: true}},
		{"urn:cerebro:writer:aws_s3_bucket:plain", "aws.s3.bucket", map[string]string{"team": "security"}, projectionmeta.EntityTypedProperties{}},
	}
	for _, seed := range seeds {
		if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
			URN:        seed.urn,
			TenantID:   "writer",
			SourceID:   "aws",
			EntityType: seed.entityType,
			Label:      seed.urn,
			Attributes: seed.attributes,
		}); err != nil {
			t.Fatalf("UpsertProjectedEntity(%q) error = %v", seed.urn, err)
		}
	}

	// Simulate pre-promotion nodes by clearing the typed properties the write path set.
	if _, err := store.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, fmt.Sprintf("MATCH (e:Entity) REMOVE e.%s, e.%s, e.%s",
			projectionmeta.PropertyInternetExposed,
			projectionmeta.PropertyPrivilegedIdentity,
			projectionmeta.PropertyMFADisabled), nil)
	}); err != nil {
		t.Fatalf("clear typed properties: %v", err)
	}

	wantSeeds := uint32(len(seeds)) // #nosec G115 -- test fixture slice is statically bounded.
	dryRun, err := store.BackfillEntityTypedProperties(ctx, graphstore.BackfillEntityTypedPropertiesRequest{DryRun: true})
	if err != nil {
		t.Fatalf("BackfillEntityTypedProperties(dry-run) error = %v", err)
	}
	if dryRun.EntitiesMatched != wantSeeds || dryRun.EntitiesUpdated != 0 || !dryRun.DryRun {
		t.Fatalf("dry-run result = %#v, want %d matched and no updates", dryRun, wantSeeds)
	}

	applied, err := store.BackfillEntityTypedProperties(ctx, graphstore.BackfillEntityTypedPropertiesRequest{BatchSize: 2, DryRun: false})
	if err != nil {
		t.Fatalf("BackfillEntityTypedProperties(apply) error = %v", err)
	}
	if applied.EntitiesUpdated != wantSeeds || applied.Batches < 2 || applied.DryRun {
		t.Fatalf("apply result = %#v, want %d updated across at least two batches", applied, wantSeeds)
	}

	for _, seed := range seeds {
		got := projectedEntityTypedProperties(t, ctx, store, seed.urn)
		if got != seed.want {
			t.Fatalf("typed properties for %q = %#v, want %#v", seed.urn, got, seed.want)
		}
	}

	after, err := store.BackfillEntityTypedProperties(ctx, graphstore.BackfillEntityTypedPropertiesRequest{DryRun: true})
	if err != nil {
		t.Fatalf("BackfillEntityTypedProperties(dry-run after) error = %v", err)
	}
	if after.EntitiesMatched != 0 {
		t.Fatalf("dry-run after backfill matched %d entities, want 0", after.EntitiesMatched)
	}

}

func runAuthoredPolicyGraphFixtures(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	graphTestStore := policyauthor.NewCompatibilityGraphTestStore(store, store)
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	paths, err := findingdsl.DiscoverPolicyTestSuites(repoRoot)
	if err != nil {
		t.Fatalf("discover authored policy graph fixtures: %v", err)
	}
	for _, path := range paths {
		suite, issues, err := findingdsl.LoadPolicyRuleTestSuite(repoRoot, filepath.Join(repoRoot, filepath.FromSlash(path)))
		if err != nil || len(issues) != 0 {
			continue // The normal findingdsl lane reports malformed suites.
		}
		hasGraphFixture := false
		for _, testCase := range suite.Cases {
			hasGraphFixture = hasGraphFixture || testCase.GraphFixture != nil
		}
		if !hasGraphFixture {
			continue
		}
		if issues := findingdsl.RunPolicyRuleTestSuiteWithGraphStore(ctx, repoRoot, filepath.Join(repoRoot, filepath.FromSlash(path)), graphTestStore); len(issues) != 0 {
			t.Fatalf("authored graph policy suite %s failed: %#v", path, issues)
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

func projectedEntityTypedProperties(t *testing.T, ctx context.Context, store *Store, urn string) projectionmeta.EntityTypedProperties {
	t.Helper()
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, fmt.Sprintf("MATCH (e:Entity {urn: $urn}) RETURN e.%s, e.%s, e.%s",
			projectionmeta.PropertyInternetExposed,
			projectionmeta.PropertyPrivilegedIdentity,
			projectionmeta.PropertyMFADisabled), map[string]any{"urn": urn})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		return result.Record().Values, result.Err()
	})
	if err != nil {
		t.Fatalf("query projected entity typed properties: %v", err)
	}
	row, ok := values.([]any)
	if !ok || len(row) != 3 {
		t.Fatalf("typed property query returned %#v, want three columns", values)
	}
	boolValue := func(v any) bool {
		b, _ := v.(bool)
		return b
	}
	return projectionmeta.EntityTypedProperties{
		InternetExposed:    boolValue(row[0]),
		PrivilegedIdentity: boolValue(row[1]),
		MFADisabled:        boolValue(row[2]),
	}
}

type projectedEntityOwner struct {
	sourceID  string
	runtimeID string
	label     string
}

// projectedEntityTypedOwner reads the node's typed source_id/runtime_id and
// label, which must stay with the observation that owns attributes_json.
func projectedEntityTypedOwner(t *testing.T, ctx context.Context, store *Store, urn string) projectedEntityOwner {
	t.Helper()
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, "MATCH (e:Entity {urn: $urn}) RETURN coalesce(e.source_id, ''), coalesce(e.runtime_id, ''), coalesce(e.label, '')", map[string]any{"urn": urn})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		return result.Record().Values, result.Err()
	})
	if err != nil {
		t.Fatalf("query projected entity typed owner: %v", err)
	}
	row, ok := values.([]any)
	if !ok || len(row) != 3 {
		t.Fatalf("typed owner query returned %#v, want three columns", values)
	}
	return projectedEntityOwner{sourceID: stringValue(row[0]), runtimeID: stringValue(row[1]), label: stringValue(row[2])}
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

type projectedLinkProvenance struct {
	sourceID         string
	runtimeID        string
	reconciliationID string
}

// projectedLinkTypedProvenance reads the logical RELATION edge's typed
// source_id/runtime_id/projection_reconciliation_id, which must stay coherent
// with attributes_json's coupled source_runtime_id for the same owning writer.
func projectedLinkTypedProvenance(t *testing.T, ctx context.Context, store *Store, link *ports.ProjectedLink) projectedLinkProvenance {
	t.Helper()
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (:Entity {urn: $from_urn})-[r:RELATION {relation: $relation}]->(:Entity {urn: $to_urn})
RETURN count(r), coalesce(r.source_id, ''), coalesce(r.runtime_id, ''), coalesce(r.projection_reconciliation_id, '')`, map[string]any{
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
		t.Fatalf("query projected link typed provenance: %v", err)
	}
	row, ok := values.([]any)
	if !ok || len(row) != 4 || toInt64(row[0]) != 1 {
		t.Fatalf("projected link typed provenance query returned %#v, want one relation", values)
	}
	return projectedLinkProvenance{
		sourceID:         stringValue(row[1]),
		runtimeID:        stringValue(row[2]),
		reconciliationID: stringValue(row[3]),
	}
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

// A projected logical RELATION edge must mirror one owning assertion's typed
// provenance (source_id/runtime_id/projection_reconciliation_id), the same
// way attributes_json's coupled keys already follow observation recency.
// projectedLinkIncomingBecomesLogicalOwner is the decision point both the
// single and batch upsert paths use to keep the typed owner coherent with
// that recency rule.
func TestProjectedLinkIncomingBecomesLogicalOwner(t *testing.T) {
	older := time.Date(2025, time.March, 1, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2025, time.March, 5, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)

	cases := []struct {
		name     string
		existing map[string]string
		incoming map[string]string
		want     bool
	}{
		{
			name:     "first write on an edge with no prior observation becomes owner",
			existing: map[string]string{},
			incoming: map[string]string{"at": newer},
			want:     true,
		},
		{
			name:     "newer incoming observation becomes owner",
			existing: map[string]string{"at": older},
			incoming: map[string]string{"at": newer},
			want:     true,
		},
		{
			name:     "older incoming observation does not become owner",
			existing: map[string]string{"at": newer},
			incoming: map[string]string{"at": older},
			want:     false,
		},
		{
			name:     "equal observation keeps incoming as owner (idempotent replay)",
			existing: map[string]string{"at": newer},
			incoming: map[string]string{"at": newer},
			want:     true,
		},
		{
			name:     "incoming missing at does not become owner when existing has one",
			existing: map[string]string{"at": newer},
			incoming: map[string]string{},
			want:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectedLinkIncomingBecomesLogicalOwner(tc.existing, tc.incoming); got != tc.want {
				t.Fatalf("projectedLinkIncomingBecomesLogicalOwner(%#v, %#v) = %v, want %v", tc.existing, tc.incoming, got, tc.want)
			}
		})
	}
}

// selectProjectedLinkSurvivor is the cleanup/rehydration counterpart of
// projectedLinkIncomingBecomesLogicalOwner (Contract G): when an owning
// assertion is deleted and several assertions remain, the logical edge must
// rehydrate from the most recently observed survivor, not an arbitrary
// deterministic-but-stale ordering.
func TestSelectProjectedLinkSurvivorPicksNewestObservation(t *testing.T) {
	sep1 := attributesJSONWithAt(t, "2026-09-01T00:00:00Z")
	sep3 := attributesJSONWithAt(t, "2026-09-03T00:00:00Z")
	candidates := []projectedLogicalLinkCandidate{
		{sourceID: "aws", runtimeID: "runtime-a", attributesJSON: sep1, elementID: "4:a:1"},
		{sourceID: "aws", runtimeID: "runtime-b", attributesJSON: sep3, elementID: "4:a:2"},
	}
	survivor, ok := selectProjectedLinkSurvivor(candidates)
	if !ok {
		t.Fatal("selectProjectedLinkSurvivor() ok = false, want true")
	}
	if survivor.runtimeID != "runtime-b" {
		t.Fatalf("selectProjectedLinkSurvivor() runtimeID = %q, want %q (Sep 3 observation must beat Sep 1)", survivor.runtimeID, "runtime-b")
	}
}

func TestSelectProjectedLinkSurvivorPresentAtBeatsMissing(t *testing.T) {
	withAt := attributesJSONWithAt(t, "2026-09-01T00:00:00Z")
	candidates := []projectedLogicalLinkCandidate{
		{sourceID: "aws", runtimeID: "no-at", attributesJSON: `{}`, elementID: "4:a:1"},
		{sourceID: "aws", runtimeID: "has-at", attributesJSON: withAt, elementID: "4:a:2"},
	}
	survivor, ok := selectProjectedLinkSurvivor(candidates)
	if !ok {
		t.Fatal("selectProjectedLinkSurvivor() ok = false, want true")
	}
	if survivor.runtimeID != "has-at" {
		t.Fatalf("selectProjectedLinkSurvivor() runtimeID = %q, want %q (present at must beat missing at)", survivor.runtimeID, "has-at")
	}
}

func TestSelectProjectedLinkSurvivorBreaksTiesDeterministically(t *testing.T) {
	sameAt := attributesJSONWithAt(t, "2026-09-01T00:00:00Z")
	candidates := []projectedLogicalLinkCandidate{
		{sourceID: "aws", runtimeID: "runtime-z", attributesJSON: sameAt, elementID: "4:a:9"},
		{sourceID: "aws", runtimeID: "runtime-a", attributesJSON: sameAt, elementID: "4:a:1"},
	}
	survivor, ok := selectProjectedLinkSurvivor(candidates)
	if !ok {
		t.Fatal("selectProjectedLinkSurvivor() ok = false, want true")
	}
	if survivor.runtimeID != "runtime-a" {
		t.Fatalf("selectProjectedLinkSurvivor() runtimeID = %q, want %q (equal at must break on (source_id, runtime_id, attributes_json, elementId))", survivor.runtimeID, "runtime-a")
	}
	// Order independence: the same tiebreak must hold regardless of input order.
	reversed, ok := selectProjectedLinkSurvivor([]projectedLogicalLinkCandidate{candidates[1], candidates[0]})
	if !ok || reversed.runtimeID != "runtime-a" {
		t.Fatalf("selectProjectedLinkSurvivor(reversed) runtimeID = %q, ok = %v, want %q, true", reversed.runtimeID, ok, "runtime-a")
	}
}

func TestSelectProjectedLinkSurvivorNoCandidatesReturnsNotFound(t *testing.T) {
	if _, ok := selectProjectedLinkSurvivor(nil); ok {
		t.Fatal("selectProjectedLinkSurvivor(nil) ok = true, want false")
	}
}

func attributesJSONWithAt(t *testing.T, at string) string {
	t.Helper()
	encoded, err := graphAttributesJSON(map[string]string{"at": at})
	if err != nil {
		t.Fatalf("graphAttributesJSON() error = %v", err)
	}
	return encoded
}

// Contract G: entities that opt in via observation_precedence:"strict" must
// ignore an incoming write whose observation is older than the stored one,
// changing no attributes at all (not even the non-coupled keys
// mergeGraphAttributes would normally last-write-wins).
func TestMergeProjectedEntityAttributesStrictIgnoresOlderWrite(t *testing.T) {
	older := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	existing := map[string]string{
		"at": newer, "observation_precedence": "strict", "status": "clear",
	}
	incoming := map[string]string{
		"at": older, "observation_precedence": "strict", "status": "supported",
	}
	merged := mergeProjectedEntityAttributes(existing, incoming, nil)
	if merged["status"] != "clear" || merged["at"] != newer {
		t.Fatalf("mergeProjectedEntityAttributes(strict, older incoming) = %#v, want unchanged existing %#v", merged, existing)
	}
}

// A missing incoming `at` must be treated the same as an older one under
// strict precedence: present beats missing.
func TestMergeProjectedEntityAttributesStrictIgnoresMissingIncomingAt(t *testing.T) {
	newer := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	existing := map[string]string{"at": newer, "observation_precedence": "strict", "status": "clear"}
	incoming := map[string]string{"observation_precedence": "strict", "status": "supported"}
	merged := mergeProjectedEntityAttributes(existing, incoming, nil)
	if merged["status"] != "clear" {
		t.Fatalf("mergeProjectedEntityAttributes(strict, missing incoming at) status = %q, want %q", merged["status"], "clear")
	}
}

func TestMergeProjectedEntityAttributesStrictAppliesNewerOrEqualWrite(t *testing.T) {
	older := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	existing := map[string]string{"at": older, "observation_precedence": "strict", "status": "clear"}
	incoming := map[string]string{"at": newer, "observation_precedence": "strict", "status": "supported"}
	merged := mergeProjectedEntityAttributes(existing, incoming, nil)
	if merged["status"] != "supported" || merged["at"] != newer {
		t.Fatalf("mergeProjectedEntityAttributes(strict, newer incoming) = %#v, want status=supported at=%s", merged, newer)
	}
	// Equal `at` is a normal merge (idempotent replay), not a no-op.
	equalIncoming := map[string]string{"at": older, "observation_precedence": "strict", "status": "replayed"}
	mergedEqual := mergeProjectedEntityAttributes(map[string]string{"at": older, "observation_precedence": "strict", "status": "clear"}, equalIncoming, nil)
	if mergedEqual["status"] != "replayed" {
		t.Fatalf("mergeProjectedEntityAttributes(strict, equal at) status = %q, want %q", mergedEqual["status"], "replayed")
	}
}

// Entities that never opt in keep mergeGraphAttributes's existing coupled-key
// semantics unchanged: an older incoming write still updates non-coupled keys.
func TestMergeProjectedEntityAttributesNonOptedInUnchanged(t *testing.T) {
	older := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	existing := map[string]string{"at": newer, "status": "clear"}
	incoming := map[string]string{"at": older, "status": "supported"}
	merged := mergeProjectedEntityAttributes(existing, incoming, nil)
	want := mergeGraphAttributes(existing, incoming)
	if merged["status"] != want["status"] || merged["at"] != want["at"] {
		t.Fatalf("mergeProjectedEntityAttributes(non-opted-in) = %#v, want it to match mergeGraphAttributes = %#v", merged, want)
	}
	if merged["status"] != "supported" {
		t.Fatalf("mergeProjectedEntityAttributes(non-opted-in, older incoming) status = %q, want %q (non-coupled keys stay last-write-wins)", merged["status"], "supported")
	}
}

// A producer can commit a higher entity version with an earlier `at` than the
// version it supersedes (VulnView samples updatedAt before its conditional
// write). observation_version decides instead, and the winning version also
// owns the time-coupled provenance keys.
func TestMergeProjectedEntityAttributesStrictOrdersByObservationVersion(t *testing.T) {
	fixed := map[string]string{
		"at": "2026-11-02T10:00:01Z", "observation_precedence": "strict", "observation_version": "2",
		"status": "fixed", "event_id": "event-v2", "source_runtime_id": "runtime-a",
	}
	reopened := map[string]string{
		"at": "2026-11-02T10:00:00Z", "observation_precedence": "strict", "observation_version": "3",
		"status": "open", "event_id": "event-v3", "source_runtime_id": "runtime-b",
	}
	merged := mergeProjectedEntityAttributes(fixed, reopened, nil)
	for key, want := range map[string]string{"status": "open", "observation_version": "3", "event_id": "event-v3", "source_runtime_id": "runtime-b"} {
		if merged[key] != want {
			t.Fatalf("version 3 after version 2: merged[%s] = %q, want %q", key, merged[key], want)
		}
	}
	replayed := mergeProjectedEntityAttributes(merged, fixed, nil)
	if !maps.Equal(replayed, merged) {
		t.Fatalf("replaying version 2 after version 3 = %#v, want unchanged %#v", replayed, merged)
	}
}

// Contract G1 rule 1: an accepted observation's retraction deletes each
// RetractedAttributes key the observation's own incoming Attributes does
// not carry, and never a key it does carry.
func TestMergeProjectedEntityAttributesAppliesRetractedAttributes(t *testing.T) {
	existing := map[string]string{"triage_state": "accepted", "triage_reason": "reviewed", "status": "open"}
	incoming := map[string]string{"triage_state": "none", "status": "open"}
	merged := mergeProjectedEntityAttributes(existing, incoming, []string{"triage_reason", "status"})
	if _, present := merged["triage_reason"]; present {
		t.Fatalf("merged = %#v, want triage_reason retracted", merged)
	}
	if merged["status"] != "open" {
		t.Fatalf("merged = %#v, want status kept (present in incoming Attributes, never retracted)", merged)
	}
	if merged["triage_state"] != "none" {
		t.Fatalf("merged = %#v, want triage_state=none", merged)
	}
}

// Contract G1 rule 2: a stale strict-precedence observation changes
// nothing at all, including an attempted retraction.
func TestMergeProjectedEntityAttributesStaleStrictIgnoresRetraction(t *testing.T) {
	older := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	existing := map[string]string{"at": newer, "observation_precedence": "strict", "status": "clear"}
	incoming := map[string]string{"at": older, "observation_precedence": "strict", "status": "supported"}
	merged := mergeProjectedEntityAttributes(existing, incoming, []string{"status"})
	if merged["status"] != "clear" {
		t.Fatalf("mergeProjectedEntityAttributes(stale strict retraction) = %#v, want unchanged status=clear", merged)
	}
}

// The logical edge's typed source_id/runtime_id/projection_reconciliation_id
// must only move to the incoming writer when it is not a preserved legacy
// edge and the incoming observation does not lose to the existing one.
func TestUpdateProjectedLinksQueriesGateTypedOwnerOnObservationRecency(t *testing.T) {
	for _, query := range []string{updateProjectedLinksQuery, updateProjectedLinkQuery} {
		for _, field := range []string{"r.source_id", "r.runtime_id", "r.projection_reconciliation_id"} {
			if !strings.Contains(query, field+" = CASE") {
				t.Fatalf("query does not gate %s behind an ownership CASE expression:\n%s", field, query)
			}
		}
		if !strings.Contains(query, "preserve_logical_owner") {
			t.Fatalf("query does not reference preserve_logical_owner:\n%s", query)
		}
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

func TestProjectedLinksBatchQueryRequiresBothEndpoints(t *testing.T) {
	for _, clause := range []string{
		"UNWIND $rows AS row",
		"MATCH (src:Entity {urn: row.from_urn}), (dst:Entity {urn: row.to_urn})",
		"SET src.relation_lock = coalesce(src.relation_lock, 0) + 1",
		"MERGE (src)-[r:RELATION {relation: row.relation}]->(dst)",
		"MERGE (src)-[a:RELATION_ASSERTION {",
		"source_id: row.source_id",
		"runtime_id: row.runtime_id",
		"logical_workspace_id <> '' AND logical_workspace_id <> row.application_workspace_id",
		"assertion_workspace_id <> '' AND assertion_workspace_id <> row.application_workspace_id",
		"a.application_workspace_id = CASE WHEN row.application_workspace_id <> '' THEN row.application_workspace_id ELSE assertion_workspace_id END",
		"workspace_conflict",
		"a.projection_reconciliation_id = row.reconciliation_id",
		"RETURN row.from_urn AS from_urn",
	} {
		if !strings.Contains(mergeProjectedLinksQuery, clause) {
			t.Fatalf("mergeProjectedLinksQuery missing %q:\n%s", clause, mergeProjectedLinksQuery)
		}
	}
	for _, clause := range []string{
		"UNWIND $rows AS row",
		"WHERE coalesce(r.attributes_version, 0) = row.attributes_version",
		"r.attributes_version = row.next_attributes_version",
		"r.assertion_managed = true",
		"RETURN count(r)",
	} {
		if !strings.Contains(updateProjectedLinksQuery, clause) {
			t.Fatalf("updateProjectedLinksQuery missing %q:\n%s", clause, updateProjectedLinksQuery)
		}
	}
	for _, clause := range []string{
		"MATCH (:Entity {urn: row.from_urn})-[a:RELATION_ASSERTION {",
		"WHERE coalesce(a.attributes_version, 0) = row.attributes_version",
		"a.projection_reconciliation_id = row.reconciliation_id",
		"RETURN count(a)",
	} {
		if !strings.Contains(updateProjectedLinkAssertionsQuery, clause) {
			t.Fatalf("updateProjectedLinkAssertionsQuery missing %q:\n%s", clause, updateProjectedLinkAssertionsQuery)
		}
	}
}

func TestUpsertProjectedEntitiesRejectsCrossTenantCerebroURNBeforeConnection(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedEntities(context.Background(), []*ports.ProjectedEntity{{
		URN:        "urn:cerebro:victim:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
	}})
	if err == nil {
		t.Fatal("UpsertProjectedEntities() error = nil, want cross-tenant Cerebro URN error")
	}
	requireProjectedTenantScopeError(t, err, "projected entity urn", "urn:cerebro:victim:github_user:alice")
}

func TestUpsertProjectedLinksRejectsCrossTenantCerebroURNBeforeConnection(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedLinks(context.Background(), []*ports.ProjectedLink{{
		TenantID: "writer",
		SourceID: "github",
		FromURN:  "urn:cerebro:writer:github_user:alice",
		ToURN:    "urn:cerebro:victim:github_code_repository:writer/cerebro",
		Relation: "owns",
	}})
	if err == nil {
		t.Fatal("UpsertProjectedLinks() error = nil, want cross-tenant Cerebro URN error")
	}
	requireProjectedTenantScopeError(t, err, "projected link to urn", "urn:cerebro:victim:github_code_repository:writer/cerebro")
}

func requireProjectedTenantScopeError(t *testing.T, err error, field, urn string) {
	t.Helper()
	if !errors.Is(err, ports.ErrProjectedTenantScope) {
		t.Fatalf("error = %v, want %v", err, ports.ErrProjectedTenantScope)
	}
	var scopeErr *ports.ProjectedTenantScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("error = %T, want *ports.ProjectedTenantScopeError", err)
	}
	if scopeErr.Field != field || scopeErr.URN != urn || scopeErr.URNTenantID != "victim" || scopeErr.ProjectionTenantID != "writer" {
		t.Fatalf("scope error = %#v", scopeErr)
	}
}

func TestPrepareProjectedEntitiesCoalescesValidatesAndSorts(t *testing.T) {
	prepared, err := prepareProjectedEntities([]*ports.ProjectedEntity{
		{
			URN:        "urn:cerebro:writer:github_user:zoe",
			TenantID:   "writer",
			SourceID:   "github",
			EntityType: "github.user",
			Attributes: map[string]string{"login": "zoe"},
		},
		{
			URN:        "urn:cerebro:writer:github_user:alice",
			TenantID:   "writer",
			SourceID:   "github",
			EntityType: "github.user",
			Attributes: map[string]string{"login": "alice"},
		},
		{
			URN:        "urn:cerebro:writer:github_user:alice",
			TenantID:   "writer",
			SourceID:   "github",
			RuntimeID:  "writer-github",
			EntityType: "github.user",
			Label:      "Alice",
			Attributes: map[string]string{"email": "alice@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("prepareProjectedEntities() error = %v", err)
	}
	if len(prepared) != 2 {
		t.Fatalf("prepared len = %d, want 2 (alice coalesced)", len(prepared))
	}
	if prepared[0].urn != "urn:cerebro:writer:github_user:alice" || prepared[1].urn != "urn:cerebro:writer:github_user:zoe" {
		t.Fatalf("prepared not sorted by urn: %q, %q", prepared[0].urn, prepared[1].urn)
	}
	alice := prepared[0]
	if alice.attributes["login"] != "alice" || alice.attributes["email"] != "alice@example.com" {
		t.Fatalf("coalesced alice attributes = %#v, want merged login+email", alice.attributes)
	}
	if alice.label != "Alice" || alice.runtimeID != "writer-github" {
		t.Fatalf("coalesced alice scalars = label %q runtime %q, want latest occurrence to win", alice.label, alice.runtimeID)
	}
	zoe := prepared[1]
	if zoe.label != zoe.urn {
		t.Fatalf("zoe label = %q, want fallback to urn", zoe.label)
	}
}

func TestPrepareProjectedEntitiesValidationErrors(t *testing.T) {
	cases := map[string]*ports.ProjectedEntity{
		"projected entity is required":      nil,
		"projected entity urn is required":  {TenantID: "writer", SourceID: "github", EntityType: "github.user"},
		"projected entity type is required": {URN: "urn:x", TenantID: "writer", SourceID: "github"},
	}
	for want, entity := range cases {
		_, err := prepareProjectedEntities([]*ports.ProjectedEntity{entity})
		if err == nil {
			t.Fatalf("prepareProjectedEntities(%#v) error = nil, want %q", entity, want)
		}
		if got := err.Error(); !strings.Contains(got, want) {
			t.Fatalf("prepareProjectedEntities(%#v) error = %q, want %q", entity, got, want)
		}
	}
}

func TestPrepareProjectedEntitiesRejectsWorkspaceLastWriteWins(t *testing.T) {
	entity := func(workspaceID string) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{URN: "urn:cerebro:writer:asset:one", TenantID: "writer", ApplicationWorkspaceID: workspaceID, SourceID: "github", EntityType: "asset"}
	}
	_, err := prepareProjectedEntities([]*ports.ProjectedEntity{entity("workspace-a"), entity("workspace-b")})
	if !errors.Is(err, ports.ErrApplicationWorkspaceConflict) {
		t.Fatalf("prepareProjectedEntities() error = %v, want workspace conflict", err)
	}
	prepared, err := prepareProjectedEntities([]*ports.ProjectedEntity{entity(""), entity("workspace-a")})
	if err != nil || len(prepared) != 1 || prepared[0].applicationWorkspaceID != "workspace-a" {
		t.Fatalf("blank legacy reprojection = %#v, %v", prepared, err)
	}
}

// Contract G1 page/batch coalescing within one UpsertProjectedEntities
// call: an ordinary entity always wins over a CreateOnly stub sharing a
// URN, in either arrival order, and two stubs for the same URN keep the
// first.
func TestPrepareProjectedEntitiesOrdinaryWinsOverCreateOnlyStub(t *testing.T) {
	ordinary := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:aws_role:principal", TenantID: "writer", SourceID: "aws", RuntimeID: "writer-aws",
		EntityType: "aws_role", Label: "arn:aws:iam::111:role/principal",
		Attributes: map[string]string{"account_id": "111"},
	}
	stub := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:aws_role:principal", TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "aws_role", Label: "urn:cerebro:writer:aws_role:principal",
		CreateOnly: true,
	}
	for _, order := range [][]*ports.ProjectedEntity{{ordinary, stub}, {stub, ordinary}} {
		prepared, err := prepareProjectedEntities(order)
		if err != nil || len(prepared) != 1 {
			t.Fatalf("prepareProjectedEntities(%#v) = %#v, %v, want one coalesced entity", order, prepared, err)
		}
		if prepared[0].sourceID != "aws" || prepared[0].label != ordinary.Label || prepared[0].createOnly || prepared[0].attributes["account_id"] != "111" {
			t.Fatalf("prepareProjectedEntities(%#v)[0] = %#v, want the ordinary entity untouched by the stub", order, prepared[0])
		}
	}
	twoStubs := []*ports.ProjectedEntity{
		{URN: "urn:cerebro:writer:aws_role:principal", TenantID: "writer", SourceID: "vulnview", EntityType: "aws_role", Label: "first", CreateOnly: true},
		{URN: "urn:cerebro:writer:aws_role:principal", TenantID: "writer", SourceID: "vulnview", EntityType: "aws_role", Label: "second", CreateOnly: true},
	}
	prepared, err := prepareProjectedEntities(twoStubs)
	if err != nil || len(prepared) != 1 || prepared[0].label != "first" || !prepared[0].createOnly {
		t.Fatalf("prepareProjectedEntities(two stubs) = %#v, %v, want the first stub retained", prepared, err)
	}
}

// Contract G1 page/batch coalescing: two ordinary entities for the same URN
// apply existing merge rules and the coalesced RetractedAttributes is the
// union of both minus keys the coalesced attributes still carry.
func TestPrepareProjectedEntitiesCoalescesRetractedAttributes(t *testing.T) {
	first := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:vulnview_finding:f-1", TenantID: "writer", SourceID: "vulnview",
		EntityType: "vulnview_finding",
		Attributes: map[string]string{"triage_state": "accepted", "triage_reason": "reviewed", "status": "open"},
	}
	second := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:vulnview_finding:f-1", TenantID: "writer", SourceID: "vulnview",
		EntityType:          "vulnview_finding",
		Attributes:          map[string]string{"triage_state": "none", "status": "open"},
		RetractedAttributes: []string{"triage_reason"},
	}
	prepared, err := prepareProjectedEntities([]*ports.ProjectedEntity{first, second})
	if err != nil || len(prepared) != 1 {
		t.Fatalf("prepareProjectedEntities() = %#v, %v, want one coalesced entity", prepared, err)
	}
	entry := prepared[0]
	if _, present := entry.attributes["triage_reason"]; present {
		t.Fatalf("attributes = %#v, want triage_reason retracted", entry.attributes)
	}
	if entry.attributes["triage_state"] != "none" || entry.attributes["status"] != "open" {
		t.Fatalf("attributes = %#v, want triage_state=none and status preserved", entry.attributes)
	}
	if len(entry.retractedAttributes) != 1 || entry.retractedAttributes[0] != "triage_reason" {
		t.Fatalf("retracted attributes = %#v, want [triage_reason]", entry.retractedAttributes)
	}
}

func TestPrepareProjectedLinksCoalescesValidatesAndSorts(t *testing.T) {
	prepared, err := prepareProjectedLinks([]*ports.ProjectedLink{
		{
			TenantID: "writer", SourceID: "github",
			FromURN:  "urn:cerebro:writer:github_user:zoe",
			Relation: "maintains",
			ToURN:    "urn:cerebro:writer:github_code_repository:writer/cerebro",
		},
		{
			TenantID: "writer", SourceID: "github",
			FromURN:    "urn:cerebro:writer:github_user:alice",
			Relation:   "maintains",
			ToURN:      "urn:cerebro:writer:github_code_repository:writer/cerebro",
			Attributes: map[string]string{"role": "admin"},
		},
		{
			TenantID: "writer", SourceID: "github", RuntimeID: "writer-github",
			FromURN:    "urn:cerebro:writer:github_user:alice",
			Relation:   "maintains",
			ToURN:      "urn:cerebro:writer:github_code_repository:writer/cerebro",
			Attributes: map[string]string{"since": "2025"},
		},
		{
			TenantID: "writer", SourceID: "github", RuntimeID: "writer-github",
			FromURN:    "urn:cerebro:writer:github_user:alice",
			Relation:   "maintains",
			ToURN:      "urn:cerebro:writer:github_code_repository:writer/cerebro",
			Attributes: map[string]string{"team": "security"},
		},
	})
	if err != nil {
		t.Fatalf("prepareProjectedLinks() error = %v", err)
	}
	if len(prepared) != 3 {
		t.Fatalf("prepared len = %d, want 3 (runtime assertions remain distinct)", len(prepared))
	}
	if prepared[0].fromURN != "urn:cerebro:writer:github_user:alice" || prepared[1].fromURN != "urn:cerebro:writer:github_user:alice" || prepared[2].fromURN != "urn:cerebro:writer:github_user:zoe" {
		t.Fatalf("prepared links not sorted by from urn: %q, %q, %q", prepared[0].fromURN, prepared[1].fromURN, prepared[2].fromURN)
	}
	if prepared[0].runtimeID != "" || prepared[0].attributes["role"] != "admin" {
		t.Fatalf("default-runtime alice assertion = %#v, want role=admin", prepared[0])
	}
	if prepared[1].runtimeID != "writer-github" || prepared[1].attributes["since"] != "2025" || prepared[1].attributes["team"] != "security" {
		t.Fatalf("writer-github alice assertion = %#v, want merged since+team", prepared[1])
	}
}

func TestPrepareProjectedLinksValidationErrors(t *testing.T) {
	cases := map[string]*ports.ProjectedLink{
		"projected link is required":          nil,
		"projected link from urn is required": {TenantID: "writer", SourceID: "github", Relation: "owns", ToURN: "urn:y"},
		"projected link relation is required": {TenantID: "writer", SourceID: "github", FromURN: "urn:x", ToURN: "urn:y"},
	}
	for want, link := range cases {
		_, err := prepareProjectedLinks([]*ports.ProjectedLink{link})
		if err == nil {
			t.Fatalf("prepareProjectedLinks(%#v) error = nil, want %q", link, want)
		}
		if got := err.Error(); !strings.Contains(got, want) {
			t.Fatalf("prepareProjectedLinks(%#v) error = %q, want %q", link, got, want)
		}
	}
}

func TestPrepareProjectedLinksRejectsWorkspaceLastWriteWins(t *testing.T) {
	link := func(workspaceID string) *ports.ProjectedLink {
		return &ports.ProjectedLink{TenantID: "writer", ApplicationWorkspaceID: workspaceID, SourceID: "github", RuntimeID: "runtime-one", FromURN: "urn:cerebro:writer:asset:one", ToURN: "urn:cerebro:writer:asset:two", Relation: "associated_with"}
	}
	_, err := prepareProjectedLinks([]*ports.ProjectedLink{link("workspace-a"), link("workspace-b")})
	if !errors.Is(err, ports.ErrApplicationWorkspaceConflict) {
		t.Fatalf("prepareProjectedLinks() error = %v, want workspace conflict", err)
	}
}

func TestChunkSlice(t *testing.T) {
	chunks := chunkSlice([]int{1, 2, 3, 4, 5}, 2)
	if len(chunks) != 3 || len(chunks[0]) != 2 || len(chunks[2]) != 1 {
		t.Fatalf("chunkSlice(5, 2) = %#v, want [[1 2] [3 4] [5]]", chunks)
	}
	if chunks[2][0] != 5 {
		t.Fatalf("chunkSlice remainder = %#v, want [5]", chunks[2])
	}
	if got := chunkSlice([]int(nil), 2); got != nil {
		t.Fatalf("chunkSlice(nil) = %#v, want nil", got)
	}
	if got := chunkSlice([]int{1, 2}, 0); len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("chunkSlice with size 0 = %#v, want single chunk", got)
	}
}

func TestNeo4jDockerBatchProjectionMatchesPerItem(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-batch-test-%d", time.Now().UnixNano())
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
		URN: "urn:cerebro:writer:github_user:alice", TenantID: "writer", SourceID: "github",
		EntityType: "github_user", Label: "alice", Attributes: map[string]string{"login": "alice"},
	}
	repo := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:github_code_repository:writer/cerebro", TenantID: "writer", SourceID: "github",
		EntityType: "github_code_repository", Label: "writer/cerebro",
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{user, repo}); err != nil {
		t.Fatalf("UpsertProjectedEntities() error = %v", err)
	}
	// Re-running the batch with new attributes must deep-merge, not clobber.
	updatedUser := *user
	updatedUser.Attributes = map[string]string{"team": "security"}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{&updatedUser}); err != nil {
		t.Fatalf("UpsertProjectedEntities(update) error = %v", err)
	}
	userAttributes := projectedEntityAttributes(t, ctx, store, user.URN)
	for key, want := range map[string]string{"login": "alice", "team": "security"} {
		if userAttributes[key] != want {
			t.Fatalf("batch user attributes[%q] = %q, want %q in %#v", key, userAttributes[key], want, userAttributes)
		}
	}

	maintains := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "github", FromURN: user.URN, Relation: "maintains", ToURN: repo.URN,
		Attributes: map[string]string{"role": "admin"},
	}
	dangling := &ports.ProjectedLink{
		TenantID: "writer", SourceID: "github", FromURN: user.URN, Relation: "maintains",
		ToURN: "urn:cerebro:writer:github_code_repository:writer/missing",
	}
	if err := store.UpsertProjectedLinks(ctx, []*ports.ProjectedLink{maintains, dangling}); err != nil {
		t.Fatalf("UpsertProjectedLinks() error = %v", err)
	}
	linkAttributes := projectedLinkAttributes(t, ctx, store, maintains)
	if linkAttributes["role"] != "admin" {
		t.Fatalf("batch link attributes = %#v, want role=admin", linkAttributes)
	}
	if neo4jProjectedLinkExists(t, ctx, store, dangling) {
		t.Fatal("dangling link was materialized; batch must skip links whose endpoints do not both exist")
	}
}

// TestNeo4jDockerProjectedLinkLogicalOwnerFollowsObservationRecency reproduces
// the EKS Pod Identity / cloud_identity convergence: two runtimes project the
// same kubernetes_service_account -can_assume-> aws_role link out of order.
// The logical edge's typed source_id/runtime_id/projection_reconciliation_id
// must always match the owning writer (the one with the most recent `at`
// observation), the same way attributes_json.source_runtime_id already does,
// for both the single-item and batch upsert paths, and the retraction path
// must keep that invariant when the owner's assertion disappears.
func TestNeo4jDockerProjectedLinkLogicalOwnerFollowsObservationRecency(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-owner-test-%d", time.Now().UnixNano())
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

	older := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newer := time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	const eks = "eks-pod-identity"
	const cloudIdentity = "cloud-identity"

	serviceAccount := func(index int) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{
			URN:      fmt.Sprintf("urn:cerebro:writer:kubernetes_service_account:111111111111:prod:default:app-%d", index),
			TenantID: "writer", SourceID: "aws", EntityType: "kubernetes_service_account",
			Label: fmt.Sprintf("app-%d", index),
		}
	}
	role := func(index int) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{
			URN:      fmt.Sprintf("urn:cerebro:writer:aws_role:arn:aws:iam::111111111111:role/app-%d", index),
			TenantID: "writer", SourceID: "aws", EntityType: "aws_role",
			Label: fmt.Sprintf("app-%d-role", index),
		}
	}
	relation := func(index int) string {
		return fmt.Sprintf("can_assume_%d", index)
	}
	link := func(index int, runtimeID string, at string) *ports.ProjectedLink {
		return &ports.ProjectedLink{
			TenantID: "writer", SourceID: "aws", RuntimeID: runtimeID,
			FromURN: serviceAccount(index).URN, ToURN: role(index).URN, Relation: relation(index),
			Attributes: map[string]string{
				"source_runtime_id": runtimeID,
				"source_event_id":   "evt-" + runtimeID + "-" + at,
				"at":                at,
			},
		}
	}
	var entities []*ports.ProjectedEntity
	for index := 1; index <= 4; index++ {
		entities = append(entities, serviceAccount(index), role(index))
	}
	if err := store.UpsertProjectedEntities(ctx, entities); err != nil {
		t.Fatalf("UpsertProjectedEntities() error = %v", err)
	}

	assertOwner := func(t *testing.T, index int, wantRuntimeID string) {
		t.Helper()
		edge := &ports.ProjectedLink{FromURN: serviceAccount(index).URN, ToURN: role(index).URN, Relation: relation(index)}
		provenance := projectedLinkTypedProvenance(t, ctx, store, edge)
		if provenance.sourceID != "aws" || provenance.runtimeID != wantRuntimeID {
			t.Fatalf("link %d typed provenance = %#v, want source_id=aws runtime_id=%q", index, provenance, wantRuntimeID)
		}
		attributes := projectedLinkAttributes(t, ctx, store, edge)
		if attributes["source_runtime_id"] != wantRuntimeID {
			t.Fatalf("link %d attributes_json source_runtime_id = %q, want %q (must match typed runtime_id %q)", index, attributes["source_runtime_id"], wantRuntimeID, provenance.runtimeID)
		}
	}

	// Link 1 (single-item path): newer observation first, then an older
	// observation from a second runtime. The first writer must stay owner.
	if err := store.UpsertProjectedLink(ctx, link(1, eks, newer)); err != nil {
		t.Fatalf("UpsertProjectedLink(link1, eks, newer) error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, link(1, cloudIdentity, older)); err != nil {
		t.Fatalf("UpsertProjectedLink(link1, cloud-identity, older) error = %v", err)
	}
	assertOwner(t, 1, eks)

	// Link 2 (single-item path): older observation first, then a newer
	// observation from a second runtime. Ownership must switch.
	if err := store.UpsertProjectedLink(ctx, link(2, eks, older)); err != nil {
		t.Fatalf("UpsertProjectedLink(link2, eks, older) error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, link(2, cloudIdentity, newer)); err != nil {
		t.Fatalf("UpsertProjectedLink(link2, cloud-identity, newer) error = %v", err)
	}
	assertOwner(t, 2, cloudIdentity)

	// Links 3 and 4 (batch path), both orderings in one batch: link 3 keeps
	// its first (newer) writer as owner; link 4 switches to its second
	// (newer) writer.
	if err := store.UpsertProjectedLinks(ctx, []*ports.ProjectedLink{
		link(3, eks, newer),
		link(3, cloudIdentity, older),
		link(4, eks, older),
		link(4, cloudIdentity, newer),
	}); err != nil {
		t.Fatalf("UpsertProjectedLinks(batch) error = %v", err)
	}
	assertOwner(t, 3, eks)
	assertOwner(t, 4, cloudIdentity)

	// Retracting the owning runtime's assertion (link 1's eks-pod-identity
	// assertion no longer observed in a fresh reconciliation pass) must
	// rebuild the logical edge from the surviving cloud-identity assertion,
	// keeping the typed/attribute invariant coherent with the new owner.
	result, err := store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: "writer", SourceID: "aws", RuntimeID: eks,
		ReconciliationID: "reconciliation-run-2", Relations: []string{relation(1)}, Limit: 100,
	})
	if err != nil {
		t.Fatalf("CleanupProjectedRuntimeLinks() error = %v", err)
	}
	if result.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks() deleted = %d, want 1", result.LinksDeleted)
	}
	edge1 := &ports.ProjectedLink{FromURN: serviceAccount(1).URN, ToURN: role(1).URN, Relation: relation(1)}
	if !neo4jProjectedLinkExists(t, ctx, store, edge1) {
		t.Fatal("logical link 1 was deleted; it must survive on the remaining cloud-identity assertion")
	}
	assertOwner(t, 1, cloudIdentity)
}

// TestNeo4jDockerProjectedLinkRehydrationPicksNewestSurvivingObservation
// reproduces review finding P2: when the owning (newest) assertion is
// retracted and several non-owning assertions remain, the logical edge must
// rehydrate from the most recently observed survivor (Sep 3), not from
// whichever candidate an arbitrary deterministic Cypher ORDER BY happened to
// sort first (previously the Sep 1 observation).
func TestNeo4jDockerProjectedLinkRehydrationPicksNewestSurvivingObservation(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-rehydrate-test-%d", time.Now().UnixNano())
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

	sep1 := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	sep3 := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	sep5 := time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

	serviceAccount := &ports.ProjectedEntity{
		URN:      "urn:cerebro:writer:kubernetes_service_account:111111111111:prod:default:rehydrate",
		TenantID: "writer", SourceID: "aws", EntityType: "kubernetes_service_account", Label: "rehydrate",
	}
	role := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:aws_role:arn:aws:iam::111111111111:role/rehydrate", TenantID: "writer",
		SourceID: "aws", EntityType: "aws_role", Label: "rehydrate-role",
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{serviceAccount, role}); err != nil {
		t.Fatalf("UpsertProjectedEntities() error = %v", err)
	}
	const relation = "can_assume"
	linkFrom := func(runtimeID string, at string) *ports.ProjectedLink {
		return &ports.ProjectedLink{
			TenantID: "writer", SourceID: "aws", RuntimeID: runtimeID,
			FromURN: serviceAccount.URN, ToURN: role.URN, Relation: relation,
			Attributes: map[string]string{"source_runtime_id": runtimeID, "at": at},
		}
	}
	// Three runtimes assert the same link: Sep 1 (oldest), Sep 3, and Sep 5
	// (the current owner). The owner always wins while present.
	for _, link := range []*ports.ProjectedLink{
		linkFrom("runtime-sep1", sep1),
		linkFrom("runtime-sep3", sep3),
		linkFrom("runtime-sep5", sep5),
	} {
		if err := store.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("UpsertProjectedLink(%s) error = %v", link.RuntimeID, err)
		}
	}
	edge := &ports.ProjectedLink{FromURN: serviceAccount.URN, ToURN: role.URN, Relation: relation}
	provenance := projectedLinkTypedProvenance(t, ctx, store, edge)
	if provenance.runtimeID != "runtime-sep5" {
		t.Fatalf("owner before retraction = %q, want %q", provenance.runtimeID, "runtime-sep5")
	}

	// Retract the Sep 5 owner. Sep 1 and Sep 3 assertions both survive; the
	// logical edge must rehydrate from Sep 3 (newest remaining), not Sep 1.
	result, err := store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: "writer", SourceID: "aws", RuntimeID: "runtime-sep5",
		ReconciliationID: "reconciliation-run-rehydrate", Relations: []string{relation}, Limit: 100,
	})
	if err != nil {
		t.Fatalf("CleanupProjectedRuntimeLinks() error = %v", err)
	}
	if result.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks() deleted = %d, want 1", result.LinksDeleted)
	}
	if !neo4jProjectedLinkExists(t, ctx, store, edge) {
		t.Fatal("logical link was deleted; it must survive on the remaining Sep 1/Sep 3 assertions")
	}
	provenance = projectedLinkTypedProvenance(t, ctx, store, edge)
	if provenance.runtimeID != "runtime-sep3" {
		t.Fatalf("rehydrated owner runtime_id = %q, want %q (Sep 3 must beat Sep 1)", provenance.runtimeID, "runtime-sep3")
	}
	attributes := projectedLinkAttributes(t, ctx, store, edge)
	if attributes["at"] != sep3 {
		t.Fatalf("rehydrated attributes_json.at = %q, want %q", attributes["at"], sep3)
	}
}

// TestNeo4jDockerProjectedEntityStrictObservationPrecedence exercises
// Contract G's entity opt-in through both UpsertProjectedEntity (single) and
// UpsertProjectedEntities (batch), against a real Neo4j instance so the
// attributes_version-gated write path is proven end to end.
func TestNeo4jDockerProjectedEntityStrictObservationPrecedence(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-strict-entity-test-%d", time.Now().UnixNano())
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

	sep1 := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	sep3 := time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	sep5 := time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

	strictEntity := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:vulnview.finding:111111111111:strict", TenantID: "writer",
		SourceID: "vulnview", EntityType: "vulnview.finding", Label: "strict",
		Attributes: map[string]string{"at": sep3, "observation_precedence": "strict", "status": "clear"},
	}
	if err := store.UpsertProjectedEntity(ctx, strictEntity); err != nil {
		t.Fatalf("UpsertProjectedEntity(establish) error = %v", err)
	}

	// Single-item path: an older write must change nothing.
	olderSingle := &ports.ProjectedEntity{
		URN: strictEntity.URN, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "strict",
		Attributes: map[string]string{"at": sep1, "observation_precedence": "strict", "status": "supported"},
	}
	if err := store.UpsertProjectedEntity(ctx, olderSingle); err != nil {
		t.Fatalf("UpsertProjectedEntity(older single) error = %v", err)
	}
	attributes := projectedEntityAttributes(t, ctx, store, strictEntity.URN)
	if attributes["status"] != "clear" || attributes["at"] != sep3 {
		t.Fatalf("after older single-path write, attributes = %#v, want status=clear at=%s (strict entity must ignore older write)", attributes, sep3)
	}

	// Batch path: an older write in UpsertProjectedEntities must also change
	// nothing.
	olderBatch := &ports.ProjectedEntity{
		URN: strictEntity.URN, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "strict",
		Attributes: map[string]string{"at": sep1, "observation_precedence": "strict", "status": "batch-supported"},
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{olderBatch}); err != nil {
		t.Fatalf("UpsertProjectedEntities(older batch) error = %v", err)
	}
	attributes = projectedEntityAttributes(t, ctx, store, strictEntity.URN)
	if attributes["status"] != "clear" || attributes["at"] != sep3 {
		t.Fatalf("after older batch-path write, attributes = %#v, want status=clear at=%s (strict entity must ignore older write)", attributes, sep3)
	}

	// A newer write through the batch path must apply normally.
	newerBatch := &ports.ProjectedEntity{
		URN: strictEntity.URN, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "strict",
		Attributes: map[string]string{"at": sep5, "observation_precedence": "strict", "status": "updated"},
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{newerBatch}); err != nil {
		t.Fatalf("UpsertProjectedEntities(newer batch) error = %v", err)
	}
	attributes = projectedEntityAttributes(t, ctx, store, strictEntity.URN)
	if attributes["status"] != "updated" || attributes["at"] != sep5 {
		t.Fatalf("after newer batch-path write, attributes = %#v, want status=updated at=%s", attributes, sep5)
	}

	// An entity without the opt-in keeps today's semantics: an older write
	// still updates non-coupled keys (last-write-wins), unaffected by Contract G.
	nonOptedEntity := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:vulnview.finding:111111111111:non-strict", TenantID: "writer",
		SourceID: "vulnview", EntityType: "vulnview.finding", Label: "non-strict",
		Attributes: map[string]string{"at": sep3, "status": "clear"},
	}
	if err := store.UpsertProjectedEntity(ctx, nonOptedEntity); err != nil {
		t.Fatalf("UpsertProjectedEntity(non-opted establish) error = %v", err)
	}
	olderNonOpted := &ports.ProjectedEntity{
		URN: nonOptedEntity.URN, TenantID: "writer", SourceID: "vulnview", EntityType: "vulnview.finding", Label: "non-strict",
		Attributes: map[string]string{"at": sep1, "status": "supported"},
	}
	if err := store.UpsertProjectedEntity(ctx, olderNonOpted); err != nil {
		t.Fatalf("UpsertProjectedEntity(non-opted older) error = %v", err)
	}
	attributes = projectedEntityAttributes(t, ctx, store, nonOptedEntity.URN)
	if attributes["status"] != "supported" {
		t.Fatalf("non-opted entity status = %q, want %q (entities without the opt-in keep last-write-wins semantics)", attributes["status"], "supported")
	}

	// observation_version, not `at`, orders a versioned strict entity, and the
	// typed source_id/runtime_id and label stay with the winning observation:
	// a stale replay from another runtime must not leave typed ownership
	// disagreeing with attributes_json.source_runtime_id.
	const versionedURN = "urn:cerebro:writer:vulnview.finding:versioned"
	versioned := func(version, at, status, runtimeID, label string) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{
			URN: versionedURN, TenantID: "writer",
			SourceID: "vulnview", RuntimeID: runtimeID, EntityType: "vulnview.finding", Label: label,
			Attributes: map[string]string{
				"at": at, "observation_precedence": "strict", "observation_version": version,
				"status": status, "source_runtime_id": runtimeID,
			},
		}
	}
	assertVersioned := func(t *testing.T, step, status, runtimeID, label string) {
		t.Helper()
		attributes := projectedEntityAttributes(t, ctx, store, versionedURN)
		owner := projectedEntityTypedOwner(t, ctx, store, versionedURN)
		if attributes["status"] != status || attributes["source_runtime_id"] != runtimeID || owner.runtimeID != runtimeID || owner.label != label {
			t.Fatalf("after %s: attributes = %#v, typed owner = %#v; want status=%s runtime=%s label=%s", step, attributes, owner, status, runtimeID, label)
		}
	}
	if err := store.UpsertProjectedEntity(ctx, versioned("2", sep3, "fixed", "runtime-old", "version-2")); err != nil {
		t.Fatalf("UpsertProjectedEntity(version 2) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, versioned("3", sep1, "open", "runtime-new", "version-3")); err != nil {
		t.Fatalf("UpsertProjectedEntity(version 3, earlier at) error = %v", err)
	}
	assertVersioned(t, "version 3 with an earlier at", "open", "runtime-new", "version-3")
	if err := store.UpsertProjectedEntity(ctx, versioned("2", sep3, "fixed", "runtime-old", "version-2")); err != nil {
		t.Fatalf("UpsertProjectedEntity(version 2 replay) error = %v", err)
	}
	assertVersioned(t, "single-path version 2 replay", "open", "runtime-new", "version-3")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{versioned("2", sep3, "fixed", "runtime-old", "version-2")}); err != nil {
		t.Fatalf("UpsertProjectedEntities(version 2 replay) error = %v", err)
	}
	assertVersioned(t, "batch-path version 2 replay", "open", "runtime-new", "version-3")
	// A newer version arriving with only a fallback (urn-equal) label still
	// keeps the stored label.
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{versioned("4", sep5, "fixed", "runtime-new", "")}); err != nil {
		t.Fatalf("UpsertProjectedEntities(version 4, fallback label) error = %v", err)
	}
	assertVersioned(t, "version 4 with a fallback label", "fixed", "runtime-new", "version-3")
}

// projectedEntitySnapshot captures every field a stale strict observation
// must never change, so tests can assert byte-for-byte equality rather
// than field-by-field spot checks.
type projectedEntitySnapshot struct {
	attributesJSON string
	version        int64
	entityType     string
	workspaceID    string
	tenantID       string
}

func projectedEntitySnapshotFor(t *testing.T, ctx context.Context, store *Store, urn string) projectedEntitySnapshot {
	t.Helper()
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (e:Entity {urn: $urn}) RETURN coalesce(e.attributes_json, '{}'), coalesce(e.attributes_version, 0), coalesce(e.entity_type, ''), coalesce(e.application_workspace_id, ''), coalesce(e.tenant_id, '')`, map[string]any{"urn": urn})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		return result.Record().Values, result.Err()
	})
	if err != nil {
		t.Fatalf("query projected entity snapshot: %v", err)
	}
	row, ok := values.([]any)
	if !ok || len(row) != 5 {
		t.Fatalf("projected entity snapshot query returned %#v, want five columns", values)
	}
	return projectedEntitySnapshot{
		attributesJSON: stringValue(row[0]), version: toInt64(row[1]), entityType: stringValue(row[2]),
		workspaceID: stringValue(row[3]), tenantID: stringValue(row[4]),
	}
}

// TestNeo4jDockerProjectedEntityStaleStrictWriteIsByteIdenticalNoOp proves
// Contract G1 rule 2 against a real Neo4j instance: a stale
// strict-precedence observation changes nothing at all. Before this fix,
// the merge query wrote tenant_id/application_workspace_id/entity_type
// before staleness was known, and the update query still bumped
// attributes_version and rewrote attributes_json/typed properties for a
// stale write — so a stale replay that also tried to move the entity to a
// different tenant-scoped workspace, type, and runtime silently succeeded
// in part. Both the single-item and batch paths must leave every field
// byte-identical.
func TestNeo4jDockerProjectedEntityStaleStrictWriteIsByteIdenticalNoOp(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-stale-noop-test-%d", time.Now().UnixNano())
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

	nov1 := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	nov3 := time.Date(2026, time.November, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	const urn = "urn:cerebro:writer:vulnview_finding:777777777777:f-stale"
	accepted := &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", ApplicationWorkspaceID: "workspace-a", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "vulnview_finding", Label: "f-stale",
		Attributes: map[string]string{"at": nov3, "observation_precedence": "strict", "observation_version": "3", "status": "fixed"},
	}
	if err := store.UpsertProjectedEntity(ctx, accepted); err != nil {
		t.Fatalf("UpsertProjectedEntity(accepted) error = %v", err)
	}
	before := projectedEntitySnapshotFor(t, ctx, store, urn)

	// A stale replay that also tries to move tenant-scoped workspace,
	// entity_type, runtime, and label must change nothing at all.
	stale := &ports.ProjectedEntity{
		URN: urn, TenantID: "writer", ApplicationWorkspaceID: "workspace-b", SourceID: "aws", RuntimeID: "other-runtime",
		EntityType: "different_type", Label: "stale-label",
		Attributes: map[string]string{"at": nov1, "observation_precedence": "strict", "observation_version": "1", "status": "stale"},
	}
	if err := store.UpsertProjectedEntity(ctx, stale); err != nil {
		t.Fatalf("UpsertProjectedEntity(stale single) error = %v", err)
	}
	afterSingle := projectedEntitySnapshotFor(t, ctx, store, urn)
	if afterSingle != before {
		t.Fatalf("stale strict single-path write changed stored state:\nbefore = %#v\nafter  = %#v", before, afterSingle)
	}
	owner := projectedEntityTypedOwner(t, ctx, store, urn)
	if owner.sourceID != "vulnview" || owner.runtimeID != "writer-vulnview" || owner.label != "f-stale" {
		t.Fatalf("stale strict single-path write changed typed ownership: %#v", owner)
	}

	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{stale}); err != nil {
		t.Fatalf("UpsertProjectedEntities(stale) error = %v", err)
	}
	afterBatch := projectedEntitySnapshotFor(t, ctx, store, urn)
	if afterBatch != before {
		t.Fatalf("stale strict batch-path write changed stored state:\nbefore = %#v\nafter  = %#v", before, afterBatch)
	}
	owner = projectedEntityTypedOwner(t, ctx, store, urn)
	if owner.sourceID != "vulnview" || owner.runtimeID != "writer-vulnview" || owner.label != "f-stale" {
		t.Fatalf("stale strict batch-path write changed typed ownership: %#v", owner)
	}
}

// linkSetOwnerRole and linkSetConsumer build distinctly indexed fixtures so
// each guarded link-set scenario below stays independent inside one shared
// container.
func linkSetOwnerRole(index int) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:      fmt.Sprintf("urn:cerebro:writer:aws_role:arn:aws:iam::222222222222:role/link-set-owner-%d", index),
		TenantID: "writer", SourceID: "vulnview", EntityType: "aws_role",
		Label: fmt.Sprintf("link-set-owner-%d", index),
	}
}

func linkSetConsumer(index int, suffix string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:      fmt.Sprintf("urn:cerebro:writer:kubernetes_service_account:222222222222:prod:default:consumer-%d-%s", index, suffix),
		TenantID: "writer", SourceID: "vulnview", EntityType: "kubernetes_service_account",
		Label: fmt.Sprintf("consumer-%d-%s", index, suffix),
	}
}

// linkSetAssertionOtherURNs returns the sorted target URNs of every outgoing
// associated_with RELATION_ASSERTION from one owner that the writer
// tenant's vulnview source asserts for one runtime, letting tests assert
// exactly which links a guarded set left in place.
func linkSetAssertionOtherURNs(t *testing.T, ctx context.Context, store *Store, ownerURN string, runtimeID string) []string {
	const relation, tenantID, sourceID = "associated_with", "writer", "vulnview"
	t.Helper()
	query := `MATCH (owner:Entity {urn: $owner_urn})-[assertion:RELATION_ASSERTION {relation: $relation, tenant_id: $tenant_id, source_id: $source_id, runtime_id: $runtime_id}]->(other:Entity) RETURN other.urn AS urn ORDER BY other.urn`
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, map[string]any{
			"owner_urn": ownerURN, "relation": relation,
			"tenant_id": tenantID, "source_id": sourceID, "runtime_id": runtimeID,
		})
		if err != nil {
			return nil, err
		}
		urns := make([]string, 0)
		for result.Next(ctx) {
			urns = append(urns, stringValue(result.Record().Values[0]))
		}
		return urns, result.Err()
	})
	if err != nil {
		t.Fatalf("query link set assertion urns: %v", err)
	}
	urns, _ := values.([]string)
	return urns
}

func neo4jEntityExists(t *testing.T, ctx context.Context, store *Store, urn string) bool {
	t.Helper()
	value, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		return queryOneValue(ctx, tx, `MATCH (e:Entity {urn: $urn}) RETURN count(e)`, map[string]any{"urn": urn})
	})
	if err != nil {
		t.Fatalf("query entity existence: %v", err)
	}
	return toInt64(value) > 0
}

// TestNeo4jDockerProjectedLinkSetGuardedSemantics proves Contract C9's core
// guard through the real store: narrowing a set retracts only the dropped
// link, a stale observation can neither retract nor restore anything, an
// authoritative empty set clears the whole scope, another runtime's
// assertions on the exact same owner and relation are never touched, and a
// missing owner entity makes the whole set a safe no-op.
func TestNeo4jDockerProjectedLinkSetGuardedSemantics(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-linkset-guard-test-%d", time.Now().UnixNano())
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

	const tenantID = "writer"
	const sourceID = "vulnview"
	linkSet := func(ownerIndex int, runtimeID string, at string, consumers ...*ports.ProjectedEntity) *ports.ProjectedLinkSet {
		owner := linkSetOwnerRole(ownerIndex).URN
		links := make([]*ports.ProjectedLink, 0, len(consumers))
		for _, consumer := range consumers {
			links = append(links, &ports.ProjectedLink{
				TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
				FromURN: owner, ToURN: consumer.URN, Relation: "associated_with",
			})
		}
		return &ports.ProjectedLinkSet{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
			OwnerURN: owner, Relation: "associated_with", Outgoing: true,
			Links: links, Observation: map[string]string{"at": at},
		}
	}

	// Scenario 1: {A,B} -> {A} retracts only B.
	owner1 := linkSetOwnerRole(1)
	consumerA := linkSetConsumer(1, "a")
	consumerB := linkSetConsumer(1, "b")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner1, consumerA, consumerB}); err != nil {
		t.Fatalf("seed scenario 1 entities: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(1, "runtime-1", "2026-11-02T10:00:00Z", consumerA, consumerB),
	}); err != nil {
		t.Fatalf("scenario 1 initial set: %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner1.URN, "runtime-1"); len(urns) != 2 {
		t.Fatalf("scenario 1 initial assertions = %v, want A and B", urns)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(1, "runtime-1", "2026-11-02T10:05:00Z", consumerA),
	}); err != nil {
		t.Fatalf("scenario 1 narrowed set: %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner1.URN, "runtime-1"); len(urns) != 1 || urns[0] != consumerA.URN {
		t.Fatalf("scenario 1 narrowed assertions = %v, want only %q", urns, consumerA.URN)
	}

	// Scenario 2: a stale observation can neither retract an existing link
	// nor restore one a newer observation already dropped.
	owner2 := linkSetOwnerRole(2)
	consumerC := linkSetConsumer(2, "c")
	consumerD := linkSetConsumer(2, "d")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner2, consumerC, consumerD}); err != nil {
		t.Fatalf("seed scenario 2 entities: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(2, "runtime-2", "2026-11-02T10:00:00Z", consumerC),
	}); err != nil {
		t.Fatalf("scenario 2 initial set: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(2, "runtime-2", "2026-11-02T09:00:00Z"),
	}); err != nil {
		t.Fatalf("scenario 2 stale retract attempt: %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner2.URN, "runtime-2"); len(urns) != 1 || urns[0] != consumerC.URN {
		t.Fatalf("a stale observation retracted link C: %v", urns)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(2, "runtime-2", "2026-11-02T11:00:00Z"),
	}); err != nil {
		t.Fatalf("scenario 2 authoritative clear: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(2, "runtime-2", "2026-11-02T10:30:00Z", consumerD),
	}); err != nil {
		t.Fatalf("scenario 2 stale restore attempt: %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner2.URN, "runtime-2"); len(urns) != 0 {
		t.Fatalf("a stale observation restored link D: %v", urns)
	}

	// Scenario 3: applying a set for one runtime never touches another
	// runtime's assertions on the exact same owner and relation.
	owner3 := linkSetOwnerRole(3)
	consumerE := linkSetConsumer(3, "e")
	consumerF := linkSetConsumer(3, "f")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner3, consumerE, consumerF}); err != nil {
		t.Fatalf("seed scenario 3 entities: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(3, "runtime-3a", "2026-11-02T10:00:00Z", consumerE),
	}); err != nil {
		t.Fatalf("scenario 3 runtime-3a set: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{
		linkSet(3, "runtime-3b", "2026-11-02T10:00:00Z", consumerF),
	}); err != nil {
		t.Fatalf("scenario 3 runtime-3b set: %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner3.URN, "runtime-3a"); len(urns) != 1 || urns[0] != consumerE.URN {
		t.Fatalf("runtime-3a assertion was touched: %v", urns)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner3.URN, "runtime-3b"); len(urns) != 1 || urns[0] != consumerF.URN {
		t.Fatalf("runtime-3b assertion was touched: %v", urns)
	}

	// Scenario 4: a missing owner entity makes the whole set a no-op and
	// never auto-creates the owner.
	missingOwnerURN := "urn:cerebro:writer:aws_role:arn:aws:iam::222222222222:role/link-set-owner-missing"
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-4",
		OwnerURN: missingOwnerURN, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-4",
			FromURN: missingOwnerURN, ToURN: consumerE.URN, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}}); err != nil {
		t.Fatalf("scenario 4 missing owner set: %v", err)
	}
	if neo4jEntityExists(t, ctx, store, missingOwnerURN) {
		t.Fatal("a missing owner was auto-created by replacing a link set")
	}
}

// neo4jEntitySourceLabel returns one entity's (source_id, label) pair for
// assertions that a CreateOnly stub never overwrote a richer provider-owned
// entity sharing the same URN.
func neo4jEntitySourceLabel(t *testing.T, ctx context.Context, store *Store, urn string) (string, string) {
	t.Helper()
	values, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (e:Entity {urn: $urn}) RETURN e.source_id, e.label`, map[string]any{"urn": urn})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		recordValues := result.Record().Values
		return [2]string{stringValue(recordValues[0]), stringValue(recordValues[1])}, result.Err()
	})
	if err != nil {
		t.Fatalf("query entity source/label: %v", err)
	}
	pair, _ := values.([2]string)
	return pair[0], pair[1]
}

// TestNeo4jDockerProjectedLinkSetEndpointsGuardedMaterialization proves
// R06 through the real store: a stale or losing link-set observation must
// never materialize its Endpoints, an accepted observation still creates
// a genuinely missing endpoint, a provider-first entity sharing an
// endpoint's URN is left untouched, and later ordinary provider
// enrichment for that URN still applies normally afterward.
func TestNeo4jDockerProjectedLinkSetEndpointsGuardedMaterialization(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-linkset-endpoints-test-%d", time.Now().UnixNano())
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

	const tenantID, sourceID, relation = "writer", "vulnview", "associated_with"

	// Scenario 1 (v3-empty then stale v2{B}): v3's authoritative empty set
	// must leave the ordering guard advanced; a stale v2 replaying a
	// previously-absent consumer B must create neither B's entity nor its
	// link.
	owner1 := linkSetOwnerRole(10)
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner1}); err != nil {
		t.Fatalf("seed scenario 1 owner: %v", err)
	}
	consumerB := linkSetConsumer(10, "b")
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-10",
		OwnerURN: owner1.URN, Relation: relation, Outgoing: true,
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "3"},
	}}); err != nil {
		t.Fatalf("scenario 1 v3 empty: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-10",
		OwnerURN: owner1.URN, Relation: relation, Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-10",
			FromURN: owner1.URN, ToURN: consumerB.URN, Relation: relation,
		}},
		Endpoints:   []*ports.ProjectedEntity{{URN: consumerB.URN, TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-10", EntityType: "kubernetes_service_account", Label: "b", CreateOnly: true}},
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "2"},
	}}); err != nil {
		t.Fatalf("scenario 1 stale v2 with B: %v", err)
	}
	if neo4jEntityExists(t, ctx, store, consumerB.URN) {
		t.Fatal("a stale link-set replay materialized consumer B's entity")
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner1.URN, "runtime-10"); len(urns) != 0 {
		t.Fatalf("a stale link-set replay asserted B's link: %v", urns)
	}

	// Scenario 2 (v1{A} then v3-incomplete then stale v2{B}): v1 creates
	// A's endpoint and link; v3 is accepted but Incomplete (advances the
	// guard only); a reordered v2 naming new consumer B must be rejected
	// as stale, keeping A and creating neither B's entity nor its link.
	owner2 := linkSetOwnerRole(11)
	consumerA := linkSetConsumer(11, "a")
	consumerB2 := linkSetConsumer(11, "b")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner2}); err != nil {
		t.Fatalf("seed scenario 2 owner: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11",
		OwnerURN: owner2.URN, Relation: relation, Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11",
			FromURN: owner2.URN, ToURN: consumerA.URN, Relation: relation,
		}},
		Endpoints:   []*ports.ProjectedEntity{{URN: consumerA.URN, TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11", EntityType: "kubernetes_service_account", Label: "a", CreateOnly: true}},
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "1"},
	}}); err != nil {
		t.Fatalf("scenario 2 v1 with A: %v", err)
	}
	if !neo4jEntityExists(t, ctx, store, consumerA.URN) {
		t.Fatal("v1 did not create consumer A's endpoint")
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11",
		OwnerURN: owner2.URN, Relation: relation, Outgoing: true,
		Incomplete:  true,
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "3"},
	}}); err != nil {
		t.Fatalf("scenario 2 v3 incomplete: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11",
		OwnerURN: owner2.URN, Relation: relation, Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11",
			FromURN: owner2.URN, ToURN: consumerB2.URN, Relation: relation,
		}},
		Endpoints:   []*ports.ProjectedEntity{{URN: consumerB2.URN, TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-11", EntityType: "kubernetes_service_account", Label: "b", CreateOnly: true}},
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "2"},
	}}); err != nil {
		t.Fatalf("scenario 2 stale v2 with B: %v", err)
	}
	if neo4jEntityExists(t, ctx, store, consumerB2.URN) {
		t.Fatal("a stale link-set replay materialized consumer B's entity after an accepted Incomplete observation")
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner2.URN, "runtime-11"); len(urns) != 1 || urns[0] != consumerA.URN {
		t.Fatalf("scenario 2 final assertions = %v, want only A to survive", urns)
	}

	// Scenario 3: an accepted set still creates a genuinely missing
	// endpoint; a provider-first entity sharing an endpoint's URN is
	// never touched by the CreateOnly stub; later ordinary provider
	// enrichment for that URN still applies normally afterward.
	owner3 := linkSetOwnerRole(12)
	providerOwned := linkSetConsumer(12, "provider-owned")
	missingEndpoint := linkSetConsumer(12, "missing")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{
		owner3,
		{URN: providerOwned.URN, TenantID: tenantID, SourceID: "kubernetes", EntityType: "kubernetes_service_account", Label: "provider-label", Attributes: map[string]string{"owner": "platform-team"}},
	}); err != nil {
		t.Fatalf("seed scenario 3 owner/provider entity: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-12",
		OwnerURN: owner3.URN, Relation: relation, Outgoing: true,
		Links: []*ports.ProjectedLink{
			{TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-12", FromURN: owner3.URN, ToURN: providerOwned.URN, Relation: relation},
			{TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-12", FromURN: owner3.URN, ToURN: missingEndpoint.URN, Relation: relation},
		},
		Endpoints: []*ports.ProjectedEntity{
			{URN: providerOwned.URN, TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-12", EntityType: "kubernetes_service_account", Label: "stub-label", CreateOnly: true},
			{URN: missingEndpoint.URN, TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-12", EntityType: "kubernetes_service_account", Label: "missing-stub", CreateOnly: true},
		},
		Observation: map[string]string{"observation_precedence": "strict", "observation_version": "1"},
	}}); err != nil {
		t.Fatalf("scenario 3 accepted set: %v", err)
	}
	if !neo4jEntityExists(t, ctx, store, missingEndpoint.URN) {
		t.Fatal("an accepted observation did not create its genuinely missing endpoint")
	}
	if source, label := neo4jEntitySourceLabel(t, ctx, store, providerOwned.URN); source != "kubernetes" || label != "provider-label" {
		t.Fatalf("provider-owned entity was touched by the CreateOnly stub: source=%q label=%q", source, label)
	}
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: missingEndpoint.URN, TenantID: tenantID, SourceID: "kubernetes", EntityType: "kubernetes_service_account",
		Label: "enriched-label", Attributes: map[string]string{"owner": "platform-team"},
	}); err != nil {
		t.Fatalf("enrich stub entity: %v", err)
	}
	if source, label := neo4jEntitySourceLabel(t, ctx, store, missingEndpoint.URN); source != "kubernetes" || label != "enriched-label" {
		t.Fatalf("later provider enrichment did not apply: source=%q label=%q", source, label)
	}
}

// TestNeo4jDockerProjectedLinkSetReconcilesLogicalLinkOnRetraction proves
// that retracting a link set's assertion correctly rehydrates (or removes)
// the shared logical RELATION edge, matching the recency rule every other
// retraction path in this store already uses.
func TestNeo4jDockerProjectedLinkSetReconcilesLogicalLinkOnRetraction(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-linkset-reconcile-test-%d", time.Now().UnixNano())
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

	owner := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:aws_role:arn:aws:iam::333333333333:role/link-set-reconcile", TenantID: "writer",
		SourceID: "vulnview", EntityType: "aws_role", Label: "link-set-reconcile",
	}
	consumer := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:kubernetes_service_account:333333333333:prod:default:reconcile-consumer", TenantID: "writer",
		SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "reconcile-consumer",
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner, consumer}); err != nil {
		t.Fatalf("seed entities: %v", err)
	}

	// The link set is the first (and only) writer, so it owns the logical edge.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "vulnview-runtime",
		OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: "vulnview-runtime",
			FromURN: owner.URN, ToURN: consumer.URN, Relation: "associated_with",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}}); err != nil {
		t.Fatalf("initial link set: %v", err)
	}
	edge := &ports.ProjectedLink{FromURN: owner.URN, ToURN: consumer.URN, Relation: "associated_with"}
	if provenance := projectedLinkTypedProvenance(t, ctx, store, edge); provenance.sourceID != "vulnview" || provenance.runtimeID != "vulnview-runtime" {
		t.Fatalf("logical edge owner = %#v, want vulnview/vulnview-runtime", provenance)
	}

	// A different source asserts the exact same logical edge with a newer
	// observation and becomes the new logical owner.
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: "writer", SourceID: "aws-exposure", RuntimeID: "aws-exposure-runtime",
		FromURN: owner.URN, ToURN: consumer.URN, Relation: "associated_with",
		Attributes: map[string]string{"at": "2026-11-02T11:00:00Z"},
	}); err != nil {
		t.Fatalf("competing source upsert: %v", err)
	}
	if provenance := projectedLinkTypedProvenance(t, ctx, store, edge); provenance.sourceID != "aws-exposure" {
		t.Fatalf("logical edge owner after competing upsert = %#v, want aws-exposure", provenance)
	}

	// Retracting the link set down to empty removes vulnview's assertion;
	// the logical edge must survive on the surviving aws-exposure assertion
	// rather than being deleted.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: "writer", SourceID: "vulnview", RuntimeID: "vulnview-runtime",
		OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
		Links: nil, Observation: map[string]string{"at": "2026-11-02T12:00:00Z"},
	}}); err != nil {
		t.Fatalf("retracting link set: %v", err)
	}
	if !neo4jProjectedLinkExists(t, ctx, store, edge) {
		t.Fatal("logical edge was deleted; it must survive on the surviving aws-exposure assertion")
	}
	if provenance := projectedLinkTypedProvenance(t, ctx, store, edge); provenance.sourceID != "aws-exposure" || provenance.runtimeID != "aws-exposure-runtime" {
		t.Fatalf("logical edge owner after link-set retraction = %#v, want aws-exposure/aws-exposure-runtime unchanged", provenance)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, "vulnview-runtime"); len(urns) != 0 {
		t.Fatalf("vulnview's assertion survived retraction: %v", urns)
	}
}

// TestNeo4jDockerProjectedLinkSetConcurrentRacingWritesConverge proves the
// guarded transaction's optimistic retry loop serializes concurrent
// writers on one owner/relation/direction/runtime scope: whichever writer
// carries the newest observation deterministically wins regardless of
// goroutine scheduling, and no other writer's distinguishing link survives.
func TestNeo4jDockerProjectedLinkSetConcurrentRacingWritesConverge(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-linkset-race-test-%d", time.Now().UnixNano())
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

	owner := &ports.ProjectedEntity{
		URN: "urn:cerebro:writer:aws_role:arn:aws:iam::444444444444:role/link-set-race", TenantID: "writer",
		SourceID: "vulnview", EntityType: "aws_role", Label: "link-set-race",
	}
	const writers = 3
	entities := []*ports.ProjectedEntity{owner}
	consumers := make([]*ports.ProjectedEntity, writers)
	for index := range writers {
		consumers[index] = &ports.ProjectedEntity{
			URN:      fmt.Sprintf("urn:cerebro:writer:kubernetes_service_account:444444444444:prod:default:race-consumer-%d", index),
			TenantID: "writer", SourceID: "vulnview", EntityType: "kubernetes_service_account",
			Label: fmt.Sprintf("race-consumer-%d", index),
		}
		entities = append(entities, consumers[index])
	}
	if err := store.UpsertProjectedEntities(ctx, entities); err != nil {
		t.Fatalf("seed race entities: %v", err)
	}

	base := time.Date(2026, time.November, 2, 10, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for index := range writers {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			at := base.Add(time.Duration(index) * time.Minute).Format(time.RFC3339)
			errs[index] = store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
				TenantID: "writer", SourceID: "vulnview", RuntimeID: "race-runtime",
				OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
				Links: []*ports.ProjectedLink{{
					TenantID: "writer", SourceID: "vulnview", RuntimeID: "race-runtime",
					FromURN: owner.URN, ToURN: consumers[index].URN, Relation: "associated_with",
				}},
				Observation: map[string]string{"at": at},
			}})
		}(index)
	}
	wg.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("concurrent writer %d error = %v", index, err)
		}
	}
	urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, "race-runtime")
	if len(urns) != 1 || urns[0] != consumers[writers-1].URN {
		t.Fatalf("after concurrent racing writes, assertions = %v, want only the newest writer's link %q", urns, consumers[writers-1].URN)
	}
}

// TestNeo4jDockerProjectedEntityCreateOnlyMaterialization proves Contract
// G1's CreateOnly endpoint stub semantics against a real Neo4j instance:
// a provider-owned principal is never overwritten by a later stub
// (regardless of an unrelated application-workspace mismatch, which must
// not surface as ErrApplicationWorkspaceConflict either), repeated stub
// imports stay no-ops, a stub-first materialization is later enriched
// normally by the real provider connector, and the batched path coalesces
// a mixed ordinary/stub batch identically to the single-item path
// regardless of array order.
func TestNeo4jDockerProjectedEntityCreateOnlyMaterialization(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-create-only-test-%d", time.Now().UnixNano())
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

	applicationWorkspaceID := func(t *testing.T, urn string) string {
		t.Helper()
		value, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			return queryOneValue(ctx, tx, "MATCH (e:Entity {urn: $urn}) RETURN coalesce(e.application_workspace_id, '')", map[string]any{"urn": urn})
		})
		if err != nil {
			t.Fatalf("query application workspace id: %v", err)
		}
		return stringValue(value)
	}

	// Provider-first then stub: the stub must leave typed ownership, label,
	// attributes, and an unrelated application-workspace mismatch entirely
	// unchanged, and must not surface ErrApplicationWorkspaceConflict.
	providerOwned := &ports.ProjectedEntity{
		URN:      "urn:cerebro:writer:gcp_service_account:projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com",
		TenantID: "writer", ApplicationWorkspaceID: "workspace-a", SourceID: "gcp", RuntimeID: "writer-gcp",
		EntityType: "gcp_service_account", Label: "sa@p.iam.gserviceaccount.com",
		Attributes: map[string]string{"project_id": "p", "disabled": "false"},
	}
	if err := store.UpsertProjectedEntity(ctx, providerOwned); err != nil {
		t.Fatalf("seed provider entity: %v", err)
	}
	stub := &ports.ProjectedEntity{
		URN: providerOwned.URN, TenantID: "writer", ApplicationWorkspaceID: "workspace-b",
		SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "gcp_service_account", Label: providerOwned.URN,
		CreateOnly: true,
	}
	if err := store.UpsertProjectedEntity(ctx, stub); err != nil {
		t.Fatalf("UpsertProjectedEntity(stub over provider) error = %v, want success (not a workspace conflict)", err)
	}
	owner := projectedEntityTypedOwner(t, ctx, store, providerOwned.URN)
	attrs := projectedEntityAttributes(t, ctx, store, providerOwned.URN)
	if owner.sourceID != "gcp" || owner.runtimeID != "writer-gcp" || owner.label != providerOwned.Label || attrs["project_id"] != "p" || attrs["disabled"] != "false" {
		t.Fatalf("stub over provider changed owned facts: owner=%#v attrs=%#v", owner, attrs)
	}
	if got := applicationWorkspaceID(t, providerOwned.URN); got != "workspace-a" {
		t.Fatalf("stub changed application_workspace_id = %q, want unchanged %q", got, "workspace-a")
	}

	// Repeated stub imports must stay no-ops.
	for i := range 2 {
		if err := store.UpsertProjectedEntity(ctx, stub); err != nil {
			t.Fatalf("UpsertProjectedEntity(repeated stub %d) error = %v", i, err)
		}
	}
	owner = projectedEntityTypedOwner(t, ctx, store, providerOwned.URN)
	if owner.sourceID != "gcp" || owner.runtimeID != "writer-gcp" {
		t.Fatalf("repeated stub imports changed owned facts: owner=%#v", owner)
	}

	// Stub-first materializes a fresh principal (create-if-absent), and a
	// later provider upsert enriches it normally afterward.
	const freshURN = "urn:cerebro:writer:aws_role:arn:aws:iam::555555555555:role/stub-first"
	freshStub := &ports.ProjectedEntity{
		URN: freshURN, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "aws_role", Label: freshURN, CreateOnly: true,
	}
	if err := store.UpsertProjectedEntity(ctx, freshStub); err != nil {
		t.Fatalf("UpsertProjectedEntity(stub-first create) error = %v", err)
	}
	if !neo4jEntityExists(t, ctx, store, freshURN) {
		t.Fatal("CreateOnly stub did not materialize an absent entity")
	}
	freshProvider := &ports.ProjectedEntity{
		URN: freshURN, TenantID: "writer", SourceID: "aws", RuntimeID: "writer-aws",
		EntityType: "aws_role", Label: "arn:aws:iam::555555555555:role/stub-first",
		Attributes: map[string]string{"account_id": "555555555555"},
	}
	if err := store.UpsertProjectedEntity(ctx, freshProvider); err != nil {
		t.Fatalf("UpsertProjectedEntity(provider enrichment) error = %v", err)
	}
	owner = projectedEntityTypedOwner(t, ctx, store, freshURN)
	attrs = projectedEntityAttributes(t, ctx, store, freshURN)
	if owner.sourceID != "aws" || owner.label != freshProvider.Label || attrs["account_id"] != "555555555555" {
		t.Fatalf("provider enrichment after stub-first did not apply: owner=%#v attrs=%#v", owner, attrs)
	}

	// Coalesced batches: a single UpsertProjectedEntities call carrying
	// both an ordinary entity and a CreateOnly stub for the same brand-new
	// URN must behave identically to the single-item path, regardless of
	// array order.
	for _, name := range []string{"ordinary-then-stub", "stub-then-ordinary"} {
		t.Run(name, func(t *testing.T) {
			urn := fmt.Sprintf("urn:cerebro:writer:aws_role:arn:aws:iam::555555555555:role/batch-%s", name)
			ordinary := &ports.ProjectedEntity{
				URN: urn, TenantID: "writer", SourceID: "aws", RuntimeID: "writer-aws",
				EntityType: "aws_role", Label: "batch-ordinary-" + name,
				Attributes: map[string]string{"account_id": "555555555555"},
			}
			batchStub := &ports.ProjectedEntity{
				URN: urn, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
				EntityType: "aws_role", Label: urn, CreateOnly: true,
			}
			entities := []*ports.ProjectedEntity{ordinary, batchStub}
			if name == "stub-then-ordinary" {
				entities = []*ports.ProjectedEntity{batchStub, ordinary}
			}
			if err := store.UpsertProjectedEntities(ctx, entities); err != nil {
				t.Fatalf("UpsertProjectedEntities() error = %v", err)
			}
			owner := projectedEntityTypedOwner(t, ctx, store, urn)
			attrs := projectedEntityAttributes(t, ctx, store, urn)
			if owner.sourceID != "aws" || owner.label != ordinary.Label || attrs["account_id"] != "555555555555" {
				t.Fatalf("batch coalescing (%s) = owner %#v attrs %#v, want the ordinary entity to win", name, owner, attrs)
			}
		})
	}
}

// TestNeo4jDockerProjectedEntityAcceptedObservationClearsRetractedAttributes
// proves Contract G1's RetractedAttributes semantics against a real Neo4j
// instance: an accepted newer strict observation removes the owned keys it
// no longer carries (clearing obsolete triage fields on a reopened
// finding) while preserving unrelated attributes, a stale strict replay's
// own retraction attempt changes nothing at all, and the batch path
// behaves identically to the single-item path.
func TestNeo4jDockerProjectedEntityAcceptedObservationClearsRetractedAttributes(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-retraction-test-%d", time.Now().UnixNano())
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

	nov1 := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	nov2 := time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

	const findingURN = "urn:cerebro:writer:vulnview_finding:666666666666:f-1"
	v1 := &ports.ProjectedEntity{
		URN: findingURN, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "vulnview_finding", Label: "f-1",
		Attributes: map[string]string{
			"at": nov1, "observation_precedence": "strict", "observation_version": "1",
			"triage_state": "accepted", "triage_reason": "reviewed", "status": "open",
		},
	}
	if err := store.UpsertProjectedEntity(ctx, v1); err != nil {
		t.Fatalf("UpsertProjectedEntity(v1) error = %v", err)
	}
	v2 := &ports.ProjectedEntity{
		URN: findingURN, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "vulnview_finding", Label: "f-1",
		Attributes: map[string]string{
			"at": nov2, "observation_precedence": "strict", "observation_version": "2",
			"triage_state": "none", "status": "open",
		},
		RetractedAttributes: []string{"triage_reason"},
	}
	if err := store.UpsertProjectedEntity(ctx, v2); err != nil {
		t.Fatalf("UpsertProjectedEntity(v2) error = %v", err)
	}
	attrs := projectedEntityAttributes(t, ctx, store, findingURN)
	if _, present := attrs["triage_reason"]; present {
		t.Fatalf("accepted retraction did not remove triage_reason: %#v", attrs)
	}
	if attrs["triage_state"] != "none" || attrs["status"] != "open" {
		t.Fatalf("accepted v2 attributes = %#v, want triage_state=none and status preserved", attrs)
	}

	// A stale strict replay that also attempts to retract `status` must
	// change nothing at all, including the retraction.
	staleReplay := &ports.ProjectedEntity{
		URN: findingURN, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "vulnview_finding", Label: "f-1",
		Attributes: map[string]string{
			"at": nov1, "observation_precedence": "strict", "observation_version": "1",
			"triage_state": "accepted", "triage_reason": "reviewed", "status": "open",
		},
		RetractedAttributes: []string{"status"},
	}
	if err := store.UpsertProjectedEntity(ctx, staleReplay); err != nil {
		t.Fatalf("UpsertProjectedEntity(stale replay) error = %v", err)
	}
	attrs = projectedEntityAttributes(t, ctx, store, findingURN)
	if attrs["triage_state"] != "none" || attrs["status"] != "open" {
		t.Fatalf("stale strict replay changed attributes: %#v, want unchanged (triage_state=none status=open)", attrs)
	}
	if _, present := attrs["triage_reason"]; present {
		t.Fatalf("stale strict replay resurrected triage_reason: %#v", attrs)
	}

	// Batch path parity: a fresh finding goes through the same v1 -> v2
	// retraction sequence via UpsertProjectedEntities.
	const batchFindingURN = "urn:cerebro:writer:vulnview_finding:666666666666:f-2"
	batchV1 := &ports.ProjectedEntity{
		URN: batchFindingURN, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "vulnview_finding", Label: "f-2",
		Attributes: map[string]string{
			"at": nov1, "observation_precedence": "strict", "observation_version": "1",
			"triage_state": "false_positive", "triage_by": "alice", "status": "open",
		},
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{batchV1}); err != nil {
		t.Fatalf("UpsertProjectedEntities(v1) error = %v", err)
	}
	batchV2 := &ports.ProjectedEntity{
		URN: batchFindingURN, TenantID: "writer", SourceID: "vulnview", RuntimeID: "writer-vulnview",
		EntityType: "vulnview_finding", Label: "f-2",
		Attributes: map[string]string{
			"at": nov2, "observation_precedence": "strict", "observation_version": "2",
			"triage_state": "none", "status": "open",
		},
		RetractedAttributes: []string{"triage_by"},
	}
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{batchV2}); err != nil {
		t.Fatalf("UpsertProjectedEntities(v2) error = %v", err)
	}
	attrs = projectedEntityAttributes(t, ctx, store, batchFindingURN)
	if _, present := attrs["triage_by"]; present {
		t.Fatalf("batch-path accepted retraction did not remove triage_by: %#v", attrs)
	}
	if attrs["triage_state"] != "none" || attrs["status"] != "open" {
		t.Fatalf("batch-path v2 attributes = %#v, want triage_state=none and status preserved", attrs)
	}
}

// TestNeo4jDockerProjectedLinkSetIncompleteAdvancesGuardWithoutMutatingLinks
// reproduces F04's exact regression against a real Neo4j instance: v1 {A}
// -> v3 Incomplete -> a replayed v2 {B} must keep {A}, because the
// Incomplete v3 observation advances the scope's ordering guard even
// though it carries no links, so the older v2 can no longer replace
// anything once v3 is accepted. An Incomplete set carrying links is
// rejected, and a later authoritative empty set still clears the scope
// normally.
func TestNeo4jDockerProjectedLinkSetIncompleteAdvancesGuardWithoutMutatingLinks(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-incomplete-test-%d", time.Now().UnixNano())
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

	owner := linkSetOwnerRole(900)
	consumerA := linkSetConsumer(900, "a")
	consumerB := linkSetConsumer(900, "b")
	if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner, consumerA, consumerB}); err != nil {
		t.Fatalf("seed entities: %v", err)
	}
	const runtimeID = "writer-vulnview"
	t1 := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	t2 := time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	t3 := time.Date(2026, time.November, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	t4 := time.Date(2026, time.November, 4, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

	setWith := func(at string, consumers ...*ports.ProjectedEntity) *ports.ProjectedLinkSet {
		links := make([]*ports.ProjectedLink, 0, len(consumers))
		for _, consumer := range consumers {
			links = append(links, &ports.ProjectedLink{
				TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
				FromURN: owner.URN, ToURN: consumer.URN, Relation: "associated_with",
			})
		}
		return &ports.ProjectedLinkSet{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
			Links: links, Observation: map[string]string{"at": at},
		}
	}

	// v1: complete set {A}.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{setWith(t1, consumerA)}); err != nil {
		t.Fatalf("ReplaceProjectedLinkSets(v1) error = %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, runtimeID); len(urns) != 1 || urns[0] != consumerA.URN {
		t.Fatalf("after v1, assertions = %v, want {A}", urns)
	}

	// v3: Incomplete, no links. Must advance the guard without touching {A}.
	incomplete := setWith(t3)
	incomplete.Incomplete = true
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{incomplete}); err != nil {
		t.Fatalf("ReplaceProjectedLinkSets(v3 incomplete) error = %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, runtimeID); len(urns) != 1 || urns[0] != consumerA.URN {
		t.Fatalf("after incomplete v3, assertions = %v, want {A} untouched", urns)
	}

	// Replayed v2 {B} is now stale relative to v3's guard and must be a
	// complete no-op: {A} must survive, not be replaced by {B}.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{setWith(t2, consumerB)}); err != nil {
		t.Fatalf("ReplaceProjectedLinkSets(replayed v2) error = %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, runtimeID); len(urns) != 1 || urns[0] != consumerA.URN {
		t.Fatalf("after replayed v2 {B}, assertions = %v, want {A} to survive (F04 regression)", urns)
	}

	// An Incomplete set must reject carrying links.
	rejected := setWith(t3, consumerB)
	rejected.Incomplete = true
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{rejected}); err == nil {
		t.Fatal("ReplaceProjectedLinkSets(incomplete with links) error = nil, want rejection")
	}

	// A later authoritative empty set still clears the scope normally.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{setWith(t4)}); err != nil {
		t.Fatalf("ReplaceProjectedLinkSets(authoritative empty v4) error = %v", err)
	}
	if urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, runtimeID); len(urns) != 0 {
		t.Fatalf("after authoritative empty v4, assertions = %v, want none", urns)
	}
}

// linkSetObservationMarkerCount counts LINK_SET_OBSERVATION self-loop
// markers on one entity, so F11 tests can prove cleanup/delete removes
// them exactly when it removes the entity itself.
func linkSetObservationMarkerCount(t *testing.T, ctx context.Context, store *Store, urn string) int64 {
	t.Helper()
	value, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		return queryOneValue(ctx, tx, `MATCH (e:Entity {urn: $urn})-[o:LINK_SET_OBSERVATION]->(e) RETURN count(o)`, map[string]any{"urn": urn})
	})
	if err != nil {
		t.Fatalf("query link set observation marker count: %v", err)
	}
	return toInt64(value)
}

// TestNeo4jDockerCleanupAndDeleteRemoveLinkSetObservationMarkers proves F11
// against a real Neo4j instance: an authoritative empty link set leaves a
// LINK_SET_OBSERVATION self-loop marker on its owner even though no
// RELATION or RELATION_ASSERTION references the owner anymore. Before the
// fix, DeleteProjectedEntity/DeleteProjectedEntities/CleanupProjectedEntities
// all failed on real Neo4j with the remaining-relationships constraint
// error on that owner. The fix deletes the marker together with the
// entity (never with DETACH DELETE), never deletes an entity that still
// has a RELATION or RELATION_ASSERTION, never deletes an entity another
// source/runtime still legitimately references, and is idempotent.
func TestNeo4jDockerCleanupAndDeleteRemoveLinkSetObservationMarkers(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-cleanup-markers-test-%d", time.Now().UnixNano())
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
	const runtimeID = "writer-vulnview"

	t.Run("DeleteProjectedEntity", func(t *testing.T) {
		owner := linkSetOwnerRole(700)
		consumer := linkSetConsumer(700, "a")
		if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner, consumer}); err != nil {
			t.Fatalf("seed entities: %v", err)
		}
		set := &ports.ProjectedLinkSet{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
			Links: []*ports.ProjectedLink{{
				TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
				FromURN: owner.URN, ToURN: consumer.URN, Relation: "associated_with",
			}},
			Observation: map[string]string{"at": "2026-11-01T10:00:00Z"},
		}
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{set}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(initial) error = %v", err)
		}
		empty := &ports.ProjectedLinkSet{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{empty}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(empty) error = %v", err)
		}
		if urns := linkSetAssertionOtherURNs(t, ctx, store, owner.URN, runtimeID); len(urns) != 0 {
			t.Fatalf("assertions after empty set = %v, want none", urns)
		}
		if linkSetObservationMarkerCount(t, ctx, store, owner.URN) != 1 {
			t.Fatal("expected a LINK_SET_OBSERVATION marker to remain on the owner")
		}
		if err := store.DeleteProjectedEntity(ctx, owner.URN); err != nil {
			t.Fatalf("DeleteProjectedEntity() error = %v, want success despite the remaining marker", err)
		}
		if neo4jEntityExists(t, ctx, store, owner.URN) {
			t.Fatal("owner entity survived DeleteProjectedEntity()")
		}
		if err := store.DeleteProjectedEntity(ctx, owner.URN); err != nil {
			t.Fatalf("DeleteProjectedEntity() repeated call error = %v, want idempotent no-op", err)
		}
		if err := store.DeleteProjectedEntity(ctx, consumer.URN); err != nil {
			t.Fatalf("DeleteProjectedEntity(consumer) error = %v", err)
		}
	})

	t.Run("DeleteProjectedEntities batch and non-isolated survival", func(t *testing.T) {
		ownerEmpty := linkSetOwnerRole(701)
		ownerShared := linkSetOwnerRole(702)
		consumer := linkSetConsumer(701, "a")
		if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{ownerEmpty, ownerShared, consumer}); err != nil {
			t.Fatalf("seed entities: %v", err)
		}
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: ownerEmpty.URN, Relation: "associated_with", Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID, FromURN: ownerEmpty.URN, ToURN: consumer.URN, Relation: "associated_with"}},
			Observation: map[string]string{"at": "2026-11-01T10:00:00Z"},
		}}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(ownerEmpty initial) error = %v", err)
		}
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: ownerEmpty.URN, Relation: "associated_with", Outgoing: true,
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(ownerEmpty clear) error = %v", err)
		}
		// ownerShared asserts the SAME consumer, which must survive the
		// batch delete even though ownerEmpty no longer references it.
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: ownerShared.URN, Relation: "associated_with", Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID, FromURN: ownerShared.URN, ToURN: consumer.URN, Relation: "associated_with"}},
			Observation: map[string]string{"at": "2026-11-01T10:00:00Z"},
		}}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(ownerShared) error = %v", err)
		}
		if linkSetObservationMarkerCount(t, ctx, store, ownerEmpty.URN) != 1 {
			t.Fatal("expected a marker on ownerEmpty before batch delete")
		}
		if err := store.DeleteProjectedEntities(ctx, []string{ownerEmpty.URN, consumer.URN}); err != nil {
			t.Fatalf("DeleteProjectedEntities() error = %v", err)
		}
		if neo4jEntityExists(t, ctx, store, ownerEmpty.URN) {
			t.Fatal("ownerEmpty survived DeleteProjectedEntities()")
		}
		if !neo4jEntityExists(t, ctx, store, consumer.URN) {
			t.Fatal("consumer was deleted even though ownerShared still asserts it")
		}
		if urns := linkSetAssertionOtherURNs(t, ctx, store, ownerShared.URN, runtimeID); len(urns) != 1 || urns[0] != consumer.URN {
			t.Fatalf("ownerShared's assertion of consumer did not survive: %v", urns)
		}
		if err := store.DeleteProjectedEntities(ctx, []string{ownerEmpty.URN}); err != nil {
			t.Fatalf("DeleteProjectedEntities() repeated call error = %v, want idempotent no-op", err)
		}
	})

	t.Run("CleanupProjectedEntities dry run and real cleanup", func(t *testing.T) {
		owner := linkSetOwnerRole(703)
		consumer := linkSetConsumer(703, "a")
		if err := store.UpsertProjectedEntities(ctx, []*ports.ProjectedEntity{owner, consumer}); err != nil {
			t.Fatalf("seed entities: %v", err)
		}
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID, FromURN: owner.URN, ToURN: consumer.URN, Relation: "associated_with"}},
			Observation: map[string]string{"at": "2026-11-01T10:00:00Z"},
		}}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(initial) error = %v", err)
		}
		if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: "writer", SourceID: "vulnview", RuntimeID: runtimeID,
			OwnerURN: owner.URN, Relation: "associated_with", Outgoing: true,
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}}); err != nil {
			t.Fatalf("ReplaceProjectedLinkSets(empty) error = %v", err)
		}

		request := ports.ProjectionCleanupRequest{
			TenantID: "writer", SourceID: "vulnview",
			URNPrefixes: []string{owner.URN}, OnlyIsolated: true, DryRun: true,
		}
		dryRun, err := store.CleanupProjectedEntities(ctx, request)
		if err != nil {
			t.Fatalf("CleanupProjectedEntities(dry run) error = %v", err)
		}
		if dryRun.EntitiesMatched != 1 {
			t.Fatalf("dry run EntitiesMatched = %d, want 1 (marker-only owner counts as isolated)", dryRun.EntitiesMatched)
		}
		if dryRun.EntitiesDeleted != 0 {
			t.Fatalf("dry run EntitiesDeleted = %d, want 0 (dry run must not mutate)", dryRun.EntitiesDeleted)
		}
		if !neo4jEntityExists(t, ctx, store, owner.URN) {
			t.Fatal("dry run deleted the owner entity")
		}

		request.DryRun = false
		result, err := store.CleanupProjectedEntities(ctx, request)
		if err != nil {
			t.Fatalf("CleanupProjectedEntities() error = %v, want success despite the remaining marker", err)
		}
		if result.EntitiesMatched != 1 || result.EntitiesDeleted != 1 {
			t.Fatalf("cleanup result = %#v, want 1 matched and 1 deleted", result)
		}
		if neo4jEntityExists(t, ctx, store, owner.URN) {
			t.Fatal("owner survived CleanupProjectedEntities()")
		}
		if linkSetObservationMarkerCount(t, ctx, store, owner.URN) != 0 {
			t.Fatal("marker survived owner deletion")
		}

		repeated, err := store.CleanupProjectedEntities(ctx, request)
		if err != nil {
			t.Fatalf("CleanupProjectedEntities() repeated call error = %v", err)
		}
		if repeated.EntitiesMatched != 0 || repeated.EntitiesDeleted != 0 {
			t.Fatalf("repeated cleanup result = %#v, want all zero (idempotent)", repeated)
		}
	})
}
