package main

// TestVulnViewLegacyGraphStateCloseoutIntegration exercises the F14 legacy
// closeout procedure documented in docs/runbooks (private deploy repo) and
// infra/aws/Pulumi.go-prod.yaml: a scoped, idempotent
// graph.cleanupProjectedEntities pass (the same facility the CLI's
// `graph cleanup-projected-entities` subcommand exposes) that retires the
// old live `writer-vulnview-vulnerability`/`writer-vulnview-dns-alert`
// per-runtime graph state left over from before the VulnView standardized
// finding-export cutover, while preserving:
//   - the `external.asset` entity also asserted by the still-active
//     `writer-vulnview-asset` runtime (overlapping ownership),
//   - new-runtime backfill (`vulnview.finding` entities from the
//     findingId-identity standardized export, a different runtime),
//   - a completely unrelated source/runtime's state.
//
// It seeds synthetic pre-cutover graph state directly through the
// ProjectionStateStore/ProjectionGraphStore ports (bypassing the retired
// vulnerability/dns_alert source connectors, which this cutover removed),
// then runs the scoped cleanup dry-run, apply, and a repeat apply to prove
// idempotency, against real local Neo4j and Postgres containers.

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	graphstoreneo4j "github.com/writer/cerebro/internal/graphstore/neo4j"
	"github.com/writer/cerebro/internal/ports"
	statestorepostgres "github.com/writer/cerebro/internal/statestore/postgres"
)

func TestVulnViewLegacyGraphStateCloseoutIntegration(t *testing.T) {
	neo4jURI, cleanupNeo4j := requireDockerNeo4jForLegacyCloseoutTest(t)
	defer cleanupNeo4j()
	pgDSN := requirePostgresDSNForLegacyCloseoutTest(t)

	ctx := context.Background()
	graphStore, err := graphstoreneo4j.Open(config.GraphStoreConfig{
		Neo4jURI:      neo4jURI,
		Neo4jUsername: "neo4j",
		Neo4jPassword: "legacy-closeout-test-password",
	})
	if err != nil {
		t.Fatalf("open neo4j store: %v", err)
	}
	defer func() { _ = graphStore.CloseContext(context.Background()) }()

	stateStore, err := statestorepostgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: pgDSN,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer func() { _ = stateStore.Close() }()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("r-postgresstore-%d", nonce)
	const (
		legacyVulnerabilityRuntime = "writer-vulnview-vulnerability"
		legacyDNSAlertRuntime      = "writer-vulnview-dns-alert"
		activeAssetRuntime         = "writer-vulnview-asset"
		newFindingRuntime          = "writer-vulnview-finding-nuclei"
		unrelatedRuntime           = "writer-github-audit"
	)

	assetURN := fmt.Sprintf("urn:cerebro:%s:external_asset:admin.writer.com", tenantID)
	legacyFindingURN := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:legacy-vuln-1", tenantID)
	legacyTemplateURN := fmt.Sprintf("urn:cerebro:%s:vulnview_template:legacy-template-1", tenantID)
	legacyAlertURN := fmt.Sprintf("urn:cerebro:%s:vulnview_dns_alert:legacy-alert-1", tenantID)
	legacyAlertTypeURN := fmt.Sprintf("urn:cerebro:%s:vulnview_dns_alert_type:legacy-type-1", tenantID)
	newFindingURN := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:cloud_identity|excess_privilege|aws|role-1", tenantID)
	unrelatedUserURN := fmt.Sprintf("urn:cerebro:%s:github_user:alice", tenantID)
	unrelatedRepoURN := fmt.Sprintf("urn:cerebro:%s:github_code_repository:writer/cerebro", tenantID)

	seedVulnViewLegacyCloseoutFixture(t, ctx, graphStore, stateStore, pgDSN, neo4jURI, "legacy-closeout-test-password", vulnViewLegacyCloseoutFixture{
		tenantID:                   tenantID,
		assetURN:                   assetURN,
		legacyFindingURN:           legacyFindingURN,
		legacyTemplateURN:          legacyTemplateURN,
		legacyAlertURN:             legacyAlertURN,
		legacyAlertTypeURN:         legacyAlertTypeURN,
		newFindingURN:              newFindingURN,
		unrelatedUserURN:           unrelatedUserURN,
		unrelatedRepoURN:           unrelatedRepoURN,
		legacyVulnerabilityRuntime: legacyVulnerabilityRuntime,
		legacyDNSAlertRuntime:      legacyDNSAlertRuntime,
		activeAssetRuntime:         activeAssetRuntime,
		newFindingRuntime:          newFindingRuntime,
		unrelatedRuntime:           unrelatedRuntime,
	})

	deps := bootstrap.Dependencies{StateStore: stateStore, GraphStore: graphStore}

	// --- Vulnerability-family closeout -------------------------------------------------
	vulnerabilityOptions := graphProjectedEntityCleanupOptions{
		TenantID:     tenantID,
		SourceID:     "vulnview",
		RuntimeID:    legacyVulnerabilityRuntime,
		EntityTypes:  []string{"vulnview.finding", "vulnview.template"},
		OnlyIsolated: false,
		AllowDetach:  true,
		Limit:        100,
		DryRun:       true,
	}
	dryRun, err := cleanupProjectedEntities(ctx, deps, vulnerabilityOptions)
	if err != nil {
		t.Fatalf("vulnerability dry-run cleanup error = %v", err)
	}
	if dryRun.GraphStore.EntitiesMatched != 2 {
		t.Fatalf("vulnerability dry-run GraphStore.EntitiesMatched = %d, want 2 (legacy finding + template)", dryRun.GraphStore.EntitiesMatched)
	}
	if dryRun.GraphStore.EntitiesDeleted != 0 || dryRun.StateStore.EntitiesDeleted != 0 {
		t.Fatalf("vulnerability dry-run mutated state: graph=%+v state=%+v", dryRun.GraphStore, dryRun.StateStore)
	}
	if !graphEntityExists(t, ctx, graphStore, legacyFindingURN) || !graphEntityExists(t, ctx, graphStore, legacyTemplateURN) {
		t.Fatal("vulnerability dry-run deleted legacy entities despite DryRun=true")
	}

	vulnerabilityOptions.DryRun = false
	applied, err := cleanupProjectedEntities(ctx, deps, vulnerabilityOptions)
	if err != nil {
		t.Fatalf("vulnerability apply cleanup error = %v", err)
	}
	if applied.GraphStore.EntitiesDeleted != 2 {
		t.Fatalf("vulnerability apply GraphStore.EntitiesDeleted = %d, want 2", applied.GraphStore.EntitiesDeleted)
	}
	if applied.StateStore.EntitiesDeleted != 2 {
		t.Fatalf("vulnerability apply StateStore.EntitiesDeleted = %d, want 2", applied.StateStore.EntitiesDeleted)
	}
	if graphEntityExists(t, ctx, graphStore, legacyFindingURN) || graphEntityExists(t, ctx, graphStore, legacyTemplateURN) {
		t.Fatal("vulnerability apply left legacy finding/template entities behind")
	}
	if stateEntityExists(t, ctx, stateStore, legacyFindingURN) || stateEntityExists(t, ctx, stateStore, legacyTemplateURN) {
		t.Fatal("vulnerability apply left legacy finding/template rows behind in Postgres")
	}

	// Shared asset (also owned by the still-active asset-family runtime),
	// new-runtime backfill, and unrelated state must all survive.
	if !graphEntityExists(t, ctx, graphStore, assetURN) {
		t.Fatal("vulnerability closeout deleted the shared external.asset entity")
	}
	if !graphEntityExists(t, ctx, graphStore, newFindingURN) {
		t.Fatal("vulnerability closeout deleted new-runtime backfilled finding")
	}
	if !graphEntityExists(t, ctx, graphStore, unrelatedUserURN) || !graphEntityExists(t, ctx, graphStore, unrelatedRepoURN) {
		t.Fatal("vulnerability closeout touched unrelated source/runtime state")
	}

	// Idempotent rerun: nothing left to match or delete.
	rerun, err := cleanupProjectedEntities(ctx, deps, vulnerabilityOptions)
	if err != nil {
		t.Fatalf("vulnerability idempotent rerun error = %v", err)
	}
	if rerun.GraphStore.EntitiesMatched != 0 || rerun.GraphStore.EntitiesDeleted != 0 {
		t.Fatalf("vulnerability idempotent rerun GraphStore = %+v, want all-zero", rerun.GraphStore)
	}
	if rerun.StateStore.EntitiesMatched != 0 || rerun.StateStore.EntitiesDeleted != 0 {
		t.Fatalf("vulnerability idempotent rerun StateStore = %+v, want all-zero", rerun.StateStore)
	}

	// --- DNS-alert-family closeout ------------------------------------------------------
	dnsAlertOptions := graphProjectedEntityCleanupOptions{
		TenantID:     tenantID,
		SourceID:     "vulnview",
		RuntimeID:    legacyDNSAlertRuntime,
		EntityTypes:  []string{"vulnview.dns_alert", "vulnview.dns_alert_type"},
		OnlyIsolated: false,
		AllowDetach:  true,
		Limit:        100,
		DryRun:       true,
	}
	dnsDryRun, err := cleanupProjectedEntities(ctx, deps, dnsAlertOptions)
	if err != nil {
		t.Fatalf("dns_alert dry-run cleanup error = %v", err)
	}
	if dnsDryRun.GraphStore.EntitiesMatched != 2 {
		t.Fatalf("dns_alert dry-run GraphStore.EntitiesMatched = %d, want 2 (legacy alert + alert type)", dnsDryRun.GraphStore.EntitiesMatched)
	}

	dnsAlertOptions.DryRun = false
	dnsApplied, err := cleanupProjectedEntities(ctx, deps, dnsAlertOptions)
	if err != nil {
		t.Fatalf("dns_alert apply cleanup error = %v", err)
	}
	if dnsApplied.GraphStore.EntitiesDeleted != 2 || dnsApplied.StateStore.EntitiesDeleted != 2 {
		t.Fatalf("dns_alert apply deleted graph=%d state=%d, want 2/2", dnsApplied.GraphStore.EntitiesDeleted, dnsApplied.StateStore.EntitiesDeleted)
	}
	if graphEntityExists(t, ctx, graphStore, legacyAlertURN) || graphEntityExists(t, ctx, graphStore, legacyAlertTypeURN) {
		t.Fatal("dns_alert apply left legacy alert/alert-type entities behind")
	}
	if !graphEntityExists(t, ctx, graphStore, assetURN) {
		t.Fatal("dns_alert closeout deleted the shared external.asset entity")
	}
	if !graphEntityExists(t, ctx, graphStore, unrelatedUserURN) {
		t.Fatal("dns_alert closeout touched unrelated source/runtime state")
	}

	dnsRerun, err := cleanupProjectedEntities(ctx, deps, dnsAlertOptions)
	if err != nil {
		t.Fatalf("dns_alert idempotent rerun error = %v", err)
	}
	if dnsRerun.GraphStore.EntitiesMatched != 0 || dnsRerun.GraphStore.EntitiesDeleted != 0 {
		t.Fatalf("dns_alert idempotent rerun GraphStore = %+v, want all-zero", dnsRerun.GraphStore)
	}
}

type vulnViewLegacyCloseoutFixture struct {
	tenantID                                                                                                   string
	assetURN, legacyFindingURN, legacyTemplateURN, legacyAlertURN, legacyAlertTypeURN                          string
	newFindingURN, unrelatedUserURN, unrelatedRepoURN                                                          string
	legacyVulnerabilityRuntime, legacyDNSAlertRuntime, activeAssetRuntime, newFindingRuntime, unrelatedRuntime string
}

// seedVulnViewLegacyCloseoutFixture writes pre-cutover legacy graph state
// (plus overlapping, backfilled, and unrelated state the closeout must
// preserve) directly through the projection ports into both the real Neo4j
// graph store and the real Postgres state store, mirroring what the retired
// vulnerability/dns_alert source connectors and the new finding importer
// would have projected.
func seedVulnViewLegacyCloseoutFixture(t *testing.T, ctx context.Context, graphStore ports.ProjectionGraphStore, stateStore ports.ProjectionStateStore, pgDSN string, neo4jURI string, neo4jPassword string, fx vulnViewLegacyCloseoutFixture) {
	t.Helper()

	upsertEntity := func(entity *ports.ProjectedEntity) {
		t.Helper()
		if err := graphStore.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("seed graph entity %s: %v", entity.URN, err)
		}
		if err := stateStore.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("seed state entity %s: %v", entity.URN, err)
		}
	}
	upsertLink := func(link *ports.ProjectedLink) {
		t.Helper()
		if err := graphStore.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("seed graph link %s %s %s: %v", link.FromURN, link.Relation, link.ToURN, err)
		}
		if err := stateStore.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("seed state link %s %s %s: %v", link.FromURN, link.Relation, link.ToURN, err)
		}
	}

	// Shared external.asset: first asserted alongside the legacy
	// vulnerability evidence, then reasserted by the still-active
	// asset-family runtime (the realistic current state once the
	// vulnerability/dns_alert families stop running but the asset family
	// keeps scanning).
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.assetURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyVulnerabilityRuntime,
		EntityType: "external.asset", Label: "admin.writer.com",
		Attributes: map[string]string{"asset_id": "admin.writer.com", "source_system": "vulnview"},
	})
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.assetURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.activeAssetRuntime,
		EntityType: "external.asset", Label: "admin.writer.com",
		Attributes: map[string]string{"asset_id": "admin.writer.com", "source_system": "vulnview", "findings_count": "3"},
	})

	// Legacy vulnerability-family graph state (old external_id/template_id
	// identity scheme, entity_type "vulnview.finding" -- same string the
	// new standardized finding export also uses, which is exactly why this
	// closeout must scope by runtime_id/source_id rather than entity_type
	// alone).
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.legacyFindingURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyVulnerabilityRuntime,
		EntityType: "vulnview.finding", Label: "legacy-template",
		Attributes: map[string]string{"template_id": "legacy-template-1", "severity": "medium", "scan_id": "scan-1"},
	})
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.legacyTemplateURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyVulnerabilityRuntime,
		EntityType: "vulnview.template", Label: "legacy-template-1",
		Attributes: map[string]string{"template_id": "legacy-template-1", "severity": "medium"},
	})
	// R03: the has_evidence link is seeded as a *raw* pre-F06 logical row
	// in both stores -- legacy tenant/source/runtime provenance recorded
	// directly, no entity_link_assertions row and no RELATION_ASSERTION
	// edge at all -- exactly the deployed shape the confirmed failure
	// describes, bypassing UpsertProjectedLink (which would create
	// assertion coverage these deployed rows never had).
	seedRawLegacyHasEvidenceLink(t, ctx, pgDSN, neo4jURI, neo4jPassword,
		fx.assetURN, fx.legacyFindingURN, fx.tenantID, "vulnview", fx.legacyVulnerabilityRuntime, "legacy-vuln-evt-1")
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyVulnerabilityRuntime,
		FromURN: fx.legacyFindingURN, ToURN: fx.assetURN, Relation: "observed_on",
		Attributes: map[string]string{"event_id": "legacy-vuln-evt-1"},
	})
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyVulnerabilityRuntime,
		FromURN: fx.legacyFindingURN, ToURN: fx.legacyTemplateURN, Relation: "has_classification",
		Attributes: map[string]string{"template_id": "legacy-template-1"},
	})

	// Legacy dns_alert-family graph state.
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.legacyAlertURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyDNSAlertRuntime,
		EntityType: "vulnview.dns_alert", Label: "legacy-alert",
		Attributes: map[string]string{"alert": "legacy-type", "record_type": "CNAME"},
	})
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.legacyAlertTypeURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyDNSAlertRuntime,
		EntityType: "vulnview.dns_alert_type", Label: "legacy-type",
		Attributes: map[string]string{"alert_type": "legacy-type"},
	})
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyDNSAlertRuntime,
		FromURN: fx.assetURN, ToURN: fx.legacyAlertURN, Relation: "has_evidence",
		Attributes: map[string]string{"event_id": "legacy-dns-evt-1"},
	})
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyDNSAlertRuntime,
		FromURN: fx.legacyAlertURN, ToURN: fx.assetURN, Relation: "observed_on",
		Attributes: map[string]string{"event_id": "legacy-dns-evt-1"},
	})
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.legacyDNSAlertRuntime,
		FromURN: fx.legacyAlertURN, ToURN: fx.legacyAlertTypeURN, Relation: "has_classification",
		Attributes: map[string]string{"alert_type": "legacy-type"},
	})

	// New-runtime backfill: a standardized findingId-identity finding from
	// the same vulnview source, projected by a different (currently
	// active) per-source finding runtime. It shares the "vulnview.finding"
	// entity_type string with the legacy vulnerability finding above.
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.newFindingURN, TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.newFindingRuntime,
		EntityType: "vulnview.finding", Label: "excess-privilege",
		Attributes: map[string]string{"finding_id": "cloud_identity|excess_privilege|aws|role-1", "source": "cloud_identity", "severity": "high"},
	})
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "vulnview", RuntimeID: fx.newFindingRuntime,
		FromURN: fx.assetURN, ToURN: fx.newFindingURN, Relation: "has_evidence",
		Attributes: map[string]string{"event_id": "new-finding-evt-1"},
	})

	// Completely unrelated source/runtime state.
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.unrelatedUserURN, TenantID: fx.tenantID, SourceID: "github", RuntimeID: fx.unrelatedRuntime,
		EntityType: "github_user", Label: "alice", Attributes: map[string]string{"login": "alice"},
	})
	upsertEntity(&ports.ProjectedEntity{
		URN: fx.unrelatedRepoURN, TenantID: fx.tenantID, SourceID: "github", RuntimeID: fx.unrelatedRuntime,
		EntityType: "github_code_repository", Label: "writer/cerebro",
	})
	upsertLink(&ports.ProjectedLink{
		TenantID: fx.tenantID, SourceID: "github", RuntimeID: fx.unrelatedRuntime,
		FromURN: fx.unrelatedUserURN, ToURN: fx.unrelatedRepoURN, Relation: "has_access_to",
	})
}

// seedRawLegacyHasEvidenceLink inserts one logical has_evidence edge
// directly through raw SQL/Cypher into both the real Postgres state store
// and the real Neo4j graph store, bypassing UpsertProjectedLink entirely
// so neither store ever creates assertion coverage for it (R03): this is
// the deployed pre-F06 shape the confirmed failure describes -- a logical
// row/edge carrying its own recorded tenant/source/runtime, and nothing
// else.
func seedRawLegacyHasEvidenceLink(t *testing.T, ctx context.Context, pgDSN string, neo4jURI string, neo4jPassword string, fromURN string, toURN string, tenantID string, sourceID string, runtimeID string, eventID string) {
	t.Helper()

	pgRaw, err := sql.Open("pgx", pgDSN)
	if err != nil {
		t.Fatalf("open raw postgres connection: %v", err)
	}
	defer func() { _ = pgRaw.Close() }()
	attributesJSON := fmt.Sprintf(`{"event_id":%q}`, eventID)
	if _, err := pgRaw.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json)
VALUES ($1, 'has_evidence', $2, $3, $4, $5, $6::jsonb)`,
		fromURN, toURN, tenantID, sourceID, runtimeID, attributesJSON); err != nil {
		t.Fatalf("seed raw legacy postgres entity_links row: %v", err)
	}

	driver, err := neo4jdriver.NewDriverWithContext(neo4jURI, neo4jdriver.BasicAuth("neo4j", neo4jPassword, ""))
	if err != nil {
		t.Fatalf("open raw neo4j driver: %v", err)
	}
	defer func() { _ = driver.Close(ctx) }()
	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{AccessMode: neo4jdriver.AccessModeWrite})
	defer func() { _ = session.Close(ctx) }()
	result, err := session.Run(ctx, `
MATCH (src:Entity {urn: $from_urn}), (dst:Entity {urn: $to_urn})
MERGE (src)-[r:RELATION {relation: 'has_evidence'}]->(dst)
SET r.tenant_id = $tenant_id, r.source_id = $source_id, r.runtime_id = $runtime_id,
    r.attributes_json = $attributes_json, r.attributes_version = 1`,
		map[string]any{
			"from_urn": fromURN, "to_urn": toURN, "tenant_id": tenantID,
			"source_id": sourceID, "runtime_id": runtimeID, "attributes_json": attributesJSON,
		})
	if err != nil {
		t.Fatalf("seed raw legacy neo4j RELATION edge: %v", err)
	}
	if _, err := result.Consume(ctx); err != nil {
		t.Fatalf("consume raw legacy neo4j RELATION edge write: %v", err)
	}
}

// graphEntityExists checks entity existence directly via Cypher: the Neo4j
// store does not implement ports.ProjectionEntityReader (that port backs
// the current-state store only), so GetProjectedEntity is unavailable here.
func graphEntityExists(t *testing.T, ctx context.Context, store *graphstoreneo4j.Store, urn string) bool {
	t.Helper()
	rows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query:    `MATCH (e:Entity {urn: $urn}) RETURN e.urn AS urn`,
		Params:   map[string]any{"urn": urn},
		RowLimit: 1,
	})
	if err != nil {
		t.Fatalf("ExecuteReadCypher(graph, %s) error = %v", urn, err)
	}
	return len(rows) > 0
}

func stateEntityExists(t *testing.T, ctx context.Context, store ports.ProjectionEntityReader, urn string) bool {
	t.Helper()
	entity, err := store.GetProjectedEntity(ctx, urn)
	if err != nil {
		t.Fatalf("GetProjectedEntity(state, %s) error = %v", urn, err)
	}
	return entity != nil
}

// requireDockerNeo4jForLegacyCloseoutTest self-provisions a disposable Neo4j
// container the same way internal/graphstore/neo4j's
// TestNeo4jDockerProjectionAndQueries does, gated by the same
// CEREBRO_RUN_NEO4J_DOCKER=1 opt-in so this permanent test follows the
// repository's existing Docker-integration convention.
func requireDockerNeo4jForLegacyCloseoutTest(t *testing.T) (string, func()) {
	t.Helper()
	if strings.TrimSpace(os.Getenv("CEREBRO_RUN_NEO4J_DOCKER")) != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run the VulnView legacy closeout Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	port := legacyCloseoutFreePort(t)
	name := fmt.Sprintf("pr3039-legacycloseout-neo4j-%d", time.Now().UnixNano())
	password := "legacy-closeout-test-password"
	image := os.Getenv("CEREBRO_NEO4J_DOCKER_IMAGE")
	if image == "" {
		image = "neo4j:5"
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "docker", "run", "-d", "--rm", "--name", name, // #nosec G204 G702 -- integration test invokes fixed docker binary with generated container arguments.
		"-e", "NEO4J_AUTH=neo4j/"+password,
		"-p", fmt.Sprintf("127.0.0.1:%d:7687", port),
		image)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run neo4j: %v\n%s", err, string(output))
	}
	cleanup := func() {
		_ = exec.Command("docker", "rm", "-f", name).Run() // #nosec G204 -- integration test cleanup invokes fixed docker binary with generated container name.
	}
	uri := fmt.Sprintf("bolt://127.0.0.1:%d", port)
	waitForLegacyCloseoutNeo4j(t, uri, password)
	return uri, cleanup
}

func requirePostgresDSNForLegacyCloseoutTest(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the VulnView legacy closeout Postgres integration test")
	}
	return dsn
}

func waitForLegacyCloseoutNeo4j(t *testing.T, uri, password string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		store, err := graphstoreneo4j.Open(config.GraphStoreConfig{Neo4jURI: uri, Neo4jUsername: "neo4j", Neo4jPassword: password})
		if err == nil {
			pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = store.Ping(pingCtx)
			cancel()
			_ = store.CloseContext(context.Background())
			if err == nil {
				return
			}
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("neo4j did not become ready at %s: %v", uri, lastErr)
}

func legacyCloseoutFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}
