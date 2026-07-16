package neo4j

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitypathdelta"
)

func TestProjectedLinkAssertionsDockerLifecycle(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-projected-link-assertions-%d", time.Now().UnixNano())
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

	tenantID := "projected-assertion-test"
	sourceID := "cloud_inventory"
	from := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:asset:entry", TenantID: tenantID, SourceID: sourceID,
		EntityType: "asset", Label: "entry",
	}
	to := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:asset:target", TenantID: tenantID, SourceID: sourceID,
		EntityType: "asset", Label: "target",
	}
	for _, entity := range []*ports.ProjectedEntity{from, to} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}

	for _, fixture := range []struct {
		runtimeID        string
		reconciliationID string
		proof            string
	}{
		{runtimeID: "runtime-a", reconciliationID: "pass-a", proof: "asserted-by-a"},
		{runtimeID: "runtime-b", reconciliationID: "pass-b", proof: "asserted-by-b"},
	} {
		if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: fixture.runtimeID,
			FromURN: from.URN, Relation: "can_reach", ToURN: to.URN,
			Attributes: map[string]string{
				"projection_reconciliation_id": fixture.reconciliationID,
				"proof":                        fixture.proof,
			},
		}); err != nil {
			t.Fatalf("UpsertProjectedLink(%s) error = %v", fixture.runtimeID, err)
		}
	}

	state := projectedLinkAssertionStateFor(t, ctx, store, from.URN, "can_reach", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 2 {
		t.Fatalf("state after two runtime upserts = %#v, want one logical link and two assertions", state)
	}
	missing, err := store.CountProjectedLinksMissingAssertions(ctx, tenantID, []string{"can_reach"})
	if err != nil || missing != 0 {
		t.Fatalf("CountProjectedLinksMissingAssertions(covered) = %d, %v, want zero", missing, err)
	}

	result, err := store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-a", ReconciliationID: "next-pass-a",
		Relations: []string{"can_reach"}, Limit: 10,
	})
	if err != nil || result.LinksMatched != 1 || result.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks(runtime-a) = %#v, %v, want one assertion deleted", result, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "can_reach", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalRuntimeID != "runtime-b" || state.assertionRuntimeID != "runtime-b" {
		t.Fatalf("state after runtime-a sweep = %#v, want logical link rehydrated from runtime-b", state)
	}
	if !strings.Contains(state.logicalAttributesJSON, `"proof":"asserted-by-b"`) || strings.Contains(state.logicalAttributesJSON, "asserted-by-a") {
		t.Fatalf("logical attributes after runtime-a sweep = %q, want only runtime-b proof", state.logicalAttributesJSON)
	}
	if state.assertionReconciliationID != "pass-b" {
		t.Fatalf("remaining assertion reconciliation id = %q, want pass-b", state.assertionReconciliationID)
	}

	result, err = store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b", ReconciliationID: "next-pass-b",
		Relations: []string{"can_reach"}, Limit: 10,
	})
	if err != nil || result.LinksMatched != 1 || result.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks(runtime-b) = %#v, %v, want final assertion deleted", result, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "can_reach", to.URN)
	if state.logicalCount != 0 || state.assertionCount != 0 {
		t.Fatalf("state after runtime-b sweep = %#v, want assertion and logical link removed", state)
	}

	if _, err := store.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `MATCH (src:Entity {urn: $from_urn}), (dst:Entity {urn: $to_urn})
MERGE (src)-[legacy:RELATION {relation: 'legacy_link'}]->(dst)
SET legacy.tenant_id = $tenant_id,
    legacy.source_id = $source_id,
    legacy.runtime_id = $runtime_id,
    legacy.attributes_json = '{"proof":"legacy-a"}',
    legacy.projection_reconciliation_id = 'legacy-pass-a',
	legacy.attributes_version = 0
MERGE (src)-[legacy_scalar:RELATION {relation: 'legacy_scalar'}]->(dst)
SET legacy_scalar.tenant_id = $tenant_id,
    legacy_scalar.source_id = $source_id,
    legacy_scalar.runtime_id = $runtime_id,
    legacy_scalar.attributes_json = '{"proof":"legacy-a"}',
    legacy_scalar.projection_reconciliation_id = 'legacy-pass-a',
    legacy_scalar.attributes_version = 0`, map[string]any{
			"from_urn": from.URN, "to_urn": to.URN, "tenant_id": tenantID, "source_id": sourceID, "runtime_id": "runtime-a",
		})
	}); err != nil {
		t.Fatalf("create legacy logical relation: %v", err)
	}
	result, err = store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-a", ReconciliationID: "next-pass-a",
		Relations: []string{"legacy_link"}, Limit: 10,
	})
	if err != nil || result.LinksMatched != 1 || result.LinksDeleted != 0 {
		t.Fatalf("CleanupProjectedRuntimeLinks(legacy) = %#v, %v, want uncovered legacy link reported but preserved", result, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "legacy_link", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 0 {
		t.Fatalf("legacy state after sweep = %#v, want logical link preserved", state)
	}
	missing, err = store.CountProjectedLinksMissingAssertions(ctx, tenantID, []string{"legacy_link"})
	if err != nil || missing != 1 {
		t.Fatalf("CountProjectedLinksMissingAssertions(legacy) = %d, %v, want one uncovered logical link", missing, err)
	}

	if err := store.UpsertProjectedLinks(ctx, []*ports.ProjectedLink{{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b",
		FromURN: from.URN, Relation: "legacy_link", ToURN: to.URN,
		Attributes: map[string]string{
			"projection_reconciliation_id": "pass-b",
			"proof":                        "asserted-by-b",
		},
	}}); err != nil {
		t.Fatalf("UpsertProjectedLinks(migrate legacy) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "legacy_link", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalAssertionManaged || state.logicalRuntimeID != "runtime-a" {
		t.Fatalf("legacy state after live assertion = %#v, want last-writer provenance quarantined", state)
	}
	missing, err = store.CountProjectedLinksMissingAssertions(ctx, tenantID, []string{"legacy_link"})
	if err != nil || missing != 1 {
		t.Fatalf("CountProjectedLinksMissingAssertions(quarantined legacy) = %d, %v, want one", missing, err)
	}
	result, err = store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b", ReconciliationID: "next-pass-b",
		Relations: []string{"legacy_link"}, Limit: 10,
	})
	if err != nil || result.LinksMatched != 1 || result.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks(migrated runtime-b) = %#v, %v, want runtime-b assertion deleted", result, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "legacy_link", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 0 || state.logicalRuntimeID != "runtime-a" || state.logicalAssertionManaged {
		t.Fatalf("quarantined legacy state after runtime-b sweep = %#v, want uncovered logical fact preserved", state)
	}
	if !strings.Contains(state.logicalAttributesJSON, `"proof":"legacy-a"`) || strings.Contains(state.logicalAttributesJSON, "asserted-by-b") {
		t.Fatalf("migrated legacy attributes after runtime-b sweep = %q, want original legacy-a proof", state.logicalAttributesJSON)
	}

	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b",
		FromURN: from.URN, Relation: "legacy_scalar", ToURN: to.URN,
		Attributes: map[string]string{"projection_reconciliation_id": "pass-b", "proof": "asserted-by-b"},
	}); err != nil {
		t.Fatalf("UpsertProjectedLink(migrate scalar legacy) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "legacy_scalar", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalAssertionManaged || state.logicalRuntimeID != "runtime-a" {
		t.Fatalf("scalar legacy state after live assertion = %#v, want last-writer provenance quarantined", state)
	}
	result, err = store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b", ReconciliationID: "next-pass-b",
		Relations: []string{"legacy_scalar"}, Limit: 10,
	})
	if err != nil || result.LinksMatched != 1 || result.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks(scalar migrated runtime-b) = %#v, %v, want runtime-b assertion deleted", result, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "legacy_scalar", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 0 || state.logicalRuntimeID != "runtime-a" || state.logicalAssertionManaged || !strings.Contains(state.logicalAttributesJSON, `"proof":"legacy-a"`) {
		t.Fatalf("scalar quarantined legacy state after runtime-b sweep = %#v, want uncovered logical fact preserved", state)
	}

	for _, runtimeID := range []string{"runtime-a", "runtime-b"} {
		if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
			FromURN: from.URN, Relation: "retract_test", ToURN: to.URN,
			Attributes: map[string]string{"proof": runtimeID},
		}); err != nil {
			t.Fatalf("UpsertProjectedLink(retract %s) error = %v", runtimeID, err)
		}
	}
	if err := store.DeleteProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-a",
		FromURN: from.URN, Relation: "retract_test", ToURN: to.URN,
	}); err != nil {
		t.Fatalf("DeleteProjectedLink(runtime-a) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "retract_test", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalRuntimeID != "runtime-b" || state.assertionRuntimeID != "runtime-b" {
		t.Fatalf("runtime-scoped retraction state = %#v, want runtime-b preserved", state)
	}
	if err := store.DeleteProjectedLink(ctx, &ports.ProjectedLink{FromURN: from.URN, Relation: "retract_test", ToURN: to.URN}); err != nil {
		t.Fatalf("DeleteProjectedLink(identity-less) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "retract_test", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 {
		t.Fatalf("identity-less retraction state = %#v, want fail-closed preservation", state)
	}

	endpoint := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:kolide_device:device-1", TenantID: tenantID, SourceID: "kolide", RuntimeID: "runtime-a",
		EntityType: "kolide.device", Label: "device-1",
	}
	staleIdentity := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:identity:login:user-1", TenantID: tenantID, SourceID: "kolide", RuntimeID: "runtime-a",
		EntityType: "identity.login", Label: "user-1",
	}
	replacementIdentity := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:endpoint_identifier:kolide_user_id:user-1", TenantID: tenantID, SourceID: "kolide", RuntimeID: "runtime-a",
		EntityType: "endpoint.identifier", Label: "user-1",
	}
	for _, entity := range []*ports.ProjectedEntity{endpoint, staleIdentity, replacementIdentity} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(endpoint fixture %s) error = %v", entity.URN, err)
		}
	}
	for _, runtimeID := range []string{"runtime-a", "runtime-b"} {
		if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID, SourceID: "kolide", RuntimeID: runtimeID,
			FromURN: endpoint.URN, Relation: "owned_by", ToURN: staleIdentity.URN,
		}); err != nil {
			t.Fatalf("UpsertProjectedLink(endpoint stale %s) error = %v", runtimeID, err)
		}
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "kolide", RuntimeID: "runtime-a",
		FromURN: endpoint.URN, Relation: "has_identifier", ToURN: replacementIdentity.URN,
	}); err != nil {
		t.Fatalf("UpsertProjectedLink(endpoint replacement) error = %v", err)
	}
	endpointCleanup, err := store.CleanupEndpointOwnerIDLinks(ctx, ports.ProjectionLinkCleanupRequest{
		TenantID: tenantID, SourceID: "kolide", RuntimeID: "runtime-a", Limit: 10,
	})
	if err != nil || endpointCleanup.LinksMatched != 1 || endpointCleanup.LinksDeleted != 1 {
		t.Fatalf("CleanupEndpointOwnerIDLinks(runtime-a) = %#v, %v, want one scoped assertion deleted", endpointCleanup, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, endpoint.URN, "owned_by", staleIdentity.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalRuntimeID != "runtime-b" {
		t.Fatalf("endpoint cleanup state = %#v, want runtime-b assertion and logical fact preserved", state)
	}

	cleanupEntity := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:cleanup_asset:shared", TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-a",
		EntityType: "cleanup.asset", Label: "shared cleanup asset",
	}
	cleanupAnchor := &ports.ProjectedEntity{
		URN: "urn:cerebro:projected-assertion-test:cleanup_anchor:anchor", TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-a",
		EntityType: "cleanup.anchor", Label: "cleanup anchor",
	}
	for _, entity := range []*ports.ProjectedEntity{cleanupEntity, cleanupAnchor} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(cleanup fixture %s) error = %v", entity.URN, err)
		}
	}
	for _, runtimeID := range []string{"runtime-a", "runtime-b"} {
		if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
			FromURN: cleanupEntity.URN, Relation: "cleanup_link", ToURN: cleanupAnchor.URN,
		}); err != nil {
			t.Fatalf("UpsertProjectedLink(entity cleanup %s) error = %v", runtimeID, err)
		}
	}
	entityCleanup, err := store.CleanupProjectedEntities(ctx, ports.ProjectionCleanupRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-a", EntityTypes: []string{"cleanup.asset"}, Limit: 10,
	})
	if err != nil || entityCleanup.EntitiesMatched != 1 || entityCleanup.EntitiesDeleted != 0 || entityCleanup.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedEntities(runtime-a) = %#v, %v, want shared entity preserved and one assertion deleted", entityCleanup, err)
	}
	if !projectedEntityExists(t, ctx, store, cleanupEntity.URN) {
		t.Fatal("CleanupProjectedEntities(runtime-a) deleted shared entity")
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, cleanupEntity.URN, "cleanup_link", cleanupAnchor.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalRuntimeID != "runtime-b" {
		t.Fatalf("entity cleanup state = %#v, want runtime-b assertion and logical fact preserved", state)
	}

	if _, err := store.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `MATCH (src:Entity {urn: $from_urn}), (dst:Entity {urn: $to_urn})
MERGE (src)-[complete:RELATION {relation: 'backfill_complete'}]->(dst)
SET complete.tenant_id = $tenant_id,
    complete.source_id = $source_id,
    complete.runtime_id = 'legacy-runtime',
    complete.attributes_json = '{"proof":"pre-upgrade"}',
    complete.projection_reconciliation_id = 'legacy-pass',
    complete.attributes_version = 0
MERGE (src)-[blank:RELATION {relation: 'backfill_blank'}]->(dst)
SET blank.tenant_id = $tenant_id,
    blank.source_id = $source_id,
    blank.runtime_id = '',
    blank.attributes_json = '{"proof":"identity-incomplete"}',
    blank.attributes_version = 0`, map[string]any{
			"from_urn": from.URN, "to_urn": to.URN, "tenant_id": tenantID, "source_id": sourceID,
		})
	}); err != nil {
		t.Fatalf("create assertion migration fixtures: %v", err)
	}
	migrationRequest := ports.ProjectionAssertionMigrationRequest{
		TenantID: tenantID, Relations: []string{"backfill_complete", "backfill_blank"}, Limit: 10,
	}
	dryMigration := migrationRequest
	dryMigration.DryRun = true
	migration, err := store.MigrateProjectedLinkAssertions(ctx, dryMigration)
	if err != nil || migration.LinksMatched != 2 || migration.LinksMigrated != 0 || migration.LinksQuarantined != 2 {
		t.Fatalf("MigrateProjectedLinkAssertions(dry-run) = %#v, %v, want both legacy links quarantined", migration, err)
	}
	migration, err = store.MigrateProjectedLinkAssertions(ctx, migrationRequest)
	if err != nil || migration.LinksMatched != 2 || migration.LinksMigrated != 0 || migration.LinksQuarantined != 2 {
		t.Fatalf("MigrateProjectedLinkAssertions() = %#v, %v, want both legacy links quarantined", migration, err)
	}
	migration, err = store.MigrateProjectedLinkAssertions(ctx, migrationRequest)
	if err != nil || migration.LinksMigrated != 0 || migration.LinksQuarantined != 2 {
		t.Fatalf("MigrateProjectedLinkAssertions(repeat) = %#v, %v, want stable quarantine", migration, err)
	}
	missing, err = store.CountProjectedLinksMissingAssertions(ctx, tenantID, []string{"backfill_complete", "backfill_blank"})
	if err != nil || missing != 2 {
		t.Fatalf("CountProjectedLinksMissingAssertions(after migration) = %d, %v, want both legacy links uncovered", missing, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "backfill_complete", to.URN)
	if state.assertionCount != 0 || state.logicalAssertionManaged || state.logicalRuntimeID != "legacy-runtime" {
		t.Fatalf("backfill complete state = %#v, want nonblank last-writer provenance quarantined", state)
	}
	result, err = store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "legacy-runtime", ReconciliationID: "current-pass",
		Relations: []string{"backfill_complete"}, Limit: 10,
	})
	if err != nil || result.LinksMatched != 1 || result.LinksDeleted != 0 {
		t.Fatalf("CleanupProjectedRuntimeLinks(legacy edge) = %#v, %v, want quarantine preserved", result, err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "backfill_complete", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 0 || state.logicalAssertionManaged {
		t.Fatalf("legacy edge after sweep = %#v, want uncovered logical quarantine preserved", state)
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b",
		FromURN: from.URN, Relation: "backfill_complete", ToURN: to.URN,
		Attributes: map[string]string{"proof": "runtime-b"},
	}); err != nil {
		t.Fatalf("UpsertProjectedLink(nonblank legacy survivor) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "backfill_complete", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalAssertionManaged || state.logicalRuntimeID != "legacy-runtime" || !strings.Contains(state.logicalAttributesJSON, "pre-upgrade") {
		t.Fatalf("nonblank legacy after live assertion = %#v, want last-writer provenance quarantine preserved", state)
	}
	if err := store.DeleteProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b",
		FromURN: from.URN, Relation: "backfill_complete", ToURN: to.URN,
	}); err != nil {
		t.Fatalf("DeleteProjectedLink(nonblank legacy runtime-b) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "backfill_complete", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 0 || state.logicalAssertionManaged {
		t.Fatalf("nonblank legacy after runtime-b retraction = %#v, want uncovered logical quarantine preserved", state)
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b",
		FromURN: from.URN, Relation: "backfill_blank", ToURN: to.URN,
		Attributes: map[string]string{"proof": "runtime-b"},
	}); err != nil {
		t.Fatalf("UpsertProjectedLink(blank legacy survivor) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "backfill_blank", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 1 || state.logicalAssertionManaged || state.logicalRuntimeID != "" || !strings.Contains(state.logicalAttributesJSON, "identity-incomplete") {
		t.Fatalf("blank-identity legacy after managed upsert = %#v, want quarantine preserved", state)
	}
	if err := store.DeleteProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: "runtime-b",
		FromURN: from.URN, Relation: "backfill_blank", ToURN: to.URN,
	}); err != nil {
		t.Fatalf("DeleteProjectedLink(blank legacy runtime-b) error = %v", err)
	}
	state = projectedLinkAssertionStateFor(t, ctx, store, from.URN, "backfill_blank", to.URN)
	if state.logicalCount != 1 || state.assertionCount != 0 || state.logicalAssertionManaged {
		t.Fatalf("blank-identity legacy after runtime-b retraction = %#v, want uncovered logical quarantine preserved", state)
	}
}

type projectedLinkAssertionState struct {
	logicalCount              int64
	assertionCount            int64
	logicalSourceID           string
	logicalRuntimeID          string
	assertionRuntimeID        string
	logicalAttributesJSON     string
	assertionReconciliationID string
	logicalAssertionManaged   bool
}

func projectedLinkAssertionStateFor(t *testing.T, ctx context.Context, store *Store, fromURN string, relation string, toURN string) projectedLinkAssertionState {
	t.Helper()
	var state projectedLinkAssertionState
	if _, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (src:Entity {urn: $from_urn}), (dst:Entity {urn: $to_urn})
OPTIONAL MATCH (src)-[logical:RELATION {relation: $relation}]->(dst)
WITH src, dst, collect(logical) AS logicals
OPTIONAL MATCH (src)-[assertion:RELATION_ASSERTION {relation: $relation}]->(dst)
WITH logicals, collect(assertion) AS assertions
RETURN size(logicals),
       size(assertions),
       coalesce(head([logical IN logicals | logical.source_id]), ''),
       coalesce(head([logical IN logicals | logical.runtime_id]), ''),
       coalesce(head([assertion IN assertions | assertion.runtime_id]), ''),
       coalesce(head([logical IN logicals | logical.attributes_json]), ''),
       coalesce(head([assertion IN assertions | assertion.projection_reconciliation_id]), ''),
       coalesce(head([logical IN logicals | logical.assertion_managed]), false)`, map[string]any{
			"from_urn": fromURN, "relation": relation, "to_urn": toURN,
		})
		if err != nil {
			return nil, err
		}
		record, err := result.Single(ctx)
		if err != nil {
			return nil, err
		}
		state = projectedLinkAssertionState{
			logicalCount:              toInt64(record.Values[0]),
			assertionCount:            toInt64(record.Values[1]),
			logicalSourceID:           stringValue(record.Values[2]),
			logicalRuntimeID:          stringValue(record.Values[3]),
			assertionRuntimeID:        stringValue(record.Values[4]),
			logicalAttributesJSON:     stringValue(record.Values[5]),
			assertionReconciliationID: stringValue(record.Values[6]),
			logicalAssertionManaged:   boolValue(record.Values[7]),
		}
		return nil, nil
	}); err != nil {
		t.Fatalf("load projected link assertion state: %v", err)
	}
	return state
}

func projectedEntityExists(t *testing.T, ctx context.Context, store *Store, urn string) bool {
	t.Helper()
	var exists bool
	if _, err := store.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		value, err := queryOneValue(ctx, tx, "MATCH (e:Entity {urn: $urn}) RETURN count(e)", map[string]any{"urn": urn})
		if err != nil {
			return nil, err
		}
		exists = toInt64(value) == 1
		return nil, nil
	}); err != nil {
		t.Fatalf("load projected entity %s: %v", urn, err)
	}
	return exists
}

func TestSecurityPathDeltaDockerLifecycle(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-security-path-delta-test-%d", time.Now().UnixNano())
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
	engine := attackpath.New(store)

	baselineResult := traverseSecurityPaths(t, ctx, engine)
	if baselineResult.Counts.Paths != 0 || len(baselineResult.Paths) != 0 {
		t.Fatalf("empty graph attack paths = counts %#v paths %#v, want none", baselineResult.Counts, baselineResult.Paths)
	}
	baselineObservedAt := time.Date(2026, time.July, 15, 8, 0, 0, 0, time.UTC)
	baseline := securityPathSnapshot(t, "baseline", baselineObservedAt, baselineResult, securitypathdelta.CollectionModeCheckpointed)

	tenantID := "security-path-delta-test"
	sourceID := "cloud_inventory"
	runtimeID := "runtime-collection-1"
	public := &ports.ProjectedEntity{URN: "urn:cerebro:security-path-delta-test:aws_public_principal:public_internet", TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, EntityType: "aws.public_principal", Label: "public internet"}
	exposed := &ports.ProjectedEntity{URN: "urn:cerebro:security-path-delta-test:aws_network_interface:entry", TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, EntityType: "aws.network.interface", Label: "production entry"}
	account := &ports.ProjectedEntity{URN: "urn:cerebro:security-path-delta-test:cloud_account:production", TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, EntityType: "cloud.account", Label: "production"}
	principal := &ports.ProjectedEntity{URN: "urn:cerebro:security-path-delta-test:aws_role:workload", TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, EntityType: "aws.role", Label: "workload role"}
	permission := &ports.ProjectedEntity{URN: "urn:cerebro:security-path-delta-test:aws_iam_policy:administrator", TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, EntityType: "aws.iam.policy", Label: "administrator"}
	owner := &ports.ProjectedEntity{URN: "urn:cerebro:security-path-delta-test:team:security", TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, EntityType: "team", Label: "Security"}
	for _, entity := range []*ports.ProjectedEntity{public, exposed, account, principal, permission, owner} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("UpsertProjectedEntity(%s) error = %v", entity.URN, err)
		}
	}

	exposureLink := &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
		FromURN: public.URN, Relation: "can_reach", ToURN: exposed.URN,
		Attributes: map[string]string{"source_runtime_id": runtimeID, "source_event_id": "event-exposure", "at": "2026-07-15T08:01:00Z"},
	}
	privilegeLink := &ports.ProjectedLink{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID,
		FromURN: principal.URN, Relation: "can_admin", ToURN: permission.URN,
		Attributes: map[string]string{"source_runtime_id": runtimeID, "source_event_id": "event-admin-grant", "at": "2026-07-15T08:03:00Z"},
	}
	links := []*ports.ProjectedLink{
		exposureLink,
		{TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, FromURN: exposed.URN, Relation: "belongs_to", ToURN: account.URN, Attributes: map[string]string{"source_runtime_id": runtimeID, "source_event_id": "event-account", "at": "2026-07-15T08:01:10Z"}},
		{TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, FromURN: exposed.URN, Relation: "runs_as", ToURN: principal.URN, Attributes: map[string]string{"source_runtime_id": runtimeID, "source_event_id": "event-runtime-role", "at": "2026-07-15T08:02:00Z"}},
		privilegeLink,
		{TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, FromURN: permission.URN, Relation: "belongs_to", ToURN: account.URN, Attributes: map[string]string{"source_runtime_id": runtimeID, "source_event_id": "event-permission-account", "at": "2026-07-15T08:03:10Z"}},
		{TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, FromURN: exposed.URN, Relation: "owned_by", ToURN: owner.URN, Attributes: map[string]string{"source_runtime_id": runtimeID, "source_event_id": "event-owner", "at": "2026-07-15T08:04:00Z"}},
	}
	for _, link := range links {
		if err := store.UpsertProjectedLink(ctx, link); err != nil {
			t.Fatalf("UpsertProjectedLink(%s %s %s) error = %v", link.FromURN, link.Relation, link.ToURN, err)
		}
	}

	activeResult := traverseSecurityPaths(t, ctx, engine)
	if activeResult.Counts.Paths != 1 || len(activeResult.Paths) != 1 {
		t.Fatalf("materialized attack paths = counts %#v paths %#v, want one", activeResult.Counts, activeResult.Paths)
	}
	runtimeScoped, err := engine.Traverse(ctx, attackpath.Request{TenantID: tenantID, RuntimeID: runtimeID, RequireAssertionProof: true, Limit: 10})
	if err != nil || len(runtimeScoped.Paths) != 1 {
		t.Fatalf("runtime-scoped attack paths = %#v error=%v, want selected runtime path", runtimeScoped, err)
	}
	mixedPrivilege := *privilegeLink
	mixedPrivilege.RuntimeID = "runtime-other"
	mixedPrivilege.Attributes = map[string]string{
		"source_runtime_id": "runtime-other",
		"source_event_id":   "event-admin-grant-other-runtime",
		"at":                "2026-07-15T08:03:30Z",
	}
	if err := store.UpsertProjectedLink(ctx, &mixedPrivilege); err != nil {
		t.Fatalf("UpsertProjectedLink(mixed runtime) error = %v", err)
	}
	mixedAll := traverseSecurityPaths(t, ctx, engine)
	if len(mixedAll.Paths) != 1 || !reflect.DeepEqual(mixedAll.Paths[0].PrivilegeEdge.AssertionRuntimeIDs, []string{"runtime-collection-1", "runtime-other"}) {
		t.Fatalf("mixed-runtime assertion union = %#v, want both contributing runtimes", mixedAll.Paths)
	}
	mixedRuntimeResult, err := engine.Traverse(ctx, attackpath.Request{TenantID: tenantID, RuntimeID: runtimeID, RequireAssertionProof: true, Limit: 10})
	if err != nil || mixedRuntimeResult.Counts.Paths != 1 || len(mixedRuntimeResult.Paths) != 1 {
		t.Fatalf("mixed-runtime proof = %#v error=%v, want runtime-scoped assertion to remain certified", mixedRuntimeResult, err)
	}
	if err := store.UpsertProjectedLink(ctx, privilegeLink); err != nil {
		t.Fatalf("UpsertProjectedLink(restore runtime) error = %v", err)
	}
	unrelatedRuntime, err := engine.Traverse(ctx, attackpath.Request{TenantID: tenantID, RuntimeID: "runtime-unrelated", RequireAssertionProof: true, Limit: 10})
	if err != nil || len(unrelatedRuntime.Paths) != 0 {
		t.Fatalf("unrelated runtime attack paths = %#v error=%v, want none", unrelatedRuntime, err)
	}
	observed := activeResult.Paths[0]
	if len(observed.Ownerships) != 1 || observed.Ownerships[0].Owner.URN != owner.URN || observed.Ownerships[0].Edge.SourceEventID != "event-owner" {
		t.Fatalf("attack path ownerships = %#v, want one source-backed assignment to %s", observed.Ownerships, owner.URN)
	}
	for name, edge := range map[string]attackpath.Edge{
		"exposure":  observed.ExposureEdge,
		"traversal": observed.TraversalEdges[0],
		"privilege": observed.PrivilegeEdge,
	} {
		if edge.SourceID != sourceID || edge.SourceRuntimeID != runtimeID || edge.SourceEventID == "" || edge.ObservedAt.IsZero() {
			t.Fatalf("%s proof edge = %#v, want source, runtime, event, and observation time", name, edge)
		}
	}
	activeObservedAt := time.Date(2026, time.July, 15, 8, 5, 0, 0, time.UTC)
	active := securityPathSnapshot(t, "path-active", activeObservedAt, activeResult, securitypathdelta.CollectionModeCheckpointed)
	added, err := securitypathdelta.Compare(&baseline, active)
	if err != nil {
		t.Fatalf("Compare(baseline, active) error = %v", err)
	}
	if added.State != securitypathdelta.DeltaStateCompared || len(added.NewlyObserved) != 1 || len(added.CandidateEdgeCuts) == 0 {
		t.Fatalf("added delta = %#v, want one new path and candidate edge cuts", added)
	}
	t.Logf(
		"newly_observed route=%s owner=%s source_event=%s candidate_cut=%s:%s->%s",
		added.NewlyObserved[0].RouteID,
		added.NewlyObserved[0].Ownerships[0].Owner.Name,
		added.NewlyObserved[0].ProofEdges[0].SourceEventID,
		added.CandidateEdgeCuts[0].Edge.Relation,
		added.CandidateEdgeCuts[0].Edge.From.Label,
		added.CandidateEdgeCuts[0].Edge.To.Label,
	)

	reconciliationID := "verification-pass-1"
	for _, link := range links[1:] {
		currentLink := *link
		currentLink.Attributes = make(map[string]string, len(link.Attributes)+1)
		for key, value := range link.Attributes {
			currentLink.Attributes[key] = value
		}
		currentLink.Attributes["projection_reconciliation_id"] = reconciliationID
		if err := store.UpsertProjectedLink(ctx, &currentLink); err != nil {
			t.Fatalf("UpsertProjectedLink(mark current) error = %v", err)
		}
	}
	reconciled, err := store.CleanupProjectedRuntimeLinks(ctx, ports.ProjectionRuntimeLinkReconciliationRequest{
		TenantID: tenantID, SourceID: sourceID, RuntimeID: runtimeID, ReconciliationID: reconciliationID,
		Relations: []string{"assigned_to", "attached_to", "belongs_to", "can_admin", "can_assume", "can_impersonate", "can_perform", "can_reach", "depends_on", "member_of", "owned_by", "runs_as"},
		Limit:     100,
	})
	if err != nil || reconciled.LinksDeleted != 1 {
		t.Fatalf("CleanupProjectedRuntimeLinks() = %#v, %v, want one stale exposure link deleted", reconciled, err)
	}
	afterResult := traverseSecurityPaths(t, ctx, engine)
	if afterResult.Counts.Paths != 0 || len(afterResult.Paths) != 0 {
		t.Fatalf("post-change attack paths = counts %#v paths %#v, want none", afterResult.Counts, afterResult.Paths)
	}
	afterObservedAt := time.Date(2026, time.July, 15, 8, 10, 0, 0, time.UTC)
	after := securityPathSnapshot(t, "path-removed", afterObservedAt, afterResult, securitypathdelta.CollectionModeCheckpointed)
	removed, err := securitypathdelta.Compare(&active, after)
	if err != nil {
		t.Fatalf("Compare(active, after) error = %v", err)
	}
	if removed.State != securitypathdelta.DeltaStateCompared || len(removed.NoLongerObserved) != 1 || removed.NoLongerObserved[0].ID != active.Paths[0].ID {
		t.Fatalf("removed delta = %#v, want the active path no longer observed", removed)
	}
	verificationResult := traverseSecurityPaths(t, ctx, engine)
	verificationSnapshot := securityPathSnapshot(
		t, "path-removed-verification", afterObservedAt.Add(time.Minute), verificationResult,
		securitypathdelta.CollectionModeGraphResetFullScan,
		"runtime-collection-1",
	)
	verification, err := securitypathdelta.VerifyObservedAbsent(active, verificationSnapshot, []string{active.Paths[0].ID})
	if err != nil {
		t.Fatalf("VerifyObservedAbsent() error = %v", err)
	}
	if verification.State != securitypathdelta.VerificationObservedAbsent || len(verification.StillObserved) != 0 {
		t.Fatalf("verification = %#v, want observed_absent", verification)
	}
	t.Logf(
		"no_longer_observed route=%s verification=%s graph_run=%s runtime_watermark=%s stale_links_deleted=%d",
		removed.NoLongerObserved[0].RouteID,
		verification.State,
		verificationSnapshot.Receipt.GraphRunID,
		verificationSnapshot.Receipt.RuntimeWatermark.Format(time.RFC3339),
		reconciled.LinksDeleted,
	)
}

func traverseSecurityPaths(t *testing.T, ctx context.Context, engine *attackpath.Engine) *attackpath.Result {
	t.Helper()
	result, err := engine.Traverse(ctx, attackpath.Request{TenantID: "security-path-delta-test", RequireAssertionProof: true, Limit: 10})
	if err != nil {
		t.Fatalf("attackpath.Traverse() error = %v", err)
	}
	return result
}

func securityPathSnapshot(t *testing.T, observationID string, observedAt time.Time, result *attackpath.Result, collectionMode string, requiredRuntimeIDs ...string) securitypathdelta.Snapshot {
	t.Helper()
	paths := make([]securitypathdelta.ObservedPath, 0, len(result.Paths))
	for _, path := range result.Paths {
		paths = append(paths, securitypathdelta.ObservedPath{Path: path})
	}
	freshReconciliation := collectionMode == securitypathdelta.CollectionModeGraphResetFullScan
	snapshot, err := securitypathdelta.NewSnapshot(securitypathdelta.SnapshotInput{
		TenantID:                "security-path-delta-test",
		ScopeID:                 "production",
		DetectorID:              "public-to-privileged",
		DetectorRevision:        "v1",
		ObservationID:           observationID,
		ObservedAt:              observedAt,
		RequiredProofRuntimeIDs: requiredRuntimeIDs,
		Receipt: securitypathdelta.CollectionReceiptInput{
			CollectionSourceReceipt: securitypathdelta.CollectionSourceReceipt{
				SourceRuntimeID:  "runtime-collection-1",
				SourceID:         "cloud_inventory",
				ProviderFamily:   "inventory",
				ConfigRevision:   "sha256:security-path-delta-test-config",
				RuntimeWatermark: observedAt.Add(-2 * time.Minute),
				LastSyncedAt:     observedAt.Add(-time.Minute),
				CollectionMode:   collectionMode,
			},
			CollectionGraphReceipt: securitypathdelta.CollectionGraphReceipt{
				GraphCheckpointID:                        "checkpoint-" + observationID,
				GraphRunID:                               "run-" + observationID,
				GraphRunStartedAt:                        observedAt.Add(-45 * time.Second),
				GraphRunFinishedAt:                       observedAt.Add(-30 * time.Second),
				GraphPagesRead:                           1,
				GraphMaterialLinkReconciliationRequested: freshReconciliation,
				GraphMaterialLinkReconciliationSupported: freshReconciliation,
				GraphMaterialLinkReconciliationCompleted: freshReconciliation,
				GraphCheckpointComplete:                  true,
				GraphCheckpointCurrent:                   true,
			},
			CollectionPathReceipt: securitypathdelta.CollectionPathReceipt{
				ObservedPathCount: len(paths),
				TotalPathCount:    result.Counts.Paths,
				LeaseHeld:         true,
			},
		},
		Paths: paths,
	})
	if err != nil {
		t.Fatalf("securitypathdelta.NewSnapshot(%s) error = %v", observationID, err)
	}
	if snapshot.Completeness.State != securitypathdelta.CompletenessComplete {
		t.Fatalf("snapshot %s completeness = %#v, want complete", observationID, snapshot.Completeness)
	}
	return snapshot
}
