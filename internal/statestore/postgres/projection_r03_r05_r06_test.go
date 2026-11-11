package postgres

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// TestPostgresCleanupProjectedEntitiesMigratesPreAssertionLegacyRows
// reproduces the R03 confirmed failure directly: a deployed pre-F06
// `entity_links` row (legacy source/runtime provenance, no
// `entity_link_assertions` row at all) survives the documented
// tenant/source/runtime/entity-type-scoped cleanup forever, because the
// new cleanup only retracts assertions. It seeds the row with raw SQL
// (never through UpsertProjectedLink, which would create an assertion the
// deployed legacy rows never had), then exercises the real
// CleanupProjectedEntities entrypoint the CLI's
// `graph cleanup-projected-entities` command calls: dry-run preview,
// apply (must migrate the trustworthy legacy row into a real assertion
// and then actually delete the link/finding), and an idempotent repeat
// apply. It also proves an already-quarantined (conflicting-provenance)
// legacy row is preserved and reported, never silently retired.
func TestPostgresCleanupProjectedEntitiesMigratesPreAssertionLegacyRows(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)

	asset := fmt.Sprintf("urn:cerebro:%s:external_asset:admin.writer.com", tenantID)
	legacyFinding := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:legacy-vuln-1", tenantID)
	quarantinedFinding := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:legacy-vuln-2", tenantID)
	const legacySource = "vulnview"
	const legacyRuntime = "writer-vulnview-vulnerability"

	for _, entity := range []*ports.ProjectedEntity{
		{URN: asset, TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime, EntityType: "external.asset", Label: "admin.writer.com"},
		{URN: legacyFinding, TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime, EntityType: "vulnview.finding", Label: "legacy-vuln-1"},
		{URN: quarantinedFinding, TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime, EntityType: "vulnview.finding", Label: "legacy-vuln-2"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}

	// Raw pre-F06 logical row: legacy tenant/source/runtime provenance
	// recorded directly on entity_links, but no entity_link_assertions
	// row at all -- exactly the deployed shape the confirmed failure
	// describes, never produced by today's UpsertProjectedLink.
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json)
VALUES ($1, 'has_evidence', $2, $3, $4, $5, '{"event_id":"legacy-evt-1"}'::jsonb)`,
		asset, legacyFinding, tenantID, legacySource, legacyRuntime); err != nil {
		t.Fatalf("seed raw legacy entity_links row: %v", err)
	}

	// A second legacy row in the exact same scope, but already flagged
	// assertion_quarantined (a conflicting assertion from another writer
	// arrived since): insufficient provenance, must never be migrated or
	// deleted, only reported as still matched.
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json, assertion_quarantined)
VALUES ($1, 'has_evidence', $2, $3, $4, $5, '{"event_id":"legacy-evt-2"}'::jsonb, true)`,
		asset, quarantinedFinding, tenantID, legacySource, legacyRuntime); err != nil {
		t.Fatalf("seed raw quarantined legacy entity_links row: %v", err)
	}

	request := ports.ProjectionCleanupRequest{
		TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime,
		EntityTypes: []string{"vulnview.finding"}, OnlyIsolated: false, DryRun: true,
	}

	// Preview: both legacy findings match, only the non-quarantined one
	// is reported migratable, and nothing is mutated yet.
	dryRun, err := store.CleanupProjectedEntities(ctx, request)
	if err != nil {
		t.Fatalf("dry-run cleanup error = %v", err)
	}
	if dryRun.EntitiesMatched != 2 {
		t.Fatalf("dry-run EntitiesMatched = %d, want 2 (both legacy findings)", dryRun.EntitiesMatched)
	}
	if dryRun.LinksMigrated != 1 {
		t.Fatalf("dry-run LinksMigrated = %d, want 1 (quarantined row excluded)", dryRun.LinksMigrated)
	}
	if dryRun.EntitiesDeleted != 0 || dryRun.LinksDeleted != 0 {
		t.Fatalf("dry-run mutated state: %#v", dryRun)
	}

	// Apply: the confirmed failure's exact reproduction -- before the
	// fix this matched the finding but deleted no link or entity.
	request.DryRun = false
	applied, err := store.CleanupProjectedEntities(ctx, request)
	if err != nil {
		t.Fatalf("apply cleanup error = %v", err)
	}
	if applied.EntitiesMatched != 2 {
		t.Fatalf("apply EntitiesMatched = %d, want 2", applied.EntitiesMatched)
	}
	if applied.LinksMigrated != 1 {
		t.Fatalf("apply LinksMigrated = %d, want 1", applied.LinksMigrated)
	}
	if applied.LinksDeleted == 0 {
		t.Fatalf("apply LinksDeleted = %d, want the migrated legacy link retracted", applied.LinksDeleted)
	}
	if applied.EntitiesDeleted != 1 {
		t.Fatalf("apply EntitiesDeleted = %d, want exactly the non-quarantined legacy finding", applied.EntitiesDeleted)
	}

	// The legacy link and finding are genuinely gone.
	assertPostgresProjectedLinkMissing(t, ctx, store, &ports.ProjectedLink{FromURN: asset, Relation: "has_evidence", ToURN: legacyFinding})
	if stored, err := store.GetProjectedEntity(ctx, legacyFinding); err != nil || stored != nil {
		t.Fatalf("legacy finding survived cleanup: err=%v stored=%#v", err, stored)
	}

	// The quarantined, insufficient-provenance row is preserved exactly:
	// its link, its finding, and its quarantined flag all survive.
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: asset, Relation: "has_evidence", ToURN: quarantinedFinding})
	if stored, err := store.GetProjectedEntity(ctx, quarantinedFinding); err != nil || stored == nil {
		t.Fatalf("quarantined legacy finding was deleted despite insufficient provenance: err=%v stored=%#v", err, stored)
	}
	var stillQuarantined bool
	if err := store.db.QueryRowContext(ctx, `SELECT assertion_quarantined FROM entity_links WHERE from_urn=$1 AND relation='has_evidence' AND to_urn=$2`, asset, quarantinedFinding).Scan(&stillQuarantined); err != nil {
		t.Fatalf("read quarantined row: %v", err)
	}
	if !stillQuarantined {
		t.Fatal("quarantined legacy row's flag was cleared by cleanup")
	}

	// The shared asset is never a cleanup candidate (its own entity_type
	// is not in scope) and must survive untouched.
	if stored, err := store.GetProjectedEntity(ctx, asset); err != nil || stored == nil {
		t.Fatalf("shared asset was deleted by legacy finding cleanup: err=%v stored=%#v", err, stored)
	}

	// Idempotent repeat apply: the migrated/deleted finding no longer
	// matches; only the quarantined one remains, still untouched.
	rerun, err := store.CleanupProjectedEntities(ctx, request)
	if err != nil {
		t.Fatalf("idempotent rerun error = %v", err)
	}
	if rerun.EntitiesMatched != 1 {
		t.Fatalf("rerun EntitiesMatched = %d, want 1 (only the quarantined finding still matches)", rerun.EntitiesMatched)
	}
	if rerun.LinksMigrated != 0 || rerun.LinksDeleted != 0 || rerun.EntitiesDeleted != 0 {
		t.Fatalf("rerun mutated state: %#v, want an all-zero no-op", rerun)
	}
}

// TestPostgresReplaceProjectedLinkSetsConcurrentCrossLockOrderNoDeadlock
// reproduces the R05 confirmed failure: runtime A initially asserts
// owner->Z and replaces its set with {A}; runtime B initially asserts
// owner->A and concurrently replaces its set with {Z}. Both transactions
// touch the exact same two logical keys (owner->A, owner->Z); locking
// the retraction phase and the assertion phase in two separately sorted
// passes let the two transactions acquire them in opposite order and
// deadlock (SQLSTATE 40P01). A disposable AFTER DELETE trigger on
// entity_links pauses logical-link deletion, mirroring the review's own
// reproduction technique, to force genuine overlap while each real store
// transaction holds its naturally acquired locks instead of trivially
// serializing. Both operations must complete and leave the correct
// per-runtime assertions and logical links.
func TestPostgresReplaceProjectedLinkSetsConcurrentCrossLockOrderNoDeadlock(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	a := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	z := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/z", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: a, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "a"},
		{URN: z, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "z"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}

	nonce := strings.ReplaceAll(strings.ReplaceAll(tenantID, "-", "_"), ".", "_")
	fnName := "r05_barrier_fn_" + nonce
	trgName := "r05_barrier_trg_" + nonce
	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %s() RETURNS trigger AS $BARRIER$
BEGIN
  IF OLD.tenant_id = '%s' THEN
    PERFORM pg_sleep(1);
  END IF;
  RETURN OLD;
END;
$BARRIER$ LANGUAGE plpgsql`, fnName, tenantID)); err != nil {
		t.Fatalf("create disposable barrier function: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON entity_links`, trgName))
		_, _ = store.db.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fnName))
	})
	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE TRIGGER %s AFTER DELETE ON entity_links
FOR EACH ROW EXECUTE FUNCTION %s()`, trgName, fnName)); err != nil {
		t.Fatalf("create disposable barrier trigger: %v", err)
	}

	// Exercise the scenario, then again with the roles the opposite way
	// round (a fresh relation so the two runs cannot interfere), proving
	// the fix is independent of which side happens to acquire first.
	t.Run("a_to_z_and_b_to_a", func(t *testing.T) {
		runScenarioCrossLock(t, ctx, store, tenantID, owner, a, z, "associated_with_1")
	})
	t.Run("reversed_initial_assignment", func(t *testing.T) {
		runScenarioCrossLock(t, ctx, store, tenantID, owner, z, a, "associated_with_2")
	})
}

// runScenarioCrossLock seeds runtime-a -> initialA and runtime-b ->
// initialB on the same owner/relation scope, then concurrently swaps
// them (runtime-a -> initialB, runtime-b -> initialA), and asserts both
// operations succeed with the correct final per-runtime ownership.
func runScenarioCrossLock(t *testing.T, ctx context.Context, store *Store, tenantID string, owner string, initialA string, initialB string, relation string) {
	t.Helper()
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-a",
		OwnerURN: owner, Relation: relation, Outgoing: true,
		Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-a", FromURN: owner, ToURN: initialA, Relation: relation}},
		Observation: map[string]string{"at": "2026-11-02T09:00:00Z"},
	}}); err != nil {
		t.Fatalf("seed runtime-a initial: %v", err)
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-b",
		OwnerURN: owner, Relation: relation, Outgoing: true,
		Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-b", FromURN: owner, ToURN: initialB, Relation: relation}},
		Observation: map[string]string{"at": "2026-11-02T09:00:00Z"},
	}}); err != nil {
		t.Fatalf("seed runtime-b initial: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-a",
			OwnerURN: owner, Relation: relation, Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-a", FromURN: owner, ToURN: initialB, Relation: relation}},
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}})
	}()
	go func() {
		defer wg.Done()
		errs[1] = store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-b",
			OwnerURN: owner, Relation: relation, Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-b", FromURN: owner, ToURN: initialA, Relation: relation}},
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}})
	}()
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent replace %d error = %v (want no SQLSTATE 40P01 deadlock)", i, err)
		}
	}

	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: relation, ToURN: initialA})
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: relation, ToURN: initialB})

	var aSourceID, aRuntimeID string
	if err := store.db.QueryRowContext(ctx, `SELECT source_id, runtime_id FROM entity_link_assertions WHERE from_urn=$1 AND relation=$2 AND to_urn=$3 AND tenant_id=$4`, owner, relation, initialA, tenantID).Scan(&aSourceID, &aRuntimeID); err != nil {
		t.Fatalf("read surviving assertion for initialA: %v", err)
	}
	if aRuntimeID != "runtime-b" {
		t.Fatalf("owner->initialA assertion runtime = %q, want runtime-b", aRuntimeID)
	}
	var bSourceID, bRuntimeID string
	if err := store.db.QueryRowContext(ctx, `SELECT source_id, runtime_id FROM entity_link_assertions WHERE from_urn=$1 AND relation=$2 AND to_urn=$3 AND tenant_id=$4`, owner, relation, initialB, tenantID).Scan(&bSourceID, &bRuntimeID); err != nil {
		t.Fatalf("read surviving assertion for initialB: %v", err)
	}
	if bRuntimeID != "runtime-a" {
		t.Fatalf("owner->initialB assertion runtime = %q, want runtime-a", bRuntimeID)
	}
	if aSourceID != "vulnview" || bSourceID != "vulnview" {
		t.Fatalf("unexpected source ids: a=%q b=%q", aSourceID, bSourceID)
	}

	// Each runtime's own prior assertion of the opposite URN must be
	// fully retracted, not merely shadowed.
	var staleCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_link_assertions WHERE from_urn=$1 AND relation=$2 AND to_urn=$3 AND tenant_id=$4 AND runtime_id='runtime-a'`, owner, relation, initialA, tenantID).Scan(&staleCount); err != nil {
		t.Fatalf("count stale runtime-a assertion: %v", err)
	}
	if staleCount != 0 {
		t.Fatalf("runtime-a's retracted owner->initialA assertion still present")
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_link_assertions WHERE from_urn=$1 AND relation=$2 AND to_urn=$3 AND tenant_id=$4 AND runtime_id='runtime-b'`, owner, relation, initialB, tenantID).Scan(&staleCount); err != nil {
		t.Fatalf("count stale runtime-b assertion: %v", err)
	}
	if staleCount != 0 {
		t.Fatalf("runtime-b's retracted owner->initialB assertion still present")
	}
}

// TestPostgresReplaceProjectedLinkSetsEndpointsGuardedMaterialization
// proves the R06 PostgreSQL endpoint contract through the real
// ReplaceProjectedLinkSets entrypoint: a stale set carrying Endpoints
// creates nothing; an accepted set creates each absent CreateOnly
// endpoint; a provider-owned existing entity is left completely
// untouched by a later link-set's CreateOnly endpoint for the same URN;
// and replaying the same accepted observation version is an idempotent
// no-op.
func TestPostgresReplaceProjectedLinkSetsEndpointsGuardedMaterialization(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	consumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/consumer", tenantID)
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal",
	}); err != nil {
		t.Fatalf("upsert owner entity: %v", err)
	}

	endpointStub := func() *ports.ProjectedEntity {
		return &ports.ProjectedEntity{
			URN: consumer, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			EntityType: "kubernetes_service_account", Label: "consumer-stub", CreateOnly: true,
			Attributes: map[string]string{"stub": "true"},
		}
	}
	linkSetAt := func(at string) *ports.ProjectedLinkSet {
		return &ports.ProjectedLinkSet{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			OwnerURN: owner, Relation: "associated_with", Outgoing: true,
			Links: []*ports.ProjectedLink{{
				TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
				FromURN: owner, ToURN: consumer, Relation: "associated_with",
			}},
			Observation: map[string]string{"at": at},
			Endpoints:   []*ports.ProjectedEntity{endpointStub()},
		}
	}

	// Establish the guard at T2 first (Incomplete: no links/endpoints).
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: "associated_with", Outgoing: true,
		Incomplete:  true,
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
	}}); err != nil {
		t.Fatalf("advance guard to T2: %v", err)
	}

	// Stale set (T1 < T2) carrying both Links and Endpoints: must create
	// neither the link nor the endpoint entity.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{linkSetAt("2026-11-02T09:00:00Z")}); err != nil {
		t.Fatalf("apply stale set: %v", err)
	}
	assertPostgresProjectedLinkMissing(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumer})
	if stored, err := store.GetProjectedEntity(ctx, consumer); err != nil || stored != nil {
		t.Fatalf("stale set created the endpoint entity: err=%v stored=%#v", err, stored)
	}

	// Accepted set (T3 > T2): creates the missing endpoint and asserts the link.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{linkSetAt("2026-11-02T11:00:00Z")}); err != nil {
		t.Fatalf("apply accepted set: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumer})
	created, err := store.GetProjectedEntity(ctx, consumer)
	if err != nil || created == nil {
		t.Fatalf("accepted set did not create the endpoint entity: err=%v", err)
	}
	if created.Label != "consumer-stub" || created.Attributes["stub"] != "true" {
		t.Fatalf("created endpoint entity = %#v, want the CreateOnly stub's own fields", created)
	}

	// Same-version replay: idempotent no-op, no error, no duplicate/second write.
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{linkSetAt("2026-11-02T11:00:00Z")}); err != nil {
		t.Fatalf("replay same version: %v", err)
	}
	replayed, err := store.GetProjectedEntity(ctx, consumer)
	if err != nil || replayed == nil {
		t.Fatalf("replay removed the endpoint entity: err=%v", err)
	}
	if replayed.Label != "consumer-stub" || replayed.Attributes["stub"] != "true" {
		t.Fatalf("replay changed the entity: %#v", replayed)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with", ToURN: consumer})

	// Provider-first: a different consumer entity already fully owned by
	// a real provider connector. A later link set's CreateOnly endpoint
	// for the exact same URN must leave it completely untouched.
	providerConsumer := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/provider-owned", tenantID)
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN: providerConsumer, TenantID: tenantID, SourceID: "kubernetes", RuntimeID: "kubernetes-runtime",
		EntityType: "kubernetes_service_account", Label: "real-provider-label",
		Attributes: map[string]string{"namespace": "ns", "owner": "provider"},
	}); err != nil {
		t.Fatalf("seed provider-owned entity: %v", err)
	}
	providerLinkSet := &ports.ProjectedLinkSet{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-2",
		OwnerURN: owner, Relation: "associated_with_provider", Outgoing: true,
		Links: []*ports.ProjectedLink{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-2",
			FromURN: owner, ToURN: providerConsumer, Relation: "associated_with_provider",
		}},
		Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		Endpoints: []*ports.ProjectedEntity{{
			URN: providerConsumer, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-2",
			EntityType: "kubernetes_service_account", Label: "stub-label-must-not-apply", CreateOnly: true,
			Attributes: map[string]string{"stub": "true"},
		}},
	}
	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{providerLinkSet}); err != nil {
		t.Fatalf("apply provider-first set: %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: "associated_with_provider", ToURN: providerConsumer})
	untouched, err := store.GetProjectedEntity(ctx, providerConsumer)
	if err != nil || untouched == nil {
		t.Fatalf("provider-owned entity missing after link set: err=%v", err)
	}
	if untouched.SourceID != "kubernetes" || untouched.RuntimeID != "kubernetes-runtime" || untouched.Label != "real-provider-label" || untouched.Attributes["owner"] != "provider" {
		t.Fatalf("provider-owned entity was overwritten by a CreateOnly endpoint: %#v", untouched)
	}
}

// TestPostgresReplaceProjectedLinkSetsEndpointInsertOrderNoDeadlock
// reproduces the RR04 confirmed failure directly: the R05/R06 logical-link
// lock order does not also order the guarded-endpoint entity inserts
// (set.Endpoints), so two distinct finding owners with disjoint logical
// link locks, sharing the same two absent consumer endpoints listed in
// reverse caller order, can each insert them in opposite orders and
// deadlock on the entities table (SQLSTATE 40P01).
//
// A disposable AFTER INSERT trigger on entities pauses each transaction
// behind a controller-held advisory lock immediately after that
// transaction's own first endpoint insert (pg_advisory_xact_lock is
// reentrant within one transaction, so only the first qualifying insert
// actually blocks). The controller releases the barrier once it observes
// either shape that can legitimately occur next: both transactions
// waiting at the barrier (the pre-fix caller-order shape, when each
// transaction's own first insert targets a different row), or one
// transaction already waiting on a lock held by the other (the
// canonical-order shape, when both transactions' first insert targets
// the very same row). Either way the test cannot hang, and releasing the
// barrier at that point deterministically reproduces the deadlock
// pre-fix and the race-free completion post-fix.
func TestPostgresReplaceProjectedLinkSetsEndpointInsertOrderNoDeadlock(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	ownerF1 := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:f1", tenantID)
	ownerF2 := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:f2", tenantID)
	endpointA := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/a", tenantID)
	endpointB := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/b", tenantID)
	for _, entity := range []*ports.ProjectedEntity{
		{URN: ownerF1, TenantID: tenantID, SourceID: "vulnview", EntityType: "vulnview_finding", Label: "f1"},
		{URN: ownerF2, TenantID: tenantID, SourceID: "vulnview", EntityType: "vulnview_finding", Label: "f2"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert owner entity %s: %v", entity.URN, err)
		}
	}

	nonce := time.Now().UnixNano()
	const lockClass = int32(0x72723034) // "rr04"
	lockObject := int32(nonce & 0x3fffffff)
	if lockObject == 0 {
		lockObject = 1
	}
	safeTenant := strings.ReplaceAll(strings.ReplaceAll(tenantID, "-", "_"), ".", "_")
	fnName := "rr04_endpoint_barrier_fn_" + safeTenant
	trgName := "rr04_endpoint_barrier_trg_" + safeTenant
	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %s() RETURNS trigger AS $BARRIER$
BEGIN
  IF NEW.tenant_id = '%s' AND NEW.urn IN ('%s', '%s') THEN
    PERFORM pg_advisory_xact_lock(%d, %d);
  END IF;
  RETURN NEW;
END;
$BARRIER$ LANGUAGE plpgsql`, fnName, tenantID, endpointA, endpointB, lockClass, lockObject)); err != nil {
		t.Fatalf("create disposable endpoint barrier function: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON entities`, trgName))
		_, _ = store.db.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fnName))
	})
	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE TRIGGER %s AFTER INSERT ON entities
FOR EACH ROW EXECUTE FUNCTION %s()`, trgName, fnName)); err != nil {
		t.Fatalf("create disposable endpoint barrier trigger: %v", err)
	}

	controller, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatalf("open controller connection: %v", err)
	}
	barrierHeld := true
	t.Cleanup(func() {
		if barrierHeld {
			_, _ = controller.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1, $2)`, lockClass, lockObject)
		}
		_ = controller.Close()
	})
	if _, err := controller.ExecContext(ctx, `SELECT pg_advisory_lock($1, $2)`, lockClass, lockObject); err != nil {
		t.Fatalf("acquire controller barrier lock: %v", err)
	}

	endpointStub := func(urn string) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{
			URN: urn, TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-rr04",
			EntityType: "kubernetes_service_account", Label: urn, CreateOnly: true,
		}
	}
	linkSet := func(owner string, relation string, endpointOrder []string) *ports.ProjectedLinkSet {
		links := make([]*ports.ProjectedLink, len(endpointOrder))
		endpoints := make([]*ports.ProjectedEntity, len(endpointOrder))
		for i, urn := range endpointOrder {
			links[i] = &ports.ProjectedLink{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-rr04", FromURN: owner, ToURN: urn, Relation: relation}
			endpoints[i] = endpointStub(urn)
		}
		return &ports.ProjectedLinkSet{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-rr04",
			OwnerURN: owner, Relation: relation, Outgoing: true,
			Links: links, Endpoints: endpoints,
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{linkSet(ownerF1, "has_consumer", []string{endpointA, endpointB})})
	}()
	go func() {
		defer wg.Done()
		errs[1] = store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{linkSet(ownerF2, "has_consumer", []string{endpointB, endpointA})})
	}()

	deadline := time.Now().Add(15 * time.Second)
	for {
		var blocked int
		if err := store.db.QueryRowContext(ctx, `
SELECT count(*) FROM pg_stat_activity
WHERE wait_event_type = 'Lock' AND query ILIKE '%INSERT INTO entities%' AND pid <> pg_backend_pid()`).Scan(&blocked); err != nil {
			t.Fatalf("poll blocked backends: %v", err)
		}
		if blocked > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a concurrent endpoint insert to block (barrier or row lock)")
		}
		time.Sleep(5 * time.Millisecond)
	}

	var unlocked bool
	if err := controller.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1, $2)`, lockClass, lockObject).Scan(&unlocked); err != nil {
		t.Fatalf("release controller barrier lock: %v", err)
	}
	if !unlocked {
		t.Fatal("release controller barrier lock = false")
	}
	barrierHeld = false

	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent ReplaceProjectedLinkSets %d error = %v (want no SQLSTATE 40P01 deadlock)", i, err)
		}
	}

	for _, urn := range []string{endpointA, endpointB} {
		stored, err := store.GetProjectedEntity(ctx, urn)
		if err != nil || stored == nil {
			t.Fatalf("endpoint %s missing after both concurrent sets: err=%v", urn, err)
		}
	}
	var markerCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM link_set_observations WHERE tenant_id = $1 AND owner_urn IN ($2, $3) AND relation = 'has_consumer'`, tenantID, ownerF1, ownerF2).Scan(&markerCount); err != nil {
		t.Fatalf("count observation markers: %v", err)
	}
	if markerCount != 2 {
		t.Fatalf("observation marker count = %d, want 2", markerCount)
	}
	var assertionCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM entity_link_assertions WHERE tenant_id = $1 AND relation = 'has_consumer' AND from_urn IN ($2, $3)`, tenantID, ownerF1, ownerF2).Scan(&assertionCount); err != nil {
		t.Fatalf("count link assertions: %v", err)
	}
	if assertionCount != 4 {
		t.Fatalf("link assertion count = %d, want 4 (2 owners x 2 endpoints)", assertionCount)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: ownerF1, Relation: "has_consumer", ToURN: endpointA})
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: ownerF1, Relation: "has_consumer", ToURN: endpointB})
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: ownerF2, Relation: "has_consumer", ToURN: endpointA})
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: ownerF2, Relation: "has_consumer", ToURN: endpointB})
}

// TestPostgresReplaceProjectedLinkSetsDoesNotDeleteConcurrentlyAssertedKeyWithoutReconciling
// reproduces GraphReview finding #1: replaceProjectedLinkSet plans
// currentScope, locks that snapshot plus the desired keys, then retracts
// every scope assertion not in the desired set with a WHERE clause that
// is not restricted to the planned/locked keys. A concurrent, perfectly
// supported UpsertProjectedLink for a brand-new key in the exact same
// (tenant, source, runtime, owner, relation) scope, committed between
// planning and the retraction, is swept up by that broad DELETE without
// ever being reconciled: its entity_link_assertions row disappears but
// its entity_links logical row survives, orphaned (assertion_managed
// true, zero backing assertions). The race is forced deterministically
// by holding one of the planned keys' advisory lock open from a second
// connection so the real ReplaceProjectedLinkSets call blocks inside its
// own lock-acquisition loop, giving the real concurrent UpsertProjectedLink
// call time to commit before the lock is released.
func TestPostgresReplaceProjectedLinkSetsDoesNotDeleteConcurrentlyAssertedKeyWithoutReconciling(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	x := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/x", tenantID)
	y := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/y", tenantID)
	const relation = "associated_with"
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: x, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "x"},
		{URN: y, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "y"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}

	if err := store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		OwnerURN: owner, Relation: relation, Outgoing: true,
		Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1", FromURN: owner, ToURN: x, Relation: relation}},
		Observation: map[string]string{"at": "2026-11-02T09:00:00Z"},
	}}); err != nil {
		t.Fatalf("seed initial {X}: %v", err)
	}

	// Hold X's advisory lock from a separate connection/transaction so
	// the real ReplaceProjectedLinkSets call below blocks inside its own
	// lock-acquisition loop before it ever reaches the retraction delete.
	conn, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve barrier connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatalf("begin barrier tx: %v", err)
	}
	lockKey := projectedLinkLockKey(tenantID, owner, relation, x)
	if _, err := conn.ExecContext(ctx, projectedLinkAdvisoryLockSQL, lockKey); err != nil {
		t.Fatalf("acquire barrier lock: %v", err)
	}

	replaceDone := make(chan error, 1)
	go func() {
		replaceDone <- store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			OwnerURN: owner, Relation: relation, Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1", FromURN: owner, ToURN: x, Relation: relation}},
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}})
	}()
	// Give the goroutine time to start and block on X's held lock.
	time.Sleep(300 * time.Millisecond)

	// Real concurrent, perfectly supported write: a brand-new key Y in
	// the exact same scope, never part of replaceProjectedLinkSet's plan.
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		FromURN: owner, ToURN: y, Relation: relation,
	}); err != nil {
		t.Fatalf("concurrent UpsertProjectedLink(Y): %v", err)
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: relation, ToURN: y})

	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatalf("release barrier lock: %v", err)
	}

	select {
	case err := <-replaceDone:
		if err != nil {
			t.Fatalf("ReplaceProjectedLinkSets() error = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ReplaceProjectedLinkSets() did not complete after releasing the barrier lock")
	}

	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: relation, ToURN: x})

	var yAssertionCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_link_assertions WHERE from_urn=$1 AND relation=$2 AND to_urn=$3`, owner, relation, y).Scan(&yAssertionCount); err != nil {
		t.Fatalf("count Y assertions: %v", err)
	}
	if yAssertionCount != 0 {
		t.Fatalf("Y's concurrently-asserted assertion was not retracted: count=%d", yAssertionCount)
	}
	// The real bug: Y's logical row survives, orphaned, even though its
	// only assertion was deleted, because it was never part of the plan
	// that got reconciled.
	assertPostgresProjectedLinkMissing(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: relation, ToURN: y})
}

// TestPostgresUpsertProjectedLinkAndReplaceProjectedLinkSetDoNotDeadlock
// reproduces GraphReview finding #2: UpsertProjectedLink INSERTs/UPDATEs
// the assertion row (taking its row lock) before reconcileProjectedLink
// takes the logical-link advisory lock, while replaceProjectedLinkSet
// takes the advisory lock first and only then upserts the same assertion
// row. A disposable trigger slows down the assertion row write just
// enough to force both transactions to hold their own first lock while
// wanting the other's, reproducing SQLSTATE 40P01.
func TestPostgresUpsertProjectedLinkAndReplaceProjectedLinkSetDoNotDeadlock(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	owner := fmt.Sprintf("urn:cerebro:%s:aws_role:principal", tenantID)
	k := fmt.Sprintf("urn:cerebro:%s:kubernetes_service_account:ns/k", tenantID)
	const relation = "associated_with"
	for _, entity := range []*ports.ProjectedEntity{
		{URN: owner, TenantID: tenantID, SourceID: "vulnview", EntityType: "aws_role", Label: "principal"},
		{URN: k, TenantID: tenantID, SourceID: "vulnview", EntityType: "kubernetes_service_account", Label: "k"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
		FromURN: owner, ToURN: k, Relation: relation,
	}); err != nil {
		t.Fatalf("seed initial K: %v", err)
	}

	nonce := strings.ReplaceAll(strings.ReplaceAll(tenantID, "-", "_"), ".", "_")
	fnName := "issue2_barrier_fn_" + nonce
	trgName := "issue2_barrier_trg_" + nonce
	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %s() RETURNS trigger AS $BARRIER$
BEGIN
  IF NEW.tenant_id = '%s' THEN
    PERFORM pg_sleep(1);
  END IF;
  RETURN NEW;
END;
$BARRIER$ LANGUAGE plpgsql`, fnName, tenantID)); err != nil {
		t.Fatalf("create disposable barrier function: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON entity_link_assertions`, trgName))
		_, _ = store.db.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fnName))
	})
	if _, err := store.db.ExecContext(ctx, fmt.Sprintf(`
CREATE TRIGGER %s BEFORE INSERT OR UPDATE ON entity_link_assertions
FOR EACH ROW EXECUTE FUNCTION %s()`, trgName, fnName)); err != nil {
		t.Fatalf("create disposable barrier trigger: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			FromURN: owner, ToURN: k, Relation: relation,
			Attributes: map[string]string{"replay": "true"},
		})
	}()
	time.Sleep(200 * time.Millisecond)
	go func() {
		defer wg.Done()
		errs[1] = store.ReplaceProjectedLinkSets(ctx, []*ports.ProjectedLinkSet{{
			TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1",
			OwnerURN: owner, Relation: relation, Outgoing: true,
			Links:       []*ports.ProjectedLink{{TenantID: tenantID, SourceID: "vulnview", RuntimeID: "runtime-1", FromURN: owner, ToURN: k, Relation: relation}},
			Observation: map[string]string{"at": "2026-11-02T10:00:00Z"},
		}})
	}()
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent call %d error = %v (want no SQLSTATE 40P01 deadlock)", i, err)
		}
	}
	assertPostgresProjectedLinkExists(t, ctx, store, &ports.ProjectedLink{FromURN: owner, Relation: relation, ToURN: k})
}

// TestPostgresCleanupProjectedEntitiesPrioritizesActionableCandidatesOverQuarantinedBlockers
// reproduces GraphReview finding #3: an entity a quarantined legacy edge
// keeps alive sorts ahead of a different, genuinely migratable entity by
// plain URN order. With a small limit, every pass reselects the
// permanently-blocked entity and never reaches the migratable one, so
// "repeat until entities_matched reaches 0" (and, short of that, any
// actual progress) never happens.
func TestPostgresCleanupProjectedEntitiesPrioritizesActionableCandidatesOverQuarantinedBlockers(t *testing.T) {
	ctx := context.Background()
	store, tenantID := openPostgresProjectionTestStore(t)
	asset := fmt.Sprintf("urn:cerebro:%s:external_asset:admin.writer.com", tenantID)
	// "a-blocked" sorts before "b-actionable" in plain URN order.
	blockedFinding := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:a-blocked", tenantID)
	actionableFinding := fmt.Sprintf("urn:cerebro:%s:vulnview_finding:b-actionable", tenantID)
	const legacySource = "vulnview"
	const legacyRuntime = "writer-vulnview-vulnerability"
	for _, entity := range []*ports.ProjectedEntity{
		{URN: asset, TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime, EntityType: "external.asset", Label: "admin.writer.com"},
		{URN: blockedFinding, TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime, EntityType: "vulnview.finding", Label: "a-blocked"},
		{URN: actionableFinding, TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime, EntityType: "vulnview.finding", Label: "b-actionable"},
	} {
		if err := store.UpsertProjectedEntity(ctx, entity); err != nil {
			t.Fatalf("upsert entity %s: %v", entity.URN, err)
		}
	}
	// blockedFinding's link is already quarantined (insufficient
	// provenance): it will never be migrated or deleted by this cleanup.
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json, assertion_quarantined)
VALUES ($1, 'has_evidence', $2, $3, $4, $5, '{"event_id":"blocked"}'::jsonb, true)`,
		asset, blockedFinding, tenantID, legacySource, legacyRuntime); err != nil {
		t.Fatalf("seed quarantined blocked row: %v", err)
	}
	// actionableFinding's link is a clean legacy pre-assertion row: it
	// will be migrated and fully retracted in one pass.
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json)
VALUES ($1, 'has_evidence', $2, $3, $4, $5, '{"event_id":"actionable"}'::jsonb)`,
		asset, actionableFinding, tenantID, legacySource, legacyRuntime); err != nil {
		t.Fatalf("seed actionable legacy row: %v", err)
	}

	request := ports.ProjectionCleanupRequest{
		TenantID: tenantID, SourceID: legacySource, RuntimeID: legacyRuntime,
		EntityTypes: []string{"vulnview.finding"}, OnlyIsolated: false, Limit: 1,
	}
	result, err := store.CleanupProjectedEntities(ctx, request)
	if err != nil {
		t.Fatalf("limited cleanup pass error = %v", err)
	}
	if result.EntitiesMatched != 1 {
		t.Fatalf("limited pass EntitiesMatched = %d, want exactly 1 (limit=1)", result.EntitiesMatched)
	}
	if result.EntitiesDeleted != 1 {
		t.Fatalf("limited pass EntitiesDeleted = %d, want the actionable entity deleted despite limit=1 and a lower-sorting blocked entity", result.EntitiesDeleted)
	}
	if stored, err := store.GetProjectedEntity(ctx, actionableFinding); err != nil || stored != nil {
		t.Fatalf("actionable finding survived a limit=1 pass: err=%v stored=%#v", err, stored)
	}
	if stored, err := store.GetProjectedEntity(ctx, blockedFinding); err != nil || stored == nil {
		t.Fatalf("blocked finding was deleted (should still be quarantined): err=%v stored=%#v", err, stored)
	}
}
