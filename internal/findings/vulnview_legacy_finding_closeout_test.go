package findings_test

// TestTombstoneFindingsBulk_VulnViewRetiredRuleCloseout is the C5 retirement
// regression for rule-derived finding rows (as opposed to the graph
// entities/links covered by cmd/cerebro's
// TestVulnViewLegacyGraphStateCloseoutIntegration).
//
// `vulnview-actionable-external-finding` (vulnview_signal_rule.go) and
// `vulnview-external-asset-concentrated-signal` (vulnview_graph_rule.go)
// are now fully retired: neither rule ever emits a finding again, from any
// vulnview.finding event or runtime. That makes every still-open row under
// either rule id invalid, regardless of which runtime created it or most
// recently re-asserted it -- the runtime-identity distinction a prior,
// narrower migration phase needed (an orphaned legacy-runtime row versus a
// row a currently-active runtime kept re-asserting onto the same
// fingerprint) no longer matters, because no runtime -- legacy or current
// -- can ever produce a valid open row under these rule ids again.
//
// Per Contract C5 and docs/VULNVIEW_LEGACY_CLOSEOUT.md (private deploy
// repo), the documented procedure selects by tenant + the two rule ids
// alone, with no RuntimeIDs and no OlderThan: internal/findings/closeout.go
// CloseoutSelector.RuntimeIDs is optional (ports.FindingMatchesRuntimeIDs
// always matches an empty scope), so the selector already supports this
// without any code change. last_observed_at staleness is still not a safe
// selector on its own (it reflects the exported finding's own updatedAt,
// not Cerebro import wall-clock time), but it is also no longer needed:
// rule id alone is sufficient once the rule is retired.
//
// This test seeds nine rows directly (bypassing rule evaluation, same
// pattern as TestService_TombstonedFindingEmitMintsFreshGraphEdge), all with
// an OLD last_observed_at (proving no OlderThan cutoff is needed), covering
// every runtime-identity variant the prior migration phase distinguished,
// for BOTH retired rule ids:
//   - a pre-cutover orphan: legacy runtime_id, legacy source_runtime_id;
//   - a legacy row with no source_runtime_id attribute at all;
//   - a converged row: legacy runtime_id, but a *new*, non-legacy
//     source_runtime_id (the shape a currently-active runtime produces by
//     re-asserting the identical fingerprint onto a legacy row);
//   - a row created directly by a new, non-legacy finding runtime
//     (writer-vulnview-<source>).
//
// Plus two rows the selector must leave untouched: an unrelated rule in the
// same tenant, and a row under one of the retired rule ids in a *different*
// tenant.
//
// It then runs findings.Service.TombstoneFindingsBulk (the same primitive
// cmd/cerebro's `closeout` CLI and .github/workflows/closeout.yml drive)
// scoped to the tenant and the two retired rule ids only -- no RuntimeIDs,
// no OlderThan: dry run proposes exactly the eight retired-rule rows and
// tombstones nothing, apply tombstones exactly those eight (the row
// survives with tombstoned=true, proving preservation rather than
// deletion), and a repeat apply is a no-op (idempotent). The unrelated-rule
// and other-tenant rows are verified untouched throughout.
//
// A separate, narrower dry run exercises the still-supported optional
// RuntimeIDs refinement (existing selector behavior, unchanged by
// retirement): scoping to just the legacy runtimes proposes only the
// legacy-runtime-pinned rows whose source_runtime_id (when present) is
// also a legacy runtime -- the orphan and no-attr rows -- and excludes the
// converged rows, whose source_runtime_id now names a non-legacy runtime.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
)

const (
	vulnViewLegacyCloseoutSignalRuleID = "vulnview-actionable-external-finding"
	vulnViewLegacyCloseoutGraphRuleID  = "vulnview-external-asset-concentrated-signal"
)

func TestTombstoneFindingsBulk_VulnViewRetiredRuleCloseout(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the VulnView retired-rule closeout integration test")
	}

	ctx := context.Background()
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-vulnview-retired-closeout-%d", nonce)
	otherTenantID := fmt.Sprintf("tenant-vulnview-retired-closeout-other-%d", nonce)
	legacyRuntimeID := "writer-vulnview-vulnerability"
	legacyRuntimeID2 := "writer-vulnview-dns-alert"
	newFindingRuntimeID := fmt.Sprintf("writer-vulnview-finding-nuclei-%d", nonce)
	unrelatedRuntimeID := fmt.Sprintf("runtime-unrelated-%d", nonce)

	// Every row is old: the selector must not rely on staleness at all.
	oldTimestamp := time.Now().UTC().Add(-365 * 24 * time.Hour).Truncate(time.Microsecond)

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_tombstone_events WHERE tenant_id = $1 OR tenant_id = $2`, tenantID, otherTenantID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1 OR tenant_id = $2`, tenantID, otherTenantID)
	})

	graph := newE2EGraphFake()
	appendLog := &recordingAppendLog{}
	closeoutStore := newStubCloseoutStore()
	tombstoneEventStore := newStubFindingTombstoneEventStore()
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{}}

	service := findings.New(runtimeStore, &stubReplayer{}, store, store, store, store).
		WithAppendLog(appendLog).
		WithGraphStore(graph).
		WithCloseoutStore(closeoutStore).
		WithFindingTombstoneEventStore(tombstoneEventStore)

	seed := func(id, ruleID, tenant, runtimeID, sourceRuntimeID string) {
		t.Helper()
		attrs := map[string]string{}
		if sourceRuntimeID != "" {
			attrs["source_runtime_id"] = sourceRuntimeID
		}
		record := &ports.FindingRecord{
			ID:              id,
			Fingerprint:     id,
			TenantID:        tenant,
			RuntimeID:       runtimeID,
			RuleID:          ruleID,
			Title:           "T " + id,
			Severity:        "MEDIUM",
			Status:          "open",
			Summary:         "S " + id,
			ResourceURNs:    []string{fmt.Sprintf("urn:cerebro:%s:external_asset:legacy-%d.example", tenant, nonce)},
			EventIDs:        []string{"event-" + id},
			Attributes:      attrs,
			FirstObservedAt: oldTimestamp,
			LastObservedAt:  oldTimestamp,
		}
		if _, err := store.UpsertFinding(ctx, record); err != nil {
			t.Fatalf("seed finding %q: %v", id, err)
		}
	}

	retiredRuleIDs := []string{vulnViewLegacyCloseoutSignalRuleID, vulnViewLegacyCloseoutGraphRuleID}
	var retiredIDs []string
	var legacyRuntimeIDs []string
	for _, ruleID := range retiredRuleIDs {
		suffix := strings.TrimPrefix(ruleID, "vulnview-")

		// Pre-cutover orphan: legacy runtime_id, source_runtime_id also
		// legacy (last touched by another legacy runtime).
		orphanID := fmt.Sprintf("f-%s-legacy-orphan-%d", suffix, nonce)
		seed(orphanID, ruleID, tenantID, legacyRuntimeID, legacyRuntimeID2)
		retiredIDs = append(retiredIDs, orphanID)
		legacyRuntimeIDs = append(legacyRuntimeIDs, orphanID)

		// Legacy row with no source_runtime_id attribute at all -- predates
		// that attribute, or was never re-emitted since creation either way.
		noAttrID := fmt.Sprintf("f-%s-legacy-no-attr-%d", suffix, nonce)
		seed(noAttrID, ruleID, tenantID, legacyRuntimeID, "")
		retiredIDs = append(retiredIDs, noAttrID)
		legacyRuntimeIDs = append(legacyRuntimeIDs, noAttrID)

		// Converged: pinned legacy runtime_id, but its source_runtime_id
		// attribute reflects a currently-active (non-legacy) finding
		// runtime that kept re-asserting the identical fingerprint. Under
		// retirement this is still invalid and must close by rule id
		// alone, even though it falls outside a legacy-runtime-only scope.
		convergedID := fmt.Sprintf("f-%s-converged-%d", suffix, nonce)
		seed(convergedID, ruleID, tenantID, legacyRuntimeID, newFindingRuntimeID)
		retiredIDs = append(retiredIDs, convergedID)

		// New-runtime: created directly by a non-legacy finding runtime.
		// Also invalid under retirement.
		newRuntimeRowID := fmt.Sprintf("f-%s-new-runtime-%d", suffix, nonce)
		seed(newRuntimeRowID, ruleID, tenantID, newFindingRuntimeID, newFindingRuntimeID)
		retiredIDs = append(retiredIDs, newRuntimeRowID)
	}

	// Unrelated: different rule and runtime, same tenant. Must survive.
	unrelatedID := fmt.Sprintf("f-unrelated-%d", nonce)
	seed(unrelatedID, "rule-some-other-detector", tenantID, unrelatedRuntimeID, unrelatedRuntimeID)

	// Another tenant's row under a retired rule id. Must survive: the
	// selector is tenant-scoped.
	otherTenantRowID := fmt.Sprintf("f-other-tenant-%d", nonce)
	seed(otherTenantRowID, vulnViewLegacyCloseoutSignalRuleID, otherTenantID, legacyRuntimeID, legacyRuntimeID2)

	// Separate assertion: an explicit RuntimeIDs filter still narrows
	// (existing optional selector behavior, unchanged by retirement). A
	// dry run only -- it must not tombstone anything before the main
	// unscoped flow below runs.
	narrowDryRun, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID:   tenantID,
			RuleIDs:    retiredRuleIDs,
			RuntimeIDs: []string{legacyRuntimeID, legacyRuntimeID2},
			Statuses:   []string{"open"},
		},
		Reason: "narrow RuntimeIDs selector regression (dry run only)",
		Actor:  "operator@writer.com",
		RunID:  fmt.Sprintf("run-narrow-dryrun-%d", nonce),
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("narrow RuntimeIDs dry-run TombstoneFindingsBulk: %v", err)
	}
	narrowProposed := map[string]struct{}{}
	for _, finding := range narrowDryRun.Proposed {
		narrowProposed[finding.ID] = struct{}{}
	}
	if len(narrowProposed) != len(legacyRuntimeIDs) {
		t.Fatalf("narrow RuntimeIDs dry-run proposed = %#v, want exactly %v", narrowProposed, legacyRuntimeIDs)
	}
	for _, id := range legacyRuntimeIDs {
		if _, ok := narrowProposed[id]; !ok {
			t.Fatalf("narrow RuntimeIDs dry-run proposed missing %q: got %#v", id, narrowProposed)
		}
	}
	for _, id := range retiredIDs {
		if _, legacy := narrowProposed[id]; legacy {
			continue
		}
		if _, proposed := narrowProposed[id]; proposed {
			t.Fatalf("narrow RuntimeIDs dry-run proposed non-legacy-runtime row %q; converged/new-runtime rows must fall outside a legacy-runtime-only scope", id)
		}
	}
	for _, id := range retiredIDs {
		if tombstonedFromDB(t, ctx, rawDB, id) {
			t.Fatalf("narrow RuntimeIDs dry run tombstoned %q", id)
		}
	}

	// Main flow: tenant + the two retired rule ids only, no RuntimeIDs, no
	// OlderThan.
	selector := findings.CloseoutSelector{
		TenantID: tenantID,
		RuleIDs:  retiredRuleIDs,
		Statuses: []string{"open"},
	}

	dryRun, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: selector,
		Reason:   "C5 VulnView rule retirement: close every open row under the two retired rule ids",
		Actor:    "operator@writer.com",
		RunID:    fmt.Sprintf("run-retired-dryrun-%d", nonce),
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("dry-run TombstoneFindingsBulk: %v", err)
	}
	gotProposed := map[string]struct{}{}
	for _, finding := range dryRun.Proposed {
		gotProposed[finding.ID] = struct{}{}
	}
	if dryRun.ProposedCount != len(retiredIDs) || len(gotProposed) != len(retiredIDs) {
		t.Fatalf("dry-run proposed = %#v, want exactly %v", dryRun.Proposed, retiredIDs)
	}
	for _, id := range retiredIDs {
		if _, ok := gotProposed[id]; !ok {
			t.Fatalf("dry-run proposed missing %q: got %#v", id, gotProposed)
		}
		if tombstonedFromDB(t, ctx, rawDB, id) {
			t.Fatalf("dry run tombstoned %q", id)
		}
	}
	if tombstonedFromDB(t, ctx, rawDB, unrelatedID) || tombstonedFromDB(t, ctx, rawDB, otherTenantRowID) {
		t.Fatal("dry run tombstoned an out-of-scope row")
	}

	applied, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: selector,
		Reason:   "C5 VulnView rule retirement: close every open row under the two retired rule ids",
		Actor:    "operator@writer.com",
		RunID:    fmt.Sprintf("run-retired-apply-%d", nonce),
		DryRun:   false,
	})
	if err != nil {
		t.Fatalf("apply TombstoneFindingsBulk: %v", err)
	}
	if applied.AppliedCount != len(retiredIDs) {
		t.Fatalf("AppliedCount = %d, want %d", applied.AppliedCount, len(retiredIDs))
	}
	for _, id := range retiredIDs {
		if !tombstonedFromDB(t, ctx, rawDB, id) {
			t.Fatalf("retired-rule row %q was not tombstoned", id)
		}
	}
	if tombstonedFromDB(t, ctx, rawDB, unrelatedID) {
		t.Fatal("unrelated rule/runtime row was tombstoned; selector scope must exclude it")
	}
	if tombstonedFromDB(t, ctx, rawDB, otherTenantRowID) {
		t.Fatal("other tenant's row was tombstoned; selector scope must exclude it")
	}
	for _, id := range []string{unrelatedID, otherTenantRowID} {
		if openStatusFromDB(t, ctx, rawDB, id) != "open" {
			t.Fatalf("row %q status changed; it must stay open", id)
		}
	}

	// Idempotent rerun: every retired-rule row is now tombstoned and
	// therefore excluded from candidate selection, so a repeat apply finds
	// nothing.
	rerun, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: selector,
		Reason:   "C5 VulnView rule retirement: close every open row under the two retired rule ids",
		Actor:    "operator@writer.com",
		RunID:    fmt.Sprintf("run-retired-rerun-%d", nonce),
		DryRun:   false,
	})
	if err != nil {
		t.Fatalf("idempotent rerun TombstoneFindingsBulk: %v", err)
	}
	if rerun.ProposedCount != 0 || rerun.AppliedCount != 0 {
		t.Fatalf("idempotent rerun = %#v, want all-zero", rerun)
	}
}

func openStatusFromDB(t *testing.T, ctx context.Context, db *sql.DB, id string) string {
	t.Helper()
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("query status for %q: %v", id, err)
	}
	return status
}
