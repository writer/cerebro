package findings_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
	"github.com/writer/cerebro/internal/workflowevents"
	"github.com/writer/cerebro/internal/workflowprojection"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestBreakStaleRunningCloseoutRuns_HoneorsHeartbeat preserves the validation
// contract spelling while asserting VAL-M6-CLOSEOUT-HEARTBEAT-002: stale-lock
// reclamation is gated by heartbeat freshness, not by the original started_at.
func TestBreakStaleRunningCloseoutRuns_HoneorsHeartbeat(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the closeout heartbeat integration test")
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

	if _, err := store.BreakStaleRunningCloseoutRuns(ctx, time.Time{}, ""); err != nil {
		t.Fatalf("ensure closeout schema: %v", err)
	}

	nonce := time.Now().UTC().UnixNano()
	freshRunID := fmt.Sprintf("test-heartbeat-fresh-%d", nonce)
	staleRunID := fmt.Sprintf("test-heartbeat-stale-%d", nonce)
	cleanup := func() {
		_, _ = rawDB.ExecContext(context.Background(), `DELETE FROM closeout_run WHERE run_id IN ($1, $2)`, freshRunID, staleRunID)
	}
	cleanup()
	t.Cleanup(cleanup)

	now := time.Now().UTC().Truncate(time.Microsecond)
	cutoff := now.Add(-time.Hour)
	insertRun := func(runID string, startedAt, heartbeatAt time.Time) {
		t.Helper()
		_, err := rawDB.ExecContext(ctx, `
INSERT INTO closeout_run (run_id, actor, change_ticket, selector_json, status, started_at, heartbeat_at, dry_run)
VALUES ($1, 'heartbeat-test', '', '{}'::jsonb, 'running', $2, $3, false)`,
			runID,
			startedAt,
			heartbeatAt,
		)
		if err != nil {
			t.Fatalf("insert closeout_run %q: %v", runID, err)
		}
	}
	statusOf := func(runID string) (string, sql.NullTime) {
		t.Helper()
		var status string
		var finishedAt sql.NullTime
		if err := rawDB.QueryRowContext(ctx, `SELECT status, finished_at FROM closeout_run WHERE run_id = $1`, runID).Scan(&status, &finishedAt); err != nil {
			t.Fatalf("read closeout_run %q: %v", runID, err)
		}
		return status, finishedAt
	}

	insertRun(freshRunID, now.Add(-2*time.Hour), now.Add(-5*time.Minute))
	broken, err := store.BreakStaleRunningCloseoutRuns(ctx, cutoff, "stale heartbeat test")
	if err != nil {
		t.Fatalf("BreakStaleRunningCloseoutRuns fresh heartbeat error: %v", err)
	}
	if broken != 0 {
		t.Fatalf("fresh heartbeat broken rows = %d, want 0", broken)
	}
	status, finishedAt := statusOf(freshRunID)
	if status != "running" {
		t.Fatalf("fresh heartbeat status = %q, want running", status)
	}
	if finishedAt.Valid {
		t.Fatalf("fresh heartbeat finished_at = %s, want NULL", finishedAt.Time)
	}

	if _, err := rawDB.ExecContext(ctx, `DELETE FROM closeout_run WHERE run_id = $1`, freshRunID); err != nil {
		t.Fatalf("delete fresh running row: %v", err)
	}

	insertRun(staleRunID, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
	broken, err = store.BreakStaleRunningCloseoutRuns(ctx, cutoff, "stale heartbeat test")
	if err != nil {
		t.Fatalf("BreakStaleRunningCloseoutRuns stale heartbeat error: %v", err)
	}
	if broken != 1 {
		t.Fatalf("stale heartbeat broken rows = %d, want 1", broken)
	}
	status, finishedAt = statusOf(staleRunID)
	if status != "failed" {
		t.Fatalf("stale heartbeat status = %q, want failed", status)
	}
	if !finishedAt.Valid {
		t.Fatalf("stale heartbeat finished_at is NULL, want timestamp")
	}
}

// TestService_TombstonedFindingEmitMintsFreshGraphEdge exercises the
// tombstone-then-emit lifecycle end-to-end against the real Postgres upsert
// path so the fresh-row mint (id = `<base>#g<N+1>` and tombstone_generation)
// is derived by the production internal/statestore/postgres UpsertFinding via
// the tombstoned fingerprint history instead of being pre-constructed by the
// test. F1 is upserted, tombstoned via Service.TombstoneFindingsBulk (which
// removes has_finding(A → F1) via the projector), and a subsequent emit on the
// same (rule_id, anchor_uri, fingerprint) re-runs through real UpsertFinding,
// which is what is expected to mint F2 with tombstoned=FALSE and the
// incremented generation. The fresh F2 is then anchored back into the graph
// so the test confirms has_finding(A → F2) is reattached.
func TestService_TombstonedFindingEmitMintsFreshGraphEdge(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the end-to-end tombstone-then-emit integration test")
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
	tenantID := fmt.Sprintf("tenant-e2e-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-e2e-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	baseID := fmt.Sprintf("f-stable-%d", nonce)
	fingerprint := fmt.Sprintf("fp-stable-%d", nonce)
	anchor := fmt.Sprintf("urn:cerebro:%s:github_code_repository:writer/cerebro-%d", tenantID, nonce)

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_tombstone_events WHERE tenant_id = $1`, tenantID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})

	graph := newE2EGraphFake()
	appendLog := &recordingAppendLog{}
	closeoutStore := newStubCloseoutStore()
	tombstoneEventStore := newStubFindingTombstoneEventStore()
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "source-e2e", TenantId: tenantID},
		},
	}

	service := findings.New(runtimeStore, &stubReplayer{}, store, store, store, store).
		WithAppendLog(appendLog).
		WithGraphStore(graph).
		WithCloseoutStore(closeoutStore).
		WithFindingTombstoneEventStore(tombstoneEventStore)

	now := time.Now().UTC().Truncate(time.Microsecond)
	firstObserved := now.Add(-48 * time.Hour)
	firstEmit := &ports.FindingRecord{
		ID:              baseID,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "T " + baseID,
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "S " + baseID,
		ResourceURNs:    []string{anchor},
		EventIDs:        []string{"event-initial-emit"},
		FirstObservedAt: firstObserved,
		LastObservedAt:  firstObserved,
	}
	storedF1, err := store.UpsertFinding(ctx, firstEmit)
	if err != nil {
		t.Fatalf("UpsertFinding F1: %v", err)
	}
	if storedF1.ID != baseID {
		t.Fatalf("F1.ID = %q, want %q", storedF1.ID, baseID)
	}

	if err := projectFindingAnchorForTest(ctx, appendLog, graph, storedF1); err != nil {
		t.Fatalf("project F1 anchor: %v", err)
	}

	firstAnchorEdgeKey := anchorEdgeKey(anchor, tenantID, storedF1.ID)
	if _, ok := graph.links[firstAnchorEdgeKey]; !ok {
		t.Fatalf("pre-condition: missing has_finding(A → F1) edge %q (links=%v)", firstAnchorEdgeKey, graph.links)
	}

	result, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID: tenantID,
			RuleIDs:  []string{ruleID},
		},
		Reason: "bulk closeout: pre-conversion backlog",
		Actor:  "operator@writer.com",
		RunID:  fmt.Sprintf("run-e2e-%d", nonce),
		DryRun: false,
	})
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk: %v", err)
	}
	if result.AppliedCount != 1 {
		t.Fatalf("AppliedCount = %d, want 1", result.AppliedCount)
	}

	if !tombstonedFromDB(t, ctx, rawDB, baseID) {
		t.Fatalf("findings.tombstoned = false for F1 %q, want true after bulk tombstone", baseID)
	}
	if _, ok := graph.links[firstAnchorEdgeKey]; ok {
		t.Fatalf("expected has_finding(A → F1) edge %q to be removed after tombstone", firstAnchorEdgeKey)
	}

	tombstoneEvents := 0
	for _, evt := range appendLog.events {
		if evt.GetKind() == workflowevents.EventKindFindingTombstoned {
			tombstoneEvents++
		}
	}
	if tombstoneEvents != 1 {
		t.Fatalf("FindingTombstoned events emitted for F1 = %d, want 1", tombstoneEvents)
	}

	firstGen := generationFromDB(t, ctx, rawDB, baseID)

	freshEmit := &ports.FindingRecord{
		ID:              baseID,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "T " + baseID,
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "S " + baseID,
		ResourceURNs:    []string{anchor},
		EventIDs:        []string{"event-fresh-emit"},
		FirstObservedAt: now.Add(-time.Minute),
		LastObservedAt:  now,
	}
	storedF2, err := store.UpsertFinding(ctx, freshEmit)
	if err != nil {
		t.Fatalf("UpsertFinding F2: %v", err)
	}

	wantSecondID := fmt.Sprintf("%s#g%d", baseID, firstGen+1)
	if storedF2.ID != wantSecondID {
		t.Fatalf("F2.ID = %q, want %q (derived by UpsertFinding from tombstoned fingerprint history)", storedF2.ID, wantSecondID)
	}
	if storedF2.ID == storedF1.ID {
		t.Fatalf("F2.ID %q must differ from tombstoned F1.ID %q", storedF2.ID, storedF1.ID)
	}

	secondGen := generationFromDB(t, ctx, rawDB, storedF2.ID)
	if secondGen != firstGen+1 {
		t.Fatalf("F2.tombstone_generation = %d, want F1.tombstone_generation+1 = %d", secondGen, firstGen+1)
	}

	secondTombstoned := tombstonedFromDB(t, ctx, rawDB, storedF2.ID)
	if secondTombstoned {
		t.Fatalf("F2.tombstoned = true, want false")
	}

	if err := projectFindingAnchorForTest(ctx, appendLog, graph, storedF2); err != nil {
		t.Fatalf("project F2 anchor: %v", err)
	}

	recordedForF2 := 0
	for _, evt := range appendLog.events {
		if evt.GetKind() != workflowevents.EventKindFindingRecorded {
			continue
		}
		payload, decodeErr := workflowevents.DecodeFindingRecorded(evt)
		if decodeErr != nil {
			t.Fatalf("decode FindingRecorded: %v", decodeErr)
		}
		if payload.Finding.FindingID == storedF2.ID {
			recordedForF2++
		}
	}
	if recordedForF2 != 1 {
		t.Fatalf("FindingRecorded events for F2 = %d, want 1", recordedForF2)
	}

	freshAnchorEdgeKey := anchorEdgeKey(anchor, tenantID, storedF2.ID)
	if freshAnchorEdgeKey == firstAnchorEdgeKey {
		t.Fatalf("F2 edge key %q must differ from F1 edge key", freshAnchorEdgeKey)
	}
	if _, ok := graph.links[freshAnchorEdgeKey]; !ok {
		t.Fatalf("expected has_finding(A → F2) edge %q after fresh emit (links=%v)", freshAnchorEdgeKey, graph.links)
	}
}

func TestService_TTLEvidenceEvaluateUsesPostgresTenantScopeAndReopens(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run the postgres-backed TTL evaluate integration test")
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
	tenantID := fmt.Sprintf("tenant-ttl-e2e-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-ttl-e2e-%d", nonce)
	evidenceID := fmt.Sprintf("evidence-ttl-e2e-%d", nonce)
	ruleID := "runtime-active-threat-evidence"
	openedAt := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	staleAt := openedAt.Add(25 * time.Hour)
	reemitAt := staleAt.Add(time.Hour)

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evidence WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM finding_evaluation_runs WHERE runtime_id = $1`, runtimeID)
		_, _ = rawDB.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})

	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "runtime", TenantId: tenantID},
		},
	}
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{
		runtimeThreatE2EEvent("runtime-threat-open", tenantID, evidenceID, openedAt),
	}}
	service := findings.NewWithRegistry(runtimeStore, replayer, store, store, store, store, findings.Builtin()).
		WithTTLClock(e2eTTLClock{now: openedAt})

	openResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(open): %v", err)
	}
	if openResult == nil || len(openResult.Evaluations) != 1 {
		t.Fatalf("open result evaluations = %#v, want one", openResult)
	}
	if got := len(openResult.Evaluations[0].Findings); got != 1 {
		t.Fatalf("open result findings = %d, want 1", got)
	}
	opened := openResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(opened.Status); got != "open" {
		t.Fatalf("opened status = %q, want open", got)
	}
	if got := strings.TrimSpace(opened.TenantID); got != tenantID {
		t.Fatalf("opened tenant_id = %q, want %q", got, tenantID)
	}

	replayer.events = nil
	service.WithTTLClock(e2eTTLClock{now: staleAt})
	if _, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(ttl resolve): %v", err)
	}
	resolved, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after TTL resolve: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(resolved.Status); got != "resolved" {
		t.Fatalf("TTL-resolved status = %q, want resolved", got)
	}
	if got := strings.TrimSpace(resolved.StatusReason); got != "ttl_expired:24h" {
		t.Fatalf("TTL-resolved status_reason = %q, want ttl_expired:24h", got)
	}
	if resolved.Tombstoned {
		t.Fatalf("TTL-resolved finding tombstoned = true, want false")
	}

	replayer.events = []*cerebrov1.EventEnvelope{
		runtimeThreatE2EEvent("runtime-threat-reemit", tenantID, evidenceID, reemitAt),
	}
	service.WithTTLClock(e2eTTLClock{now: reemitAt})
	reopenResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(reemit): %v", err)
	}
	if reopenResult == nil || len(reopenResult.Evaluations) != 1 || len(reopenResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("reemit result = %#v, want one reopened finding", reopenResult)
	}
	reopenedFromResult := reopenResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(reopenedFromResult.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("reemit finding id = %q, want original id %q from real upsert reopen path", got, opened.ID)
	}
	reopened, err := store.GetFinding(ctx, opened.ID)
	if err != nil {
		t.Fatalf("GetFinding(%q) after reemit: %v", opened.ID, err)
	}
	if got := strings.TrimSpace(reopened.Status); got != "open" {
		t.Fatalf("reopened status = %q, want open", got)
	}
	if got := strings.TrimSpace(reopened.StatusReason); got != "" {
		t.Fatalf("reopened status_reason = %q, want empty", got)
	}
	if reopened.Tombstoned {
		t.Fatalf("reopened finding tombstoned = true, want false")
	}
	if strings.Contains(reopened.ID, "#g") {
		t.Fatalf("reopened finding id = %q, want original non-generation row for non-tombstoned TTL reopen", reopened.ID)
	}

	var activeRows int
	if err := rawDB.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = $2 AND fingerprint = $3 AND tombstoned = FALSE`, tenantID, ruleID, opened.Fingerprint).Scan(&activeRows); err != nil {
		t.Fatalf("count active TTL rows: %v", err)
	}
	if activeRows != 1 {
		t.Fatalf("active rows for reopened TTL fingerprint = %d, want 1", activeRows)
	}
}

func TestTombstoneOneFinding_AtomicRollback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(t *testing.T, ctx context.Context, db *sql.DB, runID string, appendLog *recordingAppendLog) any
	}{
		{
			name: "audit_insert_failure",
			configure: func(t *testing.T, ctx context.Context, db *sql.DB, runID string, _ *recordingAppendLog) any {
				t.Helper()
				installCloseoutAuditFailureConstraint(t, ctx, db, runID)
				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store, rawDB, dsnCleanup := closeoutAtomicPostgresStore(t)
			defer dsnCleanup()

			nonce := time.Now().UTC().UnixNano()
			tenantID := fmt.Sprintf("tenant-atomic-%s-%d", strings.ReplaceAll(tc.name, "_", "-"), nonce)
			runtimeID := fmt.Sprintf("runtime-atomic-%d", nonce)
			ruleID := "rule-critical-resource-deleted"
			findingID := fmt.Sprintf("finding-atomic-%d", nonce)
			runID := fmt.Sprintf("run-atomic-%d", nonce)
			cleanupCloseoutAtomicRows(t, rawDB, tenantID, runID)
			seedCloseoutAtomicFinding(t, ctx, store, tenantID, runtimeID, ruleID, findingID, nonce)

			appendLog := &recordingAppendLog{}
			appendLogOverride := tc.configure(t, ctx, rawDB, runID, appendLog)
			if override, ok := appendLogOverride.(interface {
				Append(context.Context, *cerebrov1.EventEnvelope) error
				Ping(context.Context) error
			}); ok {
				service := closeoutAtomicService(store, override, tenantID, runtimeID)
				before := readCloseoutAtomicSnapshot(t, ctx, rawDB, findingID)
				result, err := service.TombstoneFindingsBulk(ctx, closeoutAtomicRequest(tenantID, ruleID, runID))
				assertAtomicRollback(t, ctx, rawDB, findingID, runID, before, result, err)
				return
			}

			service := closeoutAtomicService(store, appendLog, tenantID, runtimeID)
			before := readCloseoutAtomicSnapshot(t, ctx, rawDB, findingID)
			result, err := service.TombstoneFindingsBulk(ctx, closeoutAtomicRequest(tenantID, ruleID, runID))
			assertAtomicRollback(t, ctx, rawDB, findingID, runID, before, result, err)
		})
	}
}

func TestTombstoneOneFinding_RechecksStatusBeforeWrite(t *testing.T) {
	ctx := context.Background()
	store, rawDB, dsnCleanup := closeoutAtomicPostgresStore(t)
	defer dsnCleanup()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-status-recheck-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-status-recheck-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	findingID := fmt.Sprintf("finding-status-recheck-%d", nonce)
	runID := fmt.Sprintf("run-status-recheck-%d", nonce)
	cleanupCloseoutAtomicRows(t, rawDB, tenantID, runID)
	seedCloseoutAtomicFinding(t, ctx, store, tenantID, runtimeID, ruleID, findingID, nonce)

	wrappedStore := &statusChangingListStore{
		Store:     store,
		findingID: findingID,
		status:    "suppressed",
		reason:    "analyst suppression during closeout",
	}
	service := closeoutAtomicService(wrappedStore, &recordingAppendLog{}, tenantID, runtimeID)

	result, err := service.TombstoneFindingsBulk(ctx, closeoutAtomicRequest(tenantID, ruleID, runID))
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk with concurrent status change: %v", err)
	}
	if wrappedStore.mutationErr != nil {
		t.Fatalf("concurrent status mutation failed: %v", wrappedStore.mutationErr)
	}
	if result.ProposedCount != 1 {
		t.Fatalf("ProposedCount = %d, want 1", result.ProposedCount)
	}
	if result.AppliedCount != 0 {
		t.Fatalf("AppliedCount = %d, want 0 after status changed before tombstone", result.AppliedCount)
	}
	after := readCloseoutAtomicSnapshot(t, ctx, rawDB, findingID)
	if after.Status != "suppressed" {
		t.Fatalf("status after concurrent mutation = %q, want suppressed", after.Status)
	}
	if after.Tombstoned {
		t.Fatalf("tombstoned after status changed = true, want false")
	}
	if after.PriorStatus != "" {
		t.Fatalf("prior_status after skipped tombstone = %q, want empty", after.PriorStatus)
	}
	if count := countCloseoutAtomicAuditRows(t, ctx, rawDB, runID); count != 0 {
		t.Fatalf("audit rows for skipped tombstone = %d, want 0", count)
	}
}

func TestTombstoneOneFinding_RetryAfterAtomicRollback(t *testing.T) {
	ctx := context.Background()
	store, rawDB, dsnCleanup := closeoutAtomicPostgresStore(t)
	defer dsnCleanup()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-retry-rollback-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-retry-rollback-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	findingID := fmt.Sprintf("finding-retry-rollback-%d", nonce)
	failingRunID := fmt.Sprintf("run-retry-fail-%d", nonce)
	retryRunID := fmt.Sprintf("run-retry-dry-%d", nonce)
	cleanupCloseoutAtomicRows(t, rawDB, tenantID, failingRunID, retryRunID)
	seedCloseoutAtomicFinding(t, ctx, store, tenantID, runtimeID, ruleID, findingID, nonce)

	installCloseoutAuditFailureConstraint(t, ctx, rawDB, failingRunID)
	failingService := closeoutAtomicService(store, &recordingAppendLog{}, tenantID, runtimeID)
	if result, err := failingService.TombstoneFindingsBulk(ctx, closeoutAtomicRequest(tenantID, ruleID, failingRunID)); err == nil {
		t.Fatalf("expected injected audit insert error, got nil result=%+v", result)
	}
	afterFailure := readCloseoutAtomicSnapshot(t, ctx, rawDB, findingID)
	if afterFailure.Tombstoned {
		t.Fatalf("finding tombstoned after injected failure; rollback did not restore candidate")
	}

	retryReq := closeoutAtomicRequest(tenantID, ruleID, retryRunID)
	retryReq.DryRun = true
	retryService := closeoutAtomicService(store, &recordingAppendLog{}, tenantID, runtimeID)
	retry, err := retryService.TombstoneFindingsBulk(ctx, retryReq)
	if err != nil {
		t.Fatalf("retry dry-run after rollback: %v", err)
	}
	if retry.ProposedCount < 1 {
		t.Fatalf("retry ProposedCount = %d, want candidate returned after rollback", retry.ProposedCount)
	}
}

func TestTombstoneOneFinding_WorkflowEmitFailureAfterCommit(t *testing.T) {
	ctx := context.Background()
	store, rawDB, dsnCleanup := closeoutAtomicPostgresStore(t)
	defer dsnCleanup()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-emit-after-commit-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-emit-after-commit-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	findingID := fmt.Sprintf("finding-emit-after-commit-%d", nonce)
	runID := fmt.Sprintf("run-emit-after-commit-%d", nonce)
	cleanupCloseoutAtomicRows(t, rawDB, tenantID, runID)
	seedCloseoutAtomicFinding(t, ctx, store, tenantID, runtimeID, ruleID, findingID, nonce)

	service := closeoutAtomicService(store, &failingAppendLog{err: errors.New("inject workflow emit failure")}, tenantID, runtimeID)
	result, err := service.TombstoneFindingsBulk(ctx, closeoutAtomicRequest(tenantID, ruleID, runID))
	if err == nil {
		t.Fatalf("expected workflow emit failure after commit, got nil result=%+v", result)
	}
	if result == nil {
		t.Fatalf("result is nil, want committed candidate count")
	}
	if result.AppliedCount != 1 {
		t.Fatalf("AppliedCount after post-commit emit failure = %d, want 1 committed tombstone", result.AppliedCount)
	}
	after := readCloseoutAtomicSnapshot(t, ctx, rawDB, findingID)
	if !after.Tombstoned {
		t.Fatalf("finding tombstoned after post-commit workflow failure = false, want true")
	}
	if after.Status != "resolved" {
		t.Fatalf("status after post-commit workflow failure = %q, want resolved", after.Status)
	}
	if after.TombstonedRunID != runID {
		t.Fatalf("tombstoned_run_id after post-commit workflow failure = %q, want %q", after.TombstonedRunID, runID)
	}
	if count := countCloseoutAtomicAuditRows(t, ctx, rawDB, runID); count != 1 {
		t.Fatalf("audit rows after post-commit workflow failure = %d, want 1", count)
	}

	var runStatus string
	var appliedCount int
	if err := rawDB.QueryRowContext(ctx, `SELECT status, applied_count FROM closeout_run WHERE run_id = $1`, runID).Scan(&runStatus, &appliedCount); err != nil {
		t.Fatalf("read closeout_run after post-commit workflow failure: %v", err)
	}
	if runStatus != "failed" {
		t.Fatalf("closeout_run.status after post-commit workflow failure = %q, want failed", runStatus)
	}
	if appliedCount != 1 {
		t.Fatalf("closeout_run.applied_count after post-commit workflow failure = %d, want 1", appliedCount)
	}
}

func TestCloseout_DuplicateRunWithFailedStatusReturnsError(t *testing.T) {
	ctx := context.Background()
	store, rawDB, dsnCleanup := closeoutAtomicPostgresStore(t)
	defer dsnCleanup()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-duplicate-failed-%d", nonce)
	runtimeID := fmt.Sprintf("runtime-duplicate-failed-%d", nonce)
	ruleID := "rule-critical-resource-deleted"
	runID := fmt.Sprintf("run-duplicate-failed-%d", nonce)
	priorFailure := fmt.Sprintf("prior closeout failure persisted for duplicate run %d", nonce)
	cleanupCloseoutAtomicRows(t, rawDB, tenantID, runID)

	startedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.InsertCloseoutRun(ctx, ports.CloseoutRunInsert{
		RunID:        runID,
		Actor:        "operator@writer.com",
		SelectorJSON: []byte(fmt.Sprintf(`{"tenant_id":%q,"rule_ids":[%q],"statuses":["open"]}`, tenantID, ruleID)),
		DryRun:       false,
		StartedAt:    startedAt,
		HeartbeatAt:  startedAt,
	}); err != nil {
		t.Fatalf("seed closeout_run: %v", err)
	}
	if err := store.FinishCloseoutRun(ctx, ports.CloseoutRunFinish{
		RunID:         runID,
		Status:        "failed",
		ErrorMessage:  priorFailure,
		ProposedCount: 1,
		AppliedCount:  0,
		FinishedAt:    startedAt.Add(time.Minute),
	}); err != nil {
		t.Fatalf("mark closeout_run failed: %v", err)
	}

	service := closeoutAtomicService(store, &recordingAppendLog{}, tenantID, runtimeID)
	result, err := service.TombstoneFindingsBulk(ctx, closeoutAtomicRequest(tenantID, ruleID, runID))
	if err == nil {
		t.Fatalf("duplicate failed closeout_run returned nil error; result=%+v", result)
	}
	if !errors.Is(err, findings.ErrCloseoutRunFailed) {
		t.Fatalf("duplicate failed closeout error = %v, want ErrCloseoutRunFailed", err)
	}
	var failedErr *findings.CloseoutRunFailedError
	if !errors.As(err, &failedErr) {
		t.Fatalf("duplicate failed closeout error = %T, want CloseoutRunFailedError", err)
	}
	if failedErr.ErrorMessage != priorFailure {
		t.Fatalf("CloseoutRunFailedError.ErrorMessage = %q, want %q", failedErr.ErrorMessage, priorFailure)
	}
	if result == nil {
		t.Fatal("duplicate failed closeout_run returned nil result")
	}
	if len(result.BatchErrors) != 1 {
		t.Fatalf("BatchErrors len = %d, want 1", len(result.BatchErrors))
	}
	var batchErr *findings.CloseoutRunFailedError
	if !errors.As(result.BatchErrors[0], &batchErr) {
		t.Fatalf("BatchErrors[0] = %T, want CloseoutRunFailedError", result.BatchErrors[0])
	}
	if batchErr.ErrorMessage != priorFailure {
		t.Fatalf("BatchErrors[0].ErrorMessage = %q, want %q", batchErr.ErrorMessage, priorFailure)
	}

	var status, errorMessage string
	if err := rawDB.QueryRowContext(ctx, `SELECT status, error_message FROM closeout_run WHERE run_id = $1`, runID).Scan(&status, &errorMessage); err != nil {
		t.Fatalf("read closeout_run after duplicate retry: %v", err)
	}
	if status != "failed" {
		t.Fatalf("closeout_run.status = %q, want failed", status)
	}
	if errorMessage != priorFailure {
		t.Fatalf("closeout_run.error_message = %q, want %q", errorMessage, priorFailure)
	}
}

func anchorEdgeKey(anchor, tenantID, findingID string) string {
	return anchor + "|has_finding|" + fmt.Sprintf("urn:cerebro:%s:finding:%s", tenantID, findingID)
}

func generationFromDB(t *testing.T, ctx context.Context, db *sql.DB, findingID string) int {
	t.Helper()
	var gen int
	if err := db.QueryRowContext(ctx, `SELECT tombstone_generation FROM findings WHERE id = $1`, findingID).Scan(&gen); err != nil {
		t.Fatalf("read tombstone_generation for %q: %v", findingID, err)
	}
	return gen
}

func tombstonedFromDB(t *testing.T, ctx context.Context, db *sql.DB, findingID string) bool {
	t.Helper()
	var tombstoned bool
	if err := db.QueryRowContext(ctx, `SELECT tombstoned FROM findings WHERE id = $1`, findingID).Scan(&tombstoned); err != nil {
		t.Fatalf("read tombstoned for %q: %v", findingID, err)
	}
	return tombstoned
}

type closeoutAtomicSnapshot struct {
	Status           string
	StatusReason     string
	Tombstoned       bool
	TombstonedAt     sql.NullTime
	TombstonedBy     string
	TombstonedReason string
	TombstonedRunID  string
	PriorStatus      string
}

func closeoutAtomicPostgresStore(t *testing.T) (*postgres.Store, *sql.DB, func()) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run closeout atomicity integration tests")
	}
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		_ = store.Close()
		t.Fatalf("open raw db: %v", err)
	}
	return store, rawDB, func() {
		_ = rawDB.Close()
		_ = store.Close()
	}
}

func cleanupCloseoutAtomicRows(t *testing.T, db *sql.DB, tenantID string, runIDs ...string) {
	t.Helper()
	t.Cleanup(func() {
		bg := context.Background()
		for _, runID := range runIDs {
			_, _ = db.ExecContext(bg, `DELETE FROM finding_tombstone_events WHERE run_id = $1`, runID)
			_, _ = db.ExecContext(bg, `DELETE FROM closeout_run WHERE run_id = $1`, runID)
		}
		_, _ = db.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenantID)
	})
}

//nolint:unparam // Helper keeps rule ID explicit to mirror closeout selector setup.
func seedCloseoutAtomicFinding(t *testing.T, ctx context.Context, store *postgres.Store, tenantID, runtimeID, ruleID, findingID string, nonce int64) {
	t.Helper()
	now := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	_, err := store.UpsertFinding(ctx, &ports.FindingRecord{
		ID:              findingID,
		Fingerprint:     fmt.Sprintf("fp-%s-%d", findingID, nonce),
		TenantID:        tenantID,
		RuntimeID:       runtimeID,
		RuleID:          ruleID,
		Title:           "Atomic closeout regression",
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "finding used for closeout atomicity regression",
		ResourceURNs:    []string{fmt.Sprintf("urn:cerebro:%s:github_code_repository:writer/cerebro-%d", tenantID, nonce)},
		EventIDs:        []string{fmt.Sprintf("event-%d", nonce)},
		FirstObservedAt: now.Add(-24 * time.Hour),
		LastObservedAt:  now,
	})
	if err != nil {
		t.Fatalf("seed finding %q: %v", findingID, err)
	}
}

//nolint:unparam // Helper keeps rule ID explicit to mirror the atomic closeout fixture.
func closeoutAtomicRequest(tenantID, ruleID, runID string) findings.CloseoutRequest {
	return findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID:  tenantID,
			RuleIDs:   []string{ruleID},
			OlderThan: time.Hour,
		},
		Reason: "bulk closeout: atomicity regression",
		Actor:  "operator@writer.com",
		RunID:  runID,
		DryRun: false,
	}
}

type closeoutAtomicStore interface {
	ports.FindingStore
	ports.FindingEvaluationRunStore
	ports.FindingEvidenceStore
	ports.ClaimStore
	ports.CloseoutRunStore
	ports.FindingTombstoneEventStore
}

func closeoutAtomicService(store closeoutAtomicStore, appendLog ports.AppendLog, tenantID, runtimeID string) *findings.Service {
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: "source-atomic", TenantId: tenantID},
		},
	}
	return findings.New(runtimeStore, &stubReplayer{}, store, store, store, store).
		WithAppendLog(appendLog).
		WithCloseoutStore(store).
		WithFindingTombstoneEventStore(store)
}

func readCloseoutAtomicSnapshot(t *testing.T, ctx context.Context, db *sql.DB, findingID string) closeoutAtomicSnapshot {
	t.Helper()
	var snapshot closeoutAtomicSnapshot
	if err := db.QueryRowContext(ctx, `
SELECT status, status_reason, tombstoned, tombstoned_at, tombstoned_by,
       tombstoned_reason, tombstoned_run_id, prior_status
FROM findings
WHERE id = $1`, findingID).Scan(
		&snapshot.Status,
		&snapshot.StatusReason,
		&snapshot.Tombstoned,
		&snapshot.TombstonedAt,
		&snapshot.TombstonedBy,
		&snapshot.TombstonedReason,
		&snapshot.TombstonedRunID,
		&snapshot.PriorStatus,
	); err != nil {
		t.Fatalf("read closeout atomic snapshot for %q: %v", findingID, err)
	}
	return snapshot
}

func countCloseoutAtomicAuditRows(t *testing.T, ctx context.Context, db *sql.DB, runID string) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_tombstone_events WHERE run_id = $1`, runID).Scan(&count); err != nil {
		t.Fatalf("count tombstone audit rows for %q: %v", runID, err)
	}
	return count
}

func installCloseoutAuditFailureConstraint(t *testing.T, ctx context.Context, db *sql.DB, runID string) {
	t.Helper()
	constraintName := fmt.Sprintf("finding_tombstone_events_fail_%d", time.Now().UTC().UnixNano())
	if _, err := db.ExecContext(ctx, fmt.Sprintf(
		`ALTER TABLE finding_tombstone_events ADD CONSTRAINT %s CHECK (run_id <> '%s') NOT VALID`,
		constraintName,
		strings.ReplaceAll(runID, "'", "''"),
	)); err != nil {
		t.Fatalf("install audit failure constraint: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, fmt.Sprintf(
			`ALTER TABLE finding_tombstone_events DROP CONSTRAINT IF EXISTS %s`,
			constraintName,
		))
	})
}

func assertAtomicRollback(t *testing.T, ctx context.Context, db *sql.DB, findingID, runID string, before closeoutAtomicSnapshot, result *findings.CloseoutResult, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected injected closeout error, got nil")
	}
	if result != nil && result.AppliedCount != 0 {
		t.Fatalf("AppliedCount after rollback = %d, want 0", result.AppliedCount)
	}
	after := readCloseoutAtomicSnapshot(t, ctx, db, findingID)
	if after != before {
		t.Fatalf("finding snapshot changed after injected failure:\nbefore=%+v\nafter=%+v", before, after)
	}
	if count := countCloseoutAtomicAuditRows(t, ctx, db, runID); count != 0 {
		t.Fatalf("audit rows after rollback = %d, want 0", count)
	}
}

type failingAppendLog struct {
	err error
}

func (s *failingAppendLog) Ping(context.Context) error { return nil }

func (s *failingAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	return errors.New("append failed")
}

type statusChangingListStore struct {
	*postgres.Store
	findingID   string
	status      string
	reason      string
	once        sync.Once
	mutationErr error
}

func (s *statusChangingListStore) ListFindings(ctx context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	records, err := s.Store.ListFindings(ctx, request)
	if err != nil {
		return nil, err
	}
	s.once.Do(func() {
		_, s.mutationErr = s.UpdateFindingStatus(ctx, ports.FindingStatusUpdate{
			FindingID: s.findingID,
			Status:    s.status,
			Reason:    s.reason,
			UpdatedAt: time.Now().UTC(),
		})
	})
	return records, nil
}

func projectFindingAnchorForTest(ctx context.Context, appendLog *recordingAppendLog, graph *e2eGraphFake, finding *ports.FindingRecord) error {
	if finding == nil {
		return errors.New("finding is required")
	}
	recordedAt := finding.LastObservedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = finding.FirstObservedAt.UTC()
	}
	if recordedAt.IsZero() {
		recordedAt = time.Now().UTC()
	}
	resourceURNs := append([]string(nil), finding.ResourceURNs...)
	primary := ""
	if len(resourceURNs) > 0 {
		primary = resourceURNs[0]
	}
	snapshot := workflowevents.FindingSnapshot{
		TenantID:           strings.TrimSpace(finding.TenantID),
		SourceSystem:       strings.TrimSpace(finding.RuntimeID),
		FindingID:          strings.TrimSpace(finding.ID),
		Fingerprint:        strings.TrimSpace(finding.Fingerprint),
		Title:              strings.TrimSpace(finding.Title),
		Summary:            strings.TrimSpace(finding.Summary),
		RuleID:             strings.TrimSpace(finding.RuleID),
		Severity:           strings.TrimSpace(finding.Severity),
		Status:             strings.TrimSpace(finding.Status),
		RuntimeID:          strings.TrimSpace(finding.RuntimeID),
		PrimaryResourceURN: primary,
		ResourceURNs:       resourceURNs,
		EventIDs:           append([]string(nil), finding.EventIDs...),
		FirstObservedAt:    timestampOrEmpty(finding.FirstObservedAt),
		LastObservedAt:     timestampOrEmpty(finding.LastObservedAt),
		ResourceCount:      len(resourceURNs),
		EventCount:         len(finding.EventIDs),
	}
	event, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    snapshot,
		RecordedAt: recordedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	if err := appendLog.Append(ctx, event); err != nil {
		return err
	}
	if _, err := workflowprojection.New(graph).Project(ctx, event); err != nil {
		return err
	}
	return nil
}

func timestampOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

type e2eTTLClock struct {
	now time.Time
}

func (c e2eTTLClock) Now() time.Time { return c.now }

func runtimeThreatE2EEvent(id string, tenantID string, evidenceID string, observedAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   tenantID,
		SourceId:   "runtime",
		Kind:       "runtime.evidence",
		OccurredAt: timestamppb.New(observedAt),
		Attributes: map[string]string{
			"confidence":    "0.95",
			"evidence_id":   evidenceID,
			"evidence_type": "credential_use",
			"resource_urn":  fmt.Sprintf("urn:cerebro:%s:kubernetes_workload:prod-cluster:payments:workload-ttl-e2e", tenantID),
			"verdict":       "confirmed",
		},
	}
}

type e2eGraphFake struct {
	mu       sync.Mutex
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func newE2EGraphFake() *e2eGraphFake {
	return &e2eGraphFake{
		entities: map[string]*ports.ProjectedEntity{},
		links:    map[string]*ports.ProjectedLink{},
	}
}

func (g *e2eGraphFake) Ping(context.Context) error { return nil }

func (g *e2eGraphFake) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	attributes := make(map[string]string, len(entity.Attributes))
	for k, v := range entity.Attributes {
		attributes[k] = v
	}
	g.entities[entity.URN] = &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
	return nil
}

func (g *e2eGraphFake) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	attributes := make(map[string]string, len(link.Attributes))
	for k, v := range link.Attributes {
		attributes[k] = v
	}
	g.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
	return nil
}

func (g *e2eGraphFake) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.links, link.FromURN+"|"+link.Relation+"|"+link.ToURN)
	return nil
}

func (g *e2eGraphFake) DeleteProjectedEntity(_ context.Context, urn string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entities, urn)
	for key, link := range g.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(g.links, key)
		}
	}
	return nil
}

type recordingAppendLog struct {
	mu     sync.Mutex
	events []*cerebrov1.EventEnvelope
}

func (s *recordingAppendLog) Ping(context.Context) error { return nil }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

type stubRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *stubRuntimeStore) Ping(context.Context) error { return nil }

func (s *stubRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return runtime, nil
}

type stubReplayer struct {
	events []*cerebrov1.EventEnvelope
}

func (s *stubReplayer) Replay(context.Context, ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if s == nil || len(s.events) == 0 {
		return nil, nil
	}
	return append([]*cerebrov1.EventEnvelope(nil), s.events...), nil
}

type stubCloseoutStore struct {
	mu   sync.Mutex
	runs map[string]*ports.CloseoutRunRecord
}

func newStubCloseoutStore() *stubCloseoutStore {
	return &stubCloseoutStore{runs: map[string]*ports.CloseoutRunRecord{}}
}

func (s *stubCloseoutStore) InsertCloseoutRun(_ context.Context, run ports.CloseoutRunInsert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.runs[run.RunID]; ok {
		if existing.Status == "running" {
			return ports.ErrCloseoutRunInFlight
		}
		return ports.ErrCloseoutRunAlreadyExists
	}
	for _, existing := range s.runs {
		if existing.Status == "running" {
			return ports.ErrCloseoutRunInFlight
		}
	}
	selector := append([]byte(nil), run.SelectorJSON...)
	startedAt := run.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	heartbeatAt := run.HeartbeatAt.UTC()
	if heartbeatAt.IsZero() {
		heartbeatAt = startedAt
	}
	s.runs[run.RunID] = &ports.CloseoutRunRecord{
		RunID:        run.RunID,
		Actor:        run.Actor,
		ChangeTicket: run.ChangeTicket,
		SelectorJSON: selector,
		Status:       "running",
		StartedAt:    startedAt,
		HeartbeatAt:  heartbeatAt,
		DryRun:       run.DryRun,
	}
	return nil
}

func (s *stubCloseoutStore) FinishCloseoutRun(_ context.Context, finish ports.CloseoutRunFinish) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[finish.RunID]
	if !ok {
		return fmt.Errorf("closeout_run %q not found", finish.RunID)
	}
	existing.Status = finish.Status
	existing.FinishedAt = finish.FinishedAt
	existing.ProposedCount = finish.ProposedCount
	existing.AppliedCount = finish.AppliedCount
	existing.ErrorMessage = finish.ErrorMessage
	return nil
}

func (s *stubCloseoutStore) GetCloseoutRun(_ context.Context, runID string) (*ports.CloseoutRunRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("closeout_run %q not found", runID)
	}
	clone := *existing
	clone.SelectorJSON = append([]byte(nil), existing.SelectorJSON...)
	return &clone, nil
}

func (s *stubCloseoutStore) RefreshCloseoutRunHeartbeat(_ context.Context, runID string, heartbeatAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[runID]
	if !ok {
		return fmt.Errorf("closeout_run %q not found", runID)
	}
	if existing.Status != "running" {
		return nil
	}
	refreshedAt := heartbeatAt.UTC()
	if refreshedAt.IsZero() {
		refreshedAt = time.Now().UTC()
	}
	existing.HeartbeatAt = refreshedAt
	return nil
}

func (s *stubCloseoutStore) BreakStaleRunningCloseoutRuns(_ context.Context, cutoff time.Time, errMessage string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cutoff.IsZero() {
		return 0, nil
	}
	broken := 0
	for _, existing := range s.runs {
		if existing.Status != "running" {
			continue
		}
		freshnessAt := existing.HeartbeatAt
		if freshnessAt.IsZero() {
			freshnessAt = existing.StartedAt
		}
		if !freshnessAt.Before(cutoff) {
			continue
		}
		existing.Status = "failed"
		existing.FinishedAt = time.Now().UTC()
		if strings.TrimSpace(errMessage) != "" {
			existing.ErrorMessage = errMessage
		}
		broken++
	}
	return broken, nil
}

func (s *stubCloseoutStore) UpdateCloseoutRunSummary(_ context.Context, runID, summaryKey string, summaryErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.runs[runID]
	if !ok {
		return fmt.Errorf("closeout_run %q not found", runID)
	}
	if summaryErr != nil {
		existing.Status = "failed"
		existing.FinishedAt = time.Now().UTC()
		existing.ErrorMessage = summaryErr.Error()
		if summaryKey != "" {
			existing.S3SummaryKey = summaryKey
		}
		return nil
	}
	if summaryKey != "" {
		existing.S3SummaryKey = summaryKey
	}
	return nil
}

type stubFindingTombstoneEventStore struct {
	mu     sync.Mutex
	events []ports.FindingTombstoneEvent
}

func newStubFindingTombstoneEventStore() *stubFindingTombstoneEventStore {
	return &stubFindingTombstoneEventStore{}
}

func (s *stubFindingTombstoneEventStore) InsertFindingTombstoneEvent(_ context.Context, event ports.FindingTombstoneEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.TombstonedAt.IsZero() {
		event.TombstonedAt = time.Now().UTC()
	}
	s.events = append(s.events, event)
	return nil
}

func (s *stubFindingTombstoneEventStore) CountFindingTombstoneEventsByRun(_ context.Context, runID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, event := range s.events {
		if event.RunID == runID {
			count++
		}
	}
	return count, nil
}
