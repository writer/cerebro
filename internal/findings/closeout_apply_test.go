package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// TestCloseoutS3SummaryShape locks in the S3 audit summary payload shape
// (VAL-CLI-006). The document MUST carry run_id, actor, env, selector,
// proposed_count, applied_count, batch_errors, and a per_rule array so
// downstream reconciliation tooling stays parseable.
func TestCloseoutS3SummaryShape(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFindingWithRule("f-a-1", "rule-alpha", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFindingWithRule("f-a-2", "rule-alpha", "open", fx.now.Add(-49*time.Hour), nil)
	fx.seedFindingWithRule("f-b-1", "rule-beta", "open", fx.now.Add(-72*time.Hour), nil)

	req := fx.request("run-shape-1", false)
	req.Selector.RuleIDs = []string{"rule-alpha", "rule-beta"}
	req.ChangeTicket = "CHG-42"
	req.Environment = "sec-dev"

	startedAt := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}

	summary := BuildCloseoutSummary(result, CloseoutSummaryInputs{
		Actor:        CloseoutSummaryActor{Principal: req.Actor, RoleARN: "arn:aws:iam::000000000000:role/closeout"},
		Env:          req.Environment,
		Selector:     req.Selector,
		Reason:       req.Reason,
		ChangeTicket: req.ChangeTicket,
		DryRun:       req.DryRun,
		StartedAt:    startedAt,
		FinishedAt:   finishedAt,
	})

	body, err := summary.MarshalIndent()
	if err != nil {
		t.Fatalf("MarshalIndent error = %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(body, &roundTripped); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	for _, key := range []string{
		"run_id", "actor", "env", "selector", "proposed_count",
		"applied_count", "batch_errors", "per_rule",
	} {
		if _, ok := roundTripped[key]; !ok {
			t.Errorf("summary missing key %q: %s", key, string(body))
		}
	}
	if summary.RunID != "run-shape-1" {
		t.Errorf("run_id = %q, want run-shape-1", summary.RunID)
	}
	if summary.Env != "sec-dev" {
		t.Errorf("env = %q, want sec-dev", summary.Env)
	}
	if summary.Actor.Principal != req.Actor {
		t.Errorf("actor.principal = %q, want %q", summary.Actor.Principal, req.Actor)
	}
	if summary.AppliedCount != 3 || summary.ProposedCount != 3 {
		t.Errorf("counts = (proposed=%d applied=%d), want (3,3)", summary.ProposedCount, summary.AppliedCount)
	}
	if summary.ChangeTicket != "CHG-42" {
		t.Errorf("change_ticket = %q, want CHG-42", summary.ChangeTicket)
	}
	if len(summary.BatchErrors) != 0 {
		t.Errorf("batch_errors = %v, want []", summary.BatchErrors)
	}
	wantPerRule := []CloseoutPerRuleCount{
		{RuleID: "rule-alpha", Applied: 2},
		{RuleID: "rule-beta", Applied: 1},
	}
	if len(summary.PerRule) != len(wantPerRule) {
		t.Fatalf("per_rule = %v, want %v", summary.PerRule, wantPerRule)
	}
	for i, entry := range summary.PerRule {
		if entry != wantPerRule[i] {
			t.Errorf("per_rule[%d] = %+v, want %+v", i, entry, wantPerRule[i])
		}
	}
	if !strings.Contains(string(body), `"per_rule"`) {
		t.Errorf("serialized body must contain per_rule key:\n%s", string(body))
	}
}

// TestCloseoutIdempotentRunID asserts I-6 (CROSS-006): re-running with the
// same --run-id performs zero additional writes while returning the persisted
// run counts, and the closeout_run table has exactly one row for that run_id.
func TestCloseoutIdempotentRunID(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-2", "open", fx.now.Add(-72*time.Hour), nil)

	first, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-idem-shared", false))
	if err != nil {
		t.Fatalf("first apply error = %v", err)
	}
	if first.AppliedCount != 2 {
		t.Fatalf("first applied_count = %d, want 2", first.AppliedCount)
	}

	beforeAudit, _ := fx.tombstone.CountFindingTombstoneEventsByRun(context.Background(), "run-idem-shared")
	beforeTombstoned := tombstonedCount(fx.store)

	second, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-idem-shared", false))
	if err != nil {
		t.Fatalf("second apply error = %v", err)
	}
	if second.AppliedCount != first.AppliedCount {
		t.Fatalf("second applied_count = %d, want persisted %d", second.AppliedCount, first.AppliedCount)
	}
	if second.ProposedCount != first.ProposedCount {
		t.Fatalf("second proposed_count = %d, want persisted %d", second.ProposedCount, first.ProposedCount)
	}
	afterAudit, _ := fx.tombstone.CountFindingTombstoneEventsByRun(context.Background(), "run-idem-shared")
	if afterAudit != beforeAudit {
		t.Fatalf("audit count changed on re-run: before=%d after=%d", beforeAudit, afterAudit)
	}
	if got := tombstonedCount(fx.store); got != beforeTombstoned {
		t.Fatalf("tombstoned count changed on re-run: before=%d after=%d", beforeTombstoned, got)
	}

	runCount := 0
	fx.closeout.mu.Lock()
	for runID := range fx.closeout.runs {
		if runID == "run-idem-shared" {
			runCount++
		}
	}
	fx.closeout.mu.Unlock()
	if runCount != 1 {
		t.Fatalf("closeout_run rows for run-idem-shared = %d, want 1", runCount)
	}
}

// TestCloseoutBatchLogShape asserts that TombstoneFindingsBulk invokes the
// BatchLogger once per attempted batch with the pinned field names (run_id,
// batch_index, batch_size, actor, env) and that the run boundary still
// finalizes cleanly so the CLI can emit closeout.end after the last batch
// log.
func TestCloseoutBatchLogShape(t *testing.T) {
	fx := newCloseoutFixture(t)
	for i := 0; i < 11; i++ {
		fx.seedFinding(fmt.Sprintf("f-%02d", i), "open", fx.now.Add(-48*time.Hour-time.Duration(i)*time.Minute), nil)
	}

	events := []CloseoutBatchEvent{}
	req := fx.request("run-batchlog-1", false)
	req.MaxBatchSize = 5
	req.Environment = "sec-dev"
	req.BatchLogger = func(event CloseoutBatchEvent) {
		events = append(events, event)
	}
	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}

	wantSizes := []int{5, 5, 1}
	if len(events) != len(wantSizes) {
		t.Fatalf("BatchLogger invocations = %d, want %d", len(events), len(wantSizes))
	}
	for i, event := range events {
		if event.RunID != "run-batchlog-1" {
			t.Errorf("events[%d].run_id = %q, want run-batchlog-1", i, event.RunID)
		}
		if event.Actor != req.Actor {
			t.Errorf("events[%d].actor = %q, want %q", i, event.Actor, req.Actor)
		}
		if event.Env != "sec-dev" {
			t.Errorf("events[%d].env = %q, want sec-dev", i, event.Env)
		}
		if event.BatchIndex != i {
			t.Errorf("events[%d].batch_index = %d, want %d", i, event.BatchIndex, i)
		}
		if event.BatchSize != wantSizes[i] {
			t.Errorf("events[%d].batch_size = %d, want %d", i, event.BatchSize, wantSizes[i])
		}
	}

	run, err := fx.closeout.GetCloseoutRun(context.Background(), "run-batchlog-1")
	if err != nil {
		t.Fatalf("GetCloseoutRun error = %v", err)
	}
	if run.Status != "succeeded" {
		t.Errorf("closeout_run.status = %q, want succeeded (run boundary must finalize after the last batch)", run.Status)
	}
	if result.AppliedCount != 11 {
		t.Errorf("AppliedCount = %d, want 11", result.AppliedCount)
	}
}

// TestCloseoutBatchFailureMarksFailed asserts VAL-CLI-008: a batch failure
// flips closeout_run to status='failed', records the first batch error in
// error_message, leaves the committed tombstones durable, and the bulk
// primitive returns a non-nil error with AppliedCount reflecting committed
// batches only.
func TestCloseoutBatchFailureMarksFailed(t *testing.T) {
	fx := newCloseoutFixture(t)
	for i := 0; i < 6; i++ {
		fx.seedFinding(fmt.Sprintf("f-%02d", i), "open", fx.now.Add(-48*time.Hour-time.Duration(i)*time.Minute), nil)
	}

	failAfter := 3
	wrapped := newAuditStoreFailingAfter(fx.tombstone, failAfter, errors.New("inject batch failure"))
	fx.service.tombstoneEventStore = wrapped

	req := fx.request("run-batchfail-1", false)
	req.MaxBatchSize = 2
	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err == nil {
		t.Fatalf("expected non-nil error from injected batch failure")
	}
	if result == nil {
		t.Fatalf("result is nil; need committed-batch counts to be observable")
	}
	if result.AppliedCount != failAfter {
		t.Errorf("AppliedCount = %d, want %d (committed batches only)", result.AppliedCount, failAfter)
	}

	run, runErr := fx.closeout.GetCloseoutRun(context.Background(), "run-batchfail-1")
	if runErr != nil {
		t.Fatalf("GetCloseoutRun error = %v", runErr)
	}
	if run.Status != "failed" {
		t.Errorf("closeout_run.status = %q, want failed", run.Status)
	}
	if strings.TrimSpace(run.ErrorMessage) == "" {
		t.Errorf("closeout_run.error_message is empty; want the first batch error")
	}
	if run.FinishedAt.IsZero() {
		t.Errorf("closeout_run.finished_at is zero")
	}

	auditCount, _ := fx.tombstone.CountFindingTombstoneEventsByRun(context.Background(), "run-batchfail-1")
	if auditCount != failAfter {
		t.Errorf("committed audit rows = %d, want %d (durable across failure)", auditCount, failAfter)
	}
	if tombstoned := tombstonedCount(fx.store); tombstoned < failAfter {
		t.Errorf("committed tombstones = %d, want >= %d (durable across failure)", tombstoned, failAfter)
	}
}

// TestCloseoutRejectsConcurrentRun asserts I-8 (CROSS-008): a second --apply
// run while another run is still active (status='running' and started_at >
// now()-1h) is rejected at the closeout_run row layer with the conflicting
// run_id, leaving the committed tombstones from the first run untouched.
func TestCloseoutRejectsConcurrentRun(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)

	if err := fx.closeout.InsertCloseoutRun(context.Background(), ports.CloseoutRunInsert{
		RunID:        "run-active",
		Actor:        "operator",
		SelectorJSON: []byte(`{}`),
		StartedAt:    time.Now().UTC().Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("seed running row error = %v", err)
	}

	_, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-blocked-by-active", false))
	if err == nil {
		t.Fatal("expected concurrent-run rejection")
	}
	if !errors.Is(err, ErrCloseoutAnotherRunning) {
		t.Errorf("error %v should match ErrCloseoutAnotherRunning", err)
	}

	if tombstonedCount(fx.store) != 0 {
		t.Errorf("tombstones written despite rejection: %d", tombstonedCount(fx.store))
	}

	active, getErr := fx.closeout.GetCloseoutRun(context.Background(), "run-active")
	if getErr != nil {
		t.Fatalf("GetCloseoutRun(active) error = %v", getErr)
	}
	if active.Status != "running" {
		t.Errorf("blocking row status = %q, want running (must not be overwritten by the rejected run)", active.Status)
	}
}

// TestCloseoutBreaksStaleLock asserts I-8 (CROSS-008) recovery path: a
// status='running' row whose started_at is older than 1h is treated as stale,
// flipped to status='failed' with finished_at set, and the new run is allowed
// to proceed.
func TestCloseoutBreaksStaleLock(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)

	staleStartedAt := time.Now().UTC().Add(-2 * time.Hour)
	if err := fx.closeout.InsertCloseoutRun(context.Background(), ports.CloseoutRunInsert{
		RunID:        "run-stale",
		Actor:        "ghost-operator",
		SelectorJSON: []byte(`{}`),
		StartedAt:    staleStartedAt,
	}); err != nil {
		t.Fatalf("seed stale running row error = %v", err)
	}

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-after-stale", false))
	if err != nil {
		t.Fatalf("expected stale-lock break to allow new run, got %v", err)
	}
	if result.AppliedCount != 1 {
		t.Errorf("AppliedCount = %d, want 1", result.AppliedCount)
	}

	stale, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-stale")
	if stale == nil || stale.Status != "failed" {
		t.Errorf("stale row status = %v, want failed", staleStatus(stale))
	}
	if stale != nil && stale.FinishedAt.IsZero() {
		t.Errorf("stale row finished_at is zero; stale-lock break must set finished_at")
	}

	newRun, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-after-stale")
	if newRun == nil || newRun.Status != "succeeded" {
		t.Errorf("new run status = %v, want succeeded", staleStatus(newRun))
	}
}

func TestTombstoneFindingsBulk_StaleRecoveryUsesHeartbeat(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)

	now := time.Now().UTC()
	if err := fx.closeout.InsertCloseoutRun(context.Background(), ports.CloseoutRunInsert{
		RunID:        "run-long-heartbeat",
		Actor:        "operator",
		SelectorJSON: []byte(`{}`),
		StartedAt:    now.Add(-2 * time.Hour),
		HeartbeatAt:  now.Add(-5 * time.Minute),
	}); err != nil {
		t.Fatalf("seed long-running row error = %v", err)
	}

	_, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-blocked-by-heartbeat", false))
	if err == nil {
		t.Fatal("expected fresh-heartbeat run to block second invocation")
	}
	if !errors.Is(err, ErrCloseoutAnotherRunning) {
		t.Fatalf("fresh-heartbeat error = %v, want ErrCloseoutAnotherRunning", err)
	}
	active, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-long-heartbeat")
	if active == nil || active.Status != "running" {
		t.Fatalf("fresh-heartbeat row status = %v, want running", staleStatus(active))
	}

	if err := fx.closeout.RefreshCloseoutRunHeartbeat(context.Background(), "run-long-heartbeat", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("stale heartbeat update error = %v", err)
	}
	result, err := fx.service.TombstoneFindingsBulk(context.Background(), fx.request("run-after-stale-heartbeat", false))
	if err != nil {
		t.Fatalf("expected stale heartbeat to be reclaimed, got %v", err)
	}
	if result.AppliedCount != 1 {
		t.Fatalf("AppliedCount = %d, want 1", result.AppliedCount)
	}
	reclaimed, _ := fx.closeout.GetCloseoutRun(context.Background(), "run-long-heartbeat")
	if reclaimed == nil || reclaimed.Status != "failed" {
		t.Fatalf("stale-heartbeat row status = %v, want failed", staleStatus(reclaimed))
	}
}

// TestTombstoneFindingsBulk_EmitsHeartbeat asserts VAL-M6-CLOSEOUT-HEARTBEAT-001:
// apply runs keep closeout_run fresh while batch processing is still in progress.
func TestTombstoneFindingsBulk_EmitsHeartbeat(t *testing.T) {
	if closeoutHeartbeatInterval >= closeoutStaleRunCutoff/3 {
		t.Fatalf("closeoutHeartbeatInterval = %s, want < stale cutoff/3 (%s)", closeoutHeartbeatInterval, closeoutStaleRunCutoff/3)
	}

	fx := newCloseoutFixture(t)
	for i := 0; i < 3; i++ {
		fx.seedFinding(fmt.Sprintf("f-heartbeat-%d", i), "open", fx.now.Add(-48*time.Hour-time.Duration(i)*time.Minute), nil)
	}
	fx.service.closeoutHeartbeatInterval = 10 * time.Millisecond
	observing := newHeartbeatObservingCloseoutStore(fx.closeout)
	fx.service.closeoutStore = observing

	var initialHeartbeat time.Time
	var observedHeartbeat time.Time
	req := fx.request("run-heartbeat-1", false)
	req.MaxBatchSize = 3
	req.BatchLogger = func(CloseoutBatchEvent) {
		run, err := observing.GetCloseoutRun(context.Background(), req.RunID)
		if err != nil {
			t.Errorf("GetCloseoutRun during batch: %v", err)
			return
		}
		initialHeartbeat = run.HeartbeatAt
		if initialHeartbeat.IsZero() {
			t.Errorf("initial heartbeat_at is zero")
			return
		}
		deadline := time.After(2 * time.Second)
		for {
			select {
			case heartbeatAt := <-observing.heartbeats:
				if heartbeatAt.After(initialHeartbeat) {
					observedHeartbeat = heartbeatAt
					return
				}
			case <-deadline:
				t.Errorf("timed out waiting for heartbeat refresh after %s", initialHeartbeat.Format(time.RFC3339Nano))
				return
			}
		}
	}

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk error = %v", err)
	}
	if result.AppliedCount != 3 {
		t.Fatalf("AppliedCount = %d, want 3", result.AppliedCount)
	}
	if observedHeartbeat.IsZero() {
		t.Fatalf("heartbeat was not observed during batch processing")
	}
	if !observedHeartbeat.After(initialHeartbeat) {
		t.Fatalf("heartbeat_at did not advance: initial=%s observed=%s", initialHeartbeat, observedHeartbeat)
	}
}

func staleStatus(run *ports.CloseoutRunRecord) string {
	if run == nil {
		return "<nil>"
	}
	return run.Status
}

type heartbeatObservingCloseoutStore struct {
	inner      *stubCloseoutStore
	heartbeats chan time.Time
}

func newHeartbeatObservingCloseoutStore(inner *stubCloseoutStore) *heartbeatObservingCloseoutStore {
	return &heartbeatObservingCloseoutStore{
		inner:      inner,
		heartbeats: make(chan time.Time, 16),
	}
}

func (s *heartbeatObservingCloseoutStore) InsertCloseoutRun(ctx context.Context, run ports.CloseoutRunInsert) error {
	return s.inner.InsertCloseoutRun(ctx, run)
}

func (s *heartbeatObservingCloseoutStore) RetryFailedCloseoutRun(ctx context.Context, runID string, heartbeatAt time.Time) error {
	return s.inner.RetryFailedCloseoutRun(ctx, runID, heartbeatAt)
}

func (s *heartbeatObservingCloseoutStore) FinishCloseoutRun(ctx context.Context, finish ports.CloseoutRunFinish) error {
	return s.inner.FinishCloseoutRun(ctx, finish)
}

func (s *heartbeatObservingCloseoutStore) GetCloseoutRun(ctx context.Context, runID string) (*ports.CloseoutRunRecord, error) {
	return s.inner.GetCloseoutRun(ctx, runID)
}

func (s *heartbeatObservingCloseoutStore) RefreshCloseoutRunHeartbeat(_ context.Context, runID string, heartbeatAt time.Time) error {
	s.inner.mu.Lock()
	existing, ok := s.inner.runs[runID]
	if !ok {
		s.inner.mu.Unlock()
		return fmt.Errorf("closeout_run %q not found", runID)
	}
	if existing.Status == "running" {
		existing.HeartbeatAt = heartbeatAt.UTC()
	}
	refreshedAt := existing.HeartbeatAt
	s.inner.mu.Unlock()
	select {
	case s.heartbeats <- refreshedAt:
	default:
	}
	return nil
}

func (s *heartbeatObservingCloseoutStore) BreakStaleRunningCloseoutRuns(ctx context.Context, cutoff time.Time, errMessage string) (int, error) {
	return s.inner.BreakStaleRunningCloseoutRuns(ctx, cutoff, errMessage)
}

func (s *heartbeatObservingCloseoutStore) UpdateCloseoutRunSummary(ctx context.Context, runID, summaryKey string, summaryErr error) error {
	return s.inner.UpdateCloseoutRunSummary(ctx, runID, summaryKey, summaryErr)
}

// auditStoreFailingAfter wraps a tombstone audit store so that the (n+1)th
// InsertFindingTombstoneEvent returns the supplied error. The first n inserts
// pass through normally so the apply loop commits batches before the failure
// surfaces.
type auditStoreFailingAfter struct {
	inner *stubFindingTombstoneEventStore
	limit int
	fail  error
	calls int
}

func newAuditStoreFailingAfter(inner *stubFindingTombstoneEventStore, limit int, fail error) *auditStoreFailingAfter {
	return &auditStoreFailingAfter{inner: inner, limit: limit, fail: fail}
}

func (s *auditStoreFailingAfter) InsertFindingTombstoneEvent(ctx context.Context, event ports.FindingTombstoneEvent) error {
	s.calls++
	if s.calls > s.limit {
		return s.fail
	}
	return s.inner.InsertFindingTombstoneEvent(ctx, event)
}

func (s *auditStoreFailingAfter) CountFindingTombstoneEventsByRun(ctx context.Context, runID string) (int, error) {
	return s.inner.CountFindingTombstoneEventsByRun(ctx, runID)
}

// helper to ensure deterministic per-rule sort assertions even when callers
// drop entries; not used directly in tests but kept here to avoid future
// drift when the canonical sort order changes.
var _ = sort.SliceStable
