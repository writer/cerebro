package findings

import (
	"context"
	"testing"
	"time"
)

// TestCloseoutDryRunNoMutation is the service-level acceptance test for the
// m2-cli-dry-run feature: with DryRun=true the bulk tombstone primitive
// returns a populated proposed set, performs zero writes to findings and
// finding_tombstone_events, and finalises the closeout_run row with
// dry_run=true, applied_count=0, and status='succeeded'. This locks in the
// CLI's default --dry-run code path end to end against the Service surface.
func TestCloseoutDryRunNoMutation(t *testing.T) {
	fx := newCloseoutFixture(t)
	fx.seedFinding("f-1", "open", fx.now.Add(-48*time.Hour), nil)
	fx.seedFinding("f-2", "open", fx.now.Add(-72*time.Hour), nil)
	fx.seedFinding("f-3", "open", fx.now.Add(-96*time.Hour), nil)

	const runID = "run-cli-dry-1"
	req := fx.request(runID, true)

	preTombstoned := tombstonedCount(fx.store)
	preUpdateCalls := fx.store.updateStatusCallCount
	preAppendEvents := len(fx.appendLog.events)

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk dry-run error = %v", err)
	}
	if result == nil {
		t.Fatal("TombstoneFindingsBulk returned nil result")
	}
	if result.RunID != runID {
		t.Errorf("CloseoutResult.RunID = %q, want %q", result.RunID, runID)
	}
	if result.ProposedCount != 3 {
		t.Fatalf("ProposedCount = %d, want 3", result.ProposedCount)
	}
	if len(result.Proposed) != 3 {
		t.Fatalf("len(Proposed) = %d, want 3 (a populated proposed set is required for the dry-run summary)",
			len(result.Proposed))
	}
	if result.AppliedCount != 0 {
		t.Fatalf("AppliedCount = %d, want 0 (dry-run must apply nothing)", result.AppliedCount)
	}
	if len(result.BatchErrors) != 0 {
		t.Errorf("BatchErrors = %v, want empty", result.BatchErrors)
	}
	if len(result.BatchSizes) != 0 {
		t.Errorf("BatchSizes = %v, want empty (dry-run skips the batching loop)", result.BatchSizes)
	}

	if got := tombstonedCount(fx.store); got != preTombstoned {
		t.Errorf("findings.tombstoned count changed during dry-run: before=%d after=%d",
			preTombstoned, got)
	}
	for id, stored := range fx.store.findings {
		if stored.Tombstoned {
			t.Errorf("finding %s tombstoned after dry-run", id)
		}
		if stored.Status != "open" {
			t.Errorf("finding %s status = %q, want open (dry-run must not flip status)",
				id, stored.Status)
		}
	}
	if fx.store.updateStatusCallCount != preUpdateCalls {
		t.Errorf("UpdateFindingStatus calls during dry-run = %d, want %d (dry-run must not mutate)",
			fx.store.updateStatusCallCount-preUpdateCalls, 0)
	}
	if events := fx.tombstone.snapshot(); len(events) != 0 {
		t.Errorf("dry-run wrote %d finding_tombstone_events rows, want 0", len(events))
	}
	if delta := len(fx.appendLog.events) - preAppendEvents; delta != 0 {
		t.Errorf("dry-run emitted %d workflow events, want 0", delta)
	}

	run, err := fx.closeout.GetCloseoutRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("GetCloseoutRun(%q) error = %v", runID, err)
	}
	if !run.DryRun {
		t.Errorf("closeout_run.dry_run = false, want true")
	}
	if run.AppliedCount != 0 {
		t.Errorf("closeout_run.applied_count = %d, want 0", run.AppliedCount)
	}
	if run.Status != "succeeded" {
		t.Errorf("closeout_run.status = %q, want succeeded", run.Status)
	}
	if run.ProposedCount != result.ProposedCount {
		t.Errorf("closeout_run.proposed_count = %d, want %d", run.ProposedCount, result.ProposedCount)
	}
	if run.FinishedAt.IsZero() {
		t.Errorf("closeout_run.finished_at is zero")
	}
	if run.ErrorMessage != "" {
		t.Errorf("closeout_run.error_message = %q, want empty", run.ErrorMessage)
	}
}
