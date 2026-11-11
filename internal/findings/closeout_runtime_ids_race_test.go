package findings_test

// TestTombstoneOneFinding_RechecksRuntimeIDsBeforeWrite is the F14
// follow-up regression for the list-then-mutate race a reviewer flagged:
// CloseoutSelector.RuntimeIDs is evaluated while listing candidates, but
// a different, still-active runtime can re-assert the identical
// fingerprint/row id (updating its source_runtime_id attribute, status
// unchanged) in the window between that listing call and the per-finding
// tombstone mutation. Without a recheck immediately before the write, the
// row would be tombstoned even though it no longer matches the legacy
// RuntimeIDs scope by the time the mutation actually happens.
//
// This mirrors TestTombstoneOneFinding_RechecksStatusBeforeWrite's
// pattern (a *postgres.Store wrapper that performs one mutation inside
// ListFindings, the exact call TombstoneFindingsBulk uses to build its
// candidate list) but re-asserts the finding under a new runtime instead
// of changing its status, proving the real atomic path
// (ports.FindingTombstoneAtomicRequest.RuntimeIDs, rechecked against the
// row TombstoneFindingAtomic locks with SELECT ... FOR UPDATE) rejects
// the stale candidate rather than trusting the listing-time copy.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
)

func TestTombstoneOneFinding_RechecksRuntimeIDsBeforeWrite(t *testing.T) {
	ctx := context.Background()
	store, rawDB, dsnCleanup := closeoutAtomicPostgresStore(t)
	defer dsnCleanup()

	nonce := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("tenant-runtime-recheck-%d", nonce)
	legacyRuntimeID := "writer-vulnview-vulnerability"
	newRuntimeID := fmt.Sprintf("writer-vulnview-finding-nuclei-%d", nonce)
	ruleID := "vulnview-actionable-external-finding"
	findingID := fmt.Sprintf("finding-runtime-recheck-%d", nonce)
	runID := fmt.Sprintf("run-runtime-recheck-%d", nonce)
	cleanupCloseoutAtomicRows(t, rawDB, tenantID, runID)

	seedTime := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	seeded := &ports.FindingRecord{
		ID:              findingID,
		Fingerprint:     findingID,
		TenantID:        tenantID,
		RuntimeID:       legacyRuntimeID,
		RuleID:          ruleID,
		Title:           "Runtime-recheck regression",
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "finding used for closeout runtime-identity recheck regression",
		ResourceURNs:    []string{fmt.Sprintf("urn:cerebro:%s:external_asset:recheck-%d.example", tenantID, nonce)},
		EventIDs:        []string{fmt.Sprintf("event-%d", nonce)},
		Attributes:      map[string]string{"source_runtime_id": legacyRuntimeID},
		FirstObservedAt: seedTime,
		LastObservedAt:  seedTime,
	}
	if _, err := store.UpsertFinding(ctx, seeded); err != nil {
		t.Fatalf("seed finding %q: %v", findingID, err)
	}

	wrappedStore := &runtimeReassertingListStore{
		Store:         store,
		reassertOnce:  sync.Once{},
		reassertAfter: seeded,
		newRuntimeID:  newRuntimeID,
	}
	service := closeoutAtomicService(wrappedStore, &recordingAppendLog{}, tenantID, legacyRuntimeID)

	result, err := service.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID:   tenantID,
			RuleIDs:    []string{ruleID},
			RuntimeIDs: []string{legacyRuntimeID},
		},
		Reason: "F14 legacy VulnView runtime retirement: orphaned rule-finding rows",
		Actor:  "operator@writer.com",
		RunID:  runID,
		DryRun: false,
	})
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk with interleaved runtime re-assertion: %v", err)
	}
	if wrappedStore.reassertErr != nil {
		t.Fatalf("interleaved re-assertion failed: %v", wrappedStore.reassertErr)
	}
	if !wrappedStore.reasserted {
		t.Fatal("test setup error: interleaved re-assertion hook never ran")
	}
	if result.ProposedCount != 1 {
		t.Fatalf("ProposedCount = %d, want 1", result.ProposedCount)
	}
	if result.AppliedCount != 0 {
		t.Fatalf("AppliedCount = %d, want 0 after a new runtime re-asserted the row before tombstone", result.AppliedCount)
	}
	if result.SkippedCount != 1 {
		t.Fatalf("SkippedCount = %d, want 1", result.SkippedCount)
	}
	after := readCloseoutAtomicSnapshot(t, ctx, rawDB, findingID)
	if after.Status != "open" {
		t.Fatalf("status after interleaved re-assertion = %q, want open", after.Status)
	}
	if after.Tombstoned {
		t.Fatal("re-asserted row was tombstoned; it must survive")
	}
	if count := countCloseoutAtomicAuditRows(t, ctx, rawDB, runID); count != 0 {
		t.Fatalf("audit rows for skipped tombstone = %d, want 0", count)
	}

	// Control: the same legacy-only orphan, seeded without any
	// interleaved re-assertion, is tombstoned normally.
	orphanID := fmt.Sprintf("finding-runtime-recheck-orphan-%d", nonce)
	orphanRunID := fmt.Sprintf("run-runtime-recheck-orphan-%d", nonce)
	cleanupCloseoutAtomicRows(t, rawDB, tenantID, orphanRunID)
	if _, err := store.UpsertFinding(ctx, &ports.FindingRecord{
		ID:              orphanID,
		Fingerprint:     orphanID,
		TenantID:        tenantID,
		RuntimeID:       legacyRuntimeID,
		RuleID:          ruleID,
		Title:           "Runtime-recheck orphan control",
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "orphan control for closeout runtime-identity recheck regression",
		ResourceURNs:    []string{fmt.Sprintf("urn:cerebro:%s:external_asset:recheck-orphan-%d.example", tenantID, nonce)},
		EventIDs:        []string{fmt.Sprintf("event-orphan-%d", nonce)},
		Attributes:      map[string]string{"source_runtime_id": legacyRuntimeID},
		FirstObservedAt: seedTime,
		LastObservedAt:  seedTime,
	}); err != nil {
		t.Fatalf("seed orphan control finding %q: %v", orphanID, err)
	}
	controlService := closeoutAtomicService(store, &recordingAppendLog{}, tenantID, legacyRuntimeID)
	controlResult, err := controlService.TombstoneFindingsBulk(ctx, findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID:   tenantID,
			RuleIDs:    []string{ruleID},
			RuntimeIDs: []string{legacyRuntimeID},
		},
		Reason: "F14 legacy VulnView runtime retirement: orphaned rule-finding rows",
		Actor:  "operator@writer.com",
		RunID:  orphanRunID,
		DryRun: false,
	})
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk for orphan control: %v", err)
	}
	if controlResult.AppliedCount != 1 || controlResult.SkippedCount != 0 {
		t.Fatalf("orphan control result = %#v, want AppliedCount=1 SkippedCount=0", controlResult)
	}
	controlAfter := readCloseoutAtomicSnapshot(t, ctx, rawDB, orphanID)
	if !controlAfter.Tombstoned {
		t.Fatal("orphan control row was not tombstoned")
	}
}

type runtimeReassertingListStore struct {
	*postgres.Store
	reassertOnce  sync.Once
	reassertAfter *ports.FindingRecord
	newRuntimeID  string
	reasserted    bool
	reassertErr   error
}

func (s *runtimeReassertingListStore) ListFindings(ctx context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	records, err := s.Store.ListFindings(ctx, request)
	if err != nil {
		return nil, err
	}
	s.reassertOnce.Do(func() {
		reasserted := *s.reassertAfter
		reasserted.Attributes = map[string]string{"source_runtime_id": s.newRuntimeID}
		_, s.reassertErr = s.UpsertFinding(ctx, &reasserted)
		s.reasserted = true
	})
	return records, nil
}
