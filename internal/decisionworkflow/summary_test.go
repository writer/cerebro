package decisionworkflow

import (
	"testing"
	"time"
)

func TestSummarizeDeduplicatesDurableReplay(t *testing.T) {
	start := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	decision := DecisionRecord{
		ID: "decision-1", TenantID: "tenant-1", Workflow: WorkflowFindingToVerifiedFix,
		State: DecisionSupported, Disposition: DispositionAccepted, RecordedAt: start.Add(time.Hour),
		AuthenticatedTenant: true, Durable: true,
	}
	outcome := OutcomeRecord{
		ID: "outcome-1", DecisionID: decision.ID, Outcome: OutcomeVerifiedClosed, RecordedAt: start.Add(25 * time.Hour),
	}
	summary, err := Summarize(
		[]DecisionRecord{decision, decision},
		[]OutcomeRecord{outcome, outcome},
		start, start.Add(7*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Completed != 1 || summary.ByWorkflow[WorkflowFindingToVerifiedFix] != 1 || summary.CompletionLatency != 24*time.Hour {
		t.Fatalf("summary = %+v, want one 24-hour completion", summary)
	}
}

func TestSummarizeExcludesLaterReopen(t *testing.T) {
	start := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	decision := DecisionRecord{
		ID: "decision-1", TenantID: "tenant-1", Workflow: WorkflowFindingToVerifiedFix,
		State: DecisionSupported, Disposition: DispositionAccepted, RecordedAt: start,
		AuthenticatedTenant: true, Durable: true,
	}
	outcomes := []OutcomeRecord{
		{ID: "outcome-closed", DecisionID: decision.ID, Outcome: OutcomeVerifiedClosed, RecordedAt: start.Add(time.Hour)},
		{ID: "outcome-reopened", DecisionID: decision.ID, Outcome: OutcomeReopened, RecordedAt: start.Add(2 * time.Hour)},
	}
	summary, err := Summarize([]DecisionRecord{decision}, outcomes, start, start.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Completed != 0 {
		t.Fatalf("Completed = %d, want 0 after reopen", summary.Completed)
	}
}

func TestSummarizeLetsReopenWinTimestampTie(t *testing.T) {
	start := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	decision := DecisionRecord{
		ID: "decision-1", TenantID: "tenant-1", Workflow: WorkflowFindingToVerifiedFix,
		State: DecisionSupported, Disposition: DispositionAccepted, RecordedAt: start,
		AuthenticatedTenant: true, Durable: true,
	}
	observedAt := start.Add(time.Hour)
	outcomes := []OutcomeRecord{
		{ID: "z-closed", DecisionID: decision.ID, Outcome: OutcomeVerifiedClosed, RecordedAt: observedAt},
		{ID: "a-reopened", DecisionID: decision.ID, Outcome: OutcomeReopened, RecordedAt: observedAt},
	}
	summary, err := Summarize([]DecisionRecord{decision}, outcomes, start, start.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Completed != 0 {
		t.Fatalf("Completed = %d, want 0 when reopen shares the closure timestamp", summary.Completed)
	}
}

func TestSummarizeRequiresAuditExportReceipt(t *testing.T) {
	start := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	decision := DecisionRecord{
		ID: "decision-1", TenantID: "tenant-1", Workflow: WorkflowContinuousEvidence,
		State: DecisionSupportedWithGaps, Disposition: DispositionAccepted, RecordedAt: start,
		AuthenticatedTenant: true, Durable: true,
	}
	outcome := OutcomeRecord{
		ID: "outcome-1", DecisionID: decision.ID, Outcome: OutcomeAuditPacketDelivered, RecordedAt: start.Add(time.Hour),
	}
	summary, err := Summarize([]DecisionRecord{decision}, []OutcomeRecord{outcome}, start, start.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Completed != 0 {
		t.Fatalf("Completed = %d without receipt, want 0", summary.Completed)
	}
	outcome.AuditPacketExportReceiptID = "export-receipt-1"
	summary, err = Summarize([]DecisionRecord{decision}, []OutcomeRecord{outcome}, start, start.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("Summarize() with receipt error = %v", err)
	}
	if summary.Completed != 1 {
		t.Fatalf("Completed = %d with receipt, want 1", summary.Completed)
	}
}

func TestSummarizeRejectsConflictingReplayIdentity(t *testing.T) {
	start := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	decision := DecisionRecord{
		ID: "decision-1", TenantID: "tenant-1", Workflow: WorkflowChangeDecision,
		State: DecisionSupported, Disposition: DispositionAccepted, RecordedAt: start,
		AuthenticatedTenant: true, Durable: true,
	}
	conflict := decision
	conflict.State = DecisionBlocked
	summary, err := Summarize([]DecisionRecord{decision, conflict}, nil, start, start.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Completed != 0 || summary.ConflictedRecords != 1 {
		t.Fatalf("summary = %+v, want one conflict and no completion", summary)
	}
}
