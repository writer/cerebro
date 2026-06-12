package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestRecordAndProjectWorkflowEventPublishesCanonicalFindingEvent(t *testing.T) {
	event, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding: workflowevents.FindingSnapshot{
			FindingID:    "finding-1",
			TenantID:     "tenant-1",
			SourceSystem: "runtime-1",
			RuleID:       "rule-1",
			Title:        "Canonical finding alias",
			Status:       findingStatusOpen,
			Severity:     "high",
		},
		RecordedAt: "2026-05-30T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	appendLog := &recordingAppendLog{}
	service := (&Service{}).WithAppendLog(appendLog)

	if err := service.recordAndProjectWorkflowEvent(context.Background(), event); err != nil {
		t.Fatalf("recordAndProjectWorkflowEvent() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("appended events = %d, want 1", len(appendLog.events))
	}
	canonical := appendLog.events[0]
	if got := canonical.GetKind(); got != securityevents.FindingRecorded {
		t.Fatalf("canonical event kind = %q, want %q", got, securityevents.FindingRecorded)
	}
	if got := canonical.GetSchemaRef(); got != event.GetSchemaRef() {
		t.Fatalf("canonical schema_ref = %q, want %q", got, event.GetSchemaRef())
	}
	if got := canonical.GetAttributes()["canonical_kind"]; got != securityevents.FindingRecorded {
		t.Fatalf("canonical_kind attribute = %q, want %q", got, securityevents.FindingRecorded)
	}
	if canonical.GetId() == event.GetId() {
		t.Fatalf("canonical event reused workflow id %q", event.GetId())
	}
}

func TestRecordAndProjectWorkflowEventDoesNotAliasNonFindingEvent(t *testing.T) {
	appendLog := &recordingAppendLog{}
	service := (&Service{}).WithAppendLog(appendLog)

	if err := service.recordAndProjectWorkflowEvent(context.Background(), &cerebrov1.EventEnvelope{
		Id:   "evt-1",
		Kind: workflowevents.EventKindKnowledgeDecisionRecorded,
	}); err != nil {
		t.Fatalf("recordAndProjectWorkflowEvent() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("appended events = %d, want 1", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != workflowevents.EventKindKnowledgeDecisionRecorded {
		t.Fatalf("event kind = %q, want %q", got, workflowevents.EventKindKnowledgeDecisionRecorded)
	}
}
