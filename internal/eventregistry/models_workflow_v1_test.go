package eventregistry

import (
	"testing"
)

func TestDecisionRecordedV1Interface(t *testing.T) {
	var e Event = DecisionRecordedV1{
		TenantID:     "t1",
		DecisionID:   "d1",
		DecisionType: "approve",
		Status:       "recorded",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1KnowledgeDecisionRecorded {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1KnowledgeDecisionRecorded)
	}
	if got := e.Version(); got != 1 {
		t.Fatalf("Version() = %d, want 1", got)
	}
	if got := e.SchemaFingerprint(); got != workflowV1DecisionFingerprint {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1DecisionFingerprint)
	}
}

func TestActionRecordedV1Interface(t *testing.T) {
	var e Event = ActionRecordedV1{
		TenantID:     "t1",
		ActionID:     "a1",
		ActionType:   "suspend",
		Status:       "executed",
		Title:        "Suspend",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1KnowledgeActionRecorded {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1KnowledgeActionRecorded)
	}
	if got := e.Version(); got != 1 {
		t.Fatalf("Version() = %d, want 1", got)
	}
	if got := e.SchemaFingerprint(); got != workflowV1ActionFingerprint {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1ActionFingerprint)
	}
}

func TestOutcomeRecordedV1Interface(t *testing.T) {
	var e Event = OutcomeRecordedV1{
		TenantID:     "t1",
		OutcomeID:    "o1",
		DecisionID:   "d1",
		OutcomeType:  "resolved",
		Verdict:      "pass",
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1KnowledgeOutcomeRecorded {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1KnowledgeOutcomeRecorded)
	}
	if got := e.Version(); got != 1 {
		t.Fatalf("Version() = %d, want 1", got)
	}
	if got := e.SchemaFingerprint(); got != workflowV1OutcomeFingerprint {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1OutcomeFingerprint)
	}
}

func TestFindingRecordedV1Interface(t *testing.T) {
	var e Event = FindingRecordedV1{
		Finding:    FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		RecordedAt: "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1FindingRecorded {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1FindingRecorded)
	}
	if got := e.SchemaFingerprint(); got != workflowV1FindingRecordedFP {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1FindingRecordedFP)
	}
}

func TestFindingNoteAddedV1Interface(t *testing.T) {
	var e Event = FindingNoteAddedV1{
		Finding:   FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		NoteID:    "n1",
		Body:      "note body",
		CreatedAt: "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1FindingNoteAdded {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1FindingNoteAdded)
	}
	if got := e.SchemaFingerprint(); got != workflowV1FindingNoteAddedFP {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1FindingNoteAddedFP)
	}
}

func TestFindingTicketLinkedV1Interface(t *testing.T) {
	var e Event = FindingTicketLinkedV1{
		Finding:  FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		URL:      "https://example.com/ticket/1",
		LinkedAt: "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1FindingTicketLinked {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1FindingTicketLinked)
	}
	if got := e.SchemaFingerprint(); got != workflowV1FindingTicketLinkedFP {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1FindingTicketLinkedFP)
	}
}

func TestFindingExternalRefLinkedV1Interface(t *testing.T) {
	var e Event = FindingExternalRefLinkedV1{
		Finding:    FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		System:     "jira",
		Kind:       "ticket",
		ExternalID: "JIRA-123",
		LinkedAt:   "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1FindingExternalRefLinked {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1FindingExternalRefLinked)
	}
	if got := e.SchemaFingerprint(); got != workflowV1FindingExternalRefFP {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1FindingExternalRefFP)
	}
}

func TestFindingStatusChangedV1Interface(t *testing.T) {
	var e Event = FindingStatusChangedV1{
		Finding:   FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		Status:    "closed",
		UpdatedAt: "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1FindingStatusChanged {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1FindingStatusChanged)
	}
	if got := e.SchemaFingerprint(); got != workflowV1FindingStatusChangedFP {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1FindingStatusChangedFP)
	}
}

func TestFindingTombstonedV1Interface(t *testing.T) {
	var e Event = FindingTombstonedV1{
		Finding:      FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		PriorStatus:  "open",
		Reason:       "stale",
		Actor:        "system",
		RunID:        "run-1",
		TombstonedAt: "2024-01-01T00:00:00Z",
	}
	if got := e.Subject(); got != WorkflowV1FindingTombstoned {
		t.Fatalf("Subject() = %q, want %q", got, WorkflowV1FindingTombstoned)
	}
	if got := e.SchemaFingerprint(); got != workflowV1FindingTombstonedFP {
		t.Fatalf("SchemaFingerprint() = %q, want %q", got, workflowV1FindingTombstonedFP)
	}
}

func TestDecisionRecordedV1EncodeAvroRoundTrip(t *testing.T) {
	madeBy := "admin"
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "approve",
		Status:       "recorded",
		MadeBy:       &madeBy,
		TargetIDs:    []string{"target-1", "target-2"},
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
		Metadata:     map[string]any{"key": "value"},
	}
	data, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("EncodeAvro() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("EncodeAvro() returned empty bytes")
	}
}

func TestActionRecordedV1EncodeAvro(t *testing.T) {
	event := ActionRecordedV1{
		TenantID:      "tenant-1",
		ActionID:      "action-1",
		ActionType:    "suspend",
		Status:        "executed",
		Title:         "Suspend user",
		SourceSystem:  "test",
		ObservedAt:    "2024-01-01T00:00:00Z",
		ValidFrom:     "2024-01-01T00:00:00Z",
		AutoGenerated: true,
	}
	data, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("EncodeAvro() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("EncodeAvro() returned empty bytes")
	}
}

func TestOutcomeRecordedV1EncodeAvro(t *testing.T) {
	score := 0.95
	event := OutcomeRecordedV1{
		TenantID:     "tenant-1",
		OutcomeID:    "outcome-1",
		DecisionID:   "dec-1",
		OutcomeType:  "resolved",
		Verdict:      "pass",
		ImpactScore:  &score,
		TargetIDs:    []string{"t1"},
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	data, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("EncodeAvro() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("EncodeAvro() returned empty bytes")
	}
}

func TestFindingRecordedV1EncodeAvro(t *testing.T) {
	title := "High risk"
	event := FindingRecordedV1{
		Finding: FindingSnapshot{
			TenantID:     "tenant-1",
			SourceSystem: "test",
			FindingID:    "finding-1",
			Title:        &title,
			ControlRefs:  []FindingControlRefSnapshot{{FrameworkName: "SOC2", ControlID: "CC6.1"}},
			Metadata:     map[string]string{"env": "prod"},
		},
		RecordedAt: "2024-01-01T00:00:00Z",
	}
	data, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("EncodeAvro() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("EncodeAvro() returned empty bytes")
	}
}

func TestFindingTombstonedV1EncodeAvro(t *testing.T) {
	event := FindingTombstonedV1{
		Finding:      FindingSnapshot{TenantID: "t1", SourceSystem: "test", FindingID: "f1"},
		PriorStatus:  "open",
		Reason:       "deprovisioned",
		Actor:        "system",
		RunID:        "run-1",
		TombstonedAt: "2024-06-01T00:00:00Z",
	}
	data, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("EncodeAvro() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("EncodeAvro() returned empty bytes")
	}
}

func TestEncodeAvroDeterministic(t *testing.T) {
	event := DecisionRecordedV1{
		TenantID:     "tenant-1",
		DecisionID:   "dec-1",
		DecisionType: "approve",
		Status:       "recorded",
		TargetIDs:    []string{"a", "b"},
		SourceSystem: "test",
		ObservedAt:   "2024-01-01T00:00:00Z",
		ValidFrom:    "2024-01-01T00:00:00Z",
	}
	data1, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("first EncodeAvro() error = %v", err)
	}
	data2, err := event.EncodeAvro()
	if err != nil {
		t.Fatalf("second EncodeAvro() error = %v", err)
	}
	if len(data1) != len(data2) {
		t.Fatalf("determinism: len %d != %d", len(data1), len(data2))
	}
	for i := range data1 {
		if data1[i] != data2[i] {
			t.Fatalf("determinism: byte[%d] = %d != %d", i, data1[i], data2[i])
		}
	}
}
