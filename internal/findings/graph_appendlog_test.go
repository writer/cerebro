package findings

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
)

type graphlessRecordingAppendLog struct {
	events []*cerebrov1.EventEnvelope
}

func (l *graphlessRecordingAppendLog) Ping(context.Context) error { return nil }

func (l *graphlessRecordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func TestProjectFindingWorkflowAppendsEventsWithoutGraph(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	finding := graphlessWorkflowFinding(now)
	appendLog := &graphlessRecordingAppendLog{}
	service := (&Service{}).WithAppendLog(appendLog)

	if err := service.projectFindingAnchor(context.Background(), finding); err != nil {
		t.Fatalf("projectFindingAnchor() error = %v", err)
	}
	if err := service.projectFindingNote(context.Background(), finding, ports.FindingNote{
		ID:        "note-1",
		Body:      "Reviewed by security.",
		CreatedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("projectFindingNote() error = %v", err)
	}
	if err := service.projectFindingTicket(context.Background(), finding, ports.FindingTicket{
		URL:      "https://jira.example/browse/SEC-844",
		Name:     "SEC-844",
		LinkedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("projectFindingTicket() error = %v", err)
	}

	wantKinds := []string{
		securityevents.FindingRecorded,
		securityevents.FindingNoteAdded,
		securityevents.FindingTicketLinked,
	}
	if len(appendLog.events) != len(wantKinds) {
		t.Fatalf("appended events = %d, want %d", len(appendLog.events), len(wantKinds))
	}
	for i, want := range wantKinds {
		if got := appendLog.events[i].GetKind(); got != want {
			t.Fatalf("event[%d].kind = %q, want %q", i, got, want)
		}
	}
}

func TestRecordFindingStatusWorkflowAppendsWithoutGraph(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	finding := graphlessWorkflowFinding(now)
	finding.Status = findingStatusResolved
	finding.StatusReason = "accepted risk remediated"
	finding.StatusUpdatedAt = now.Add(time.Hour)
	appendLog := &graphlessRecordingAppendLog{}
	service := (&Service{}).WithAppendLog(appendLog)

	if err := service.recordFindingStatusWorkflow(context.Background(), finding, "manual"); err != nil {
		t.Fatalf("recordFindingStatusWorkflow() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("appended events = %d, want 1", len(appendLog.events))
	}
	if got := appendLog.events[0].GetKind(); got != securityevents.FindingStatusChanged {
		t.Fatalf("canonical event kind = %q, want %q", got, securityevents.FindingStatusChanged)
	}
}

func graphlessWorkflowFinding(now time.Time) *ports.FindingRecord {
	return &ports.FindingRecord{
		ID:              "finding-1",
		Fingerprint:     "fp-1",
		TenantID:        "tenant-1",
		RuntimeID:       "runtime-1",
		RuleID:          "rule-1",
		Title:           "Graphless finding",
		Severity:        "high",
		Status:          findingStatusOpen,
		Summary:         "A finding that should emit workflow events without graph projection.",
		ResourceURNs:    []string{"urn:cerebro:tenant-1:resource:identity-1"},
		EventIDs:        []string{"event-1"},
		FirstObservedAt: now,
		LastObservedAt:  now,
		Attributes:      map[string]string{},
	}
}
