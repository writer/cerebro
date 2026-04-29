package workflowprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type eventReplayer struct {
	request ports.ReplayRequest
	events  []*cerebrov1.EventEnvelope
}

func (r *eventReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	r.request = request
	return append([]*cerebrov1.EventEnvelope(nil), r.events...), nil
}

func TestReplayProjectsWorkflowEvents(t *testing.T) {
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	decisionEvent, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:     "writer",
		DecisionID:   "urn:cerebro:writer:decision:decision-1",
		DecisionType: "finding-triage",
		Status:       "approved",
		TargetIDs:    []string{targetURN},
		SourceSystem: "findings",
		ObservedAt:   "2026-04-27T12:00:00Z",
		ValidFrom:    "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	replayer := &eventReplayer{events: []*cerebrov1.EventEnvelope{decisionEvent}}
	graph := &projectionRecorder{}
	result, err := NewReplayer(replayer, graph).Replay(context.Background(), ReplayRequest{
		TenantID: "writer",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if got := replayer.request.KindPrefix; got != defaultWorkflowKindPrefix {
		t.Fatalf("ReplayRequest.KindPrefix = %q, want %q", got, defaultWorkflowKindPrefix)
	}
	if got := replayer.request.TenantID; got != "writer" {
		t.Fatalf("ReplayRequest.TenantID = %q, want writer", got)
	}
	if got := result.EventsRead; got != 1 {
		t.Fatalf("EventsRead = %d, want 1", got)
	}
	if got := result.EventsProjected; got != 1 {
		t.Fatalf("EventsProjected = %d, want 1", got)
	}
	if _, ok := graph.links["urn:cerebro:writer:decision:decision-1|targets|"+targetURN]; !ok {
		t.Fatal("decision target link missing after replay")
	}
}
