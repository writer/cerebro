package workflowprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
)

type eventReplayer struct {
	requests       []ports.ReplayRequest
	events         []*cerebrov1.EventEnvelope
	eventsByPrefix map[string][]*cerebrov1.EventEnvelope
}

func (r *eventReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	r.requests = append(r.requests, request)
	if r.eventsByPrefix != nil {
		return append([]*cerebrov1.EventEnvelope(nil), r.eventsByPrefix[request.KindPrefix]...), nil
	}
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
	replayer := &eventReplayer{eventsByPrefix: map[string][]*cerebrov1.EventEnvelope{
		defaultWorkflowKindPrefix: {decisionEvent},
	}}
	graph := &projectionRecorder{}
	result, err := NewReplayer(replayer, graph).Replay(context.Background(), ReplayRequest{
		TenantID: "writer",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(replayer.requests) != 2 {
		t.Fatalf("Replay() requests = %d, want 2", len(replayer.requests))
	}
	if got := replayer.requests[0].KindPrefix; got != defaultWorkflowKindPrefix {
		t.Fatalf("ReplayRequest[0].KindPrefix = %q, want %q", got, defaultWorkflowKindPrefix)
	}
	if got := replayer.requests[1].KindPrefix; got != securityevents.FindingsV1Prefix+"." {
		t.Fatalf("ReplayRequest[1].KindPrefix = %q, want sec findings prefix", got)
	}
	if got := replayer.requests[0].TenantID; got != "writer" {
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

func TestReplayProjectsCanonicalFindingEvents(t *testing.T) {
	findingEvent, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding: workflowevents.FindingSnapshot{
			TenantID:           "writer",
			SourceSystem:       "findings",
			FindingID:          "finding-1",
			Title:              "Risky resource",
			Status:             "open",
			PrimaryResourceURN: "urn:cerebro:writer:asset:resource-1",
		},
		RecordedAt: "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	canonical := *findingEvent
	canonical.Kind = securityevents.FindingRecorded
	graph := &projectionRecorder{}
	result, err := NewReplayer(&eventReplayer{eventsByPrefix: map[string][]*cerebrov1.EventEnvelope{
		securityevents.FindingsV1Prefix + ".": {&canonical},
	}}, graph).Replay(context.Background(), ReplayRequest{TenantID: "writer"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if got := result.EventsRead; got != 1 {
		t.Fatalf("EventsRead = %d, want 1", got)
	}
	if got := result.EventsProjected; got != 1 {
		t.Fatalf("EventsProjected = %d, want 1", got)
	}
	if len(graph.entities) == 0 {
		t.Fatal("canonical finding replay did not project graph entities")
	}
}
