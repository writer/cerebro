package workflowprojection

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

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
		events := append([]*cerebrov1.EventEnvelope(nil), r.eventsByPrefix[request.KindPrefix]...)
		for _, kindPrefix := range request.KindPrefixes {
			events = append(events, r.eventsByPrefix[kindPrefix]...)
		}
		return events, nil
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(r.events))
	for _, event := range r.events {
		if replayTestMatchesPrefix(event.GetKind(), request.KindPrefix, request.KindPrefixes) {
			events = append(events, event)
		}
	}
	return events, nil
}

func replayTestMatchesPrefix(kind string, kindPrefix string, kindPrefixes []string) bool {
	if strings.TrimSpace(kindPrefix) == "" && len(kindPrefixes) == 0 {
		return true
	}
	if strings.TrimSpace(kindPrefix) != "" && strings.HasPrefix(kind, strings.TrimSpace(kindPrefix)) {
		return true
	}
	for _, prefix := range kindPrefixes {
		if strings.TrimSpace(prefix) != "" && strings.HasPrefix(kind, strings.TrimSpace(prefix)) {
			return true
		}
	}
	return false
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
	if len(replayer.requests) != 1 {
		t.Fatalf("Replay() requests = %d, want 1", len(replayer.requests))
	}
	if got := replayer.requests[0].KindPrefixes; len(got) != 2 || got[0] != defaultWorkflowKindPrefix || got[1] != securityevents.FindingsV1Prefix+"." {
		t.Fatalf("ReplayRequest.KindPrefixes = %v, want workflow and sec findings prefixes", got)
	}
	if got := replayer.requests[0].KindPrefix; got != "" {
		t.Fatalf("ReplayRequest.KindPrefix = %q, want empty multi-prefix request", got)
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
	canonical := proto.Clone(findingEvent).(*cerebrov1.EventEnvelope)
	canonical.Kind = securityevents.FindingRecorded
	graph := &projectionRecorder{}
	result, err := NewReplayer(&eventReplayer{eventsByPrefix: map[string][]*cerebrov1.EventEnvelope{
		securityevents.FindingsV1Prefix + ".": {canonical},
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

func TestReplayDefaultPrefixesPreserveChronologyAcrossCanonicalAndWorkflowEvents(t *testing.T) {
	findingID := "finding-1"
	anchorURN := "urn:cerebro:writer:asset:resource-1"
	recorded, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding: workflowevents.FindingSnapshot{
			TenantID:           "writer",
			SourceSystem:       "findings",
			FindingID:          findingID,
			Title:              "Risky resource",
			Status:             "open",
			PrimaryResourceURN: anchorURN,
			ResourceURNs:       []string{anchorURN},
		},
		RecordedAt: "2026-04-27T11:59:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	recorded = proto.Clone(recorded).(*cerebrov1.EventEnvelope)
	recorded.Kind = securityevents.FindingRecorded
	tombstoned, err := workflowevents.NewFindingTombstonedEvent(workflowevents.FindingTombstoned{
		Finding: workflowevents.FindingSnapshot{
			TenantID:           "writer",
			SourceSystem:       "findings",
			FindingID:          findingID,
			Title:              "Risky resource",
			Status:             "tombstoned",
			PrimaryResourceURN: anchorURN,
			ResourceURNs:       []string{anchorURN},
		},
		PriorStatus:  "open",
		Reason:       "bulk closeout",
		Actor:        "operator",
		RunID:        "run-1",
		TombstonedAt: "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingTombstonedEvent() error = %v", err)
	}
	graph := &projectionRecorder{}
	result, err := NewReplayer(&eventReplayer{events: []*cerebrov1.EventEnvelope{recorded, tombstoned}}, graph).Replay(context.Background(), ReplayRequest{TenantID: "writer"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if got := result.EventsRead; got != 2 {
		t.Fatalf("EventsRead = %d, want 2", got)
	}
	linkKey := anchorURN + "|" + relationHasFinding + "|" + findingURN("writer", findingID)
	if _, ok := graph.links[linkKey]; ok {
		t.Fatalf("tombstoned finding link %q was resurrected", linkKey)
	}
}
