package app

import (
	"context"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

func TestParseTapType(t *testing.T) {
	system, entity, action := parseTapType("ensemble.tap.stripe.customer.created")
	if system != "stripe" || entity != "customer" || action != "created" {
		t.Fatalf("unexpected parse result: system=%q entity=%q action=%q", system, entity, action)
	}

	system, entity, action = parseTapType("ensemble.tap.activity.gong.call_completed")
	if system != "gong" || entity != "call_completed" || action != "call_completed" {
		t.Fatalf("unexpected activity parse result: system=%q entity=%q action=%q", system, entity, action)
	}
}

func TestDeriveComputedFields(t *testing.T) {
	now := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)

	hubspot := deriveComputedFields("hubspot", "deal", map[string]any{
		"properties": map[string]any{
			"last_activity_date": "2026-03-01T00:00:00Z",
		},
	}, nil, nil, now)
	if _, ok := hubspot["days_since_last_activity"]; !ok {
		t.Fatal("expected days_since_last_activity for hubspot deal")
	}

	salesforce := deriveComputedFields("salesforce", "opportunity", map[string]any{
		"LastModifiedDate": "2026-02-20T00:00:00Z",
	}, map[string]any{"CloseDate": "2026-04-01"}, nil, now)
	if _, ok := salesforce["days_since_last_modified"]; !ok {
		t.Fatal("expected days_since_last_modified for salesforce opportunity")
	}
	if got := toInt(salesforce["close_date_push_count"]); got < 1 {
		t.Fatalf("expected inferred close_date_push_count >= 1, got %d", got)
	}

	stripe := deriveComputedFields("stripe", "subscription", map[string]any{
		"trial_end": "2026-03-10T00:00:00Z",
	}, nil, nil, now)
	if got := toInt(stripe["days_until_trial_end"]); got <= 0 {
		t.Fatalf("expected positive days_until_trial_end, got %d", got)
	}
}

func TestHandleTapCloudEvent_BuildsBusinessNodeAndEdge(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		Type: "ensemble.tap.hubspot.contact.updated",
		Time: time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"entity_id": "contact-1",
			"snapshot": map[string]interface{}{
				"name":       "Alice",
				"company_id": "company-1",
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	node, ok := a.SecurityGraph.GetNode("hubspot:contact:contact-1")
	if !ok {
		t.Fatal("expected contact node to be created")
	}
	if node.Kind != graph.NodeKindContact {
		t.Fatalf("expected contact node kind, got %q", node.Kind)
	}

	edges := a.SecurityGraph.GetOutEdges("hubspot:contact:contact-1")
	if len(edges) == 0 {
		t.Fatal("expected at least one relationship edge")
	}
	if edges[0].Kind != graph.EdgeKindWorksAt {
		t.Fatalf("expected edge kind %q, got %q", graph.EdgeKindWorksAt, edges[0].Kind)
	}
}

func TestHandleTapCloudEvent_AccumulatesCloseDatePushCount(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	base := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)

	first := events.CloudEvent{
		Type: "ensemble.tap.salesforce.opportunity.updated",
		Time: base,
		Data: map[string]interface{}{
			"entity_id": "opp-1",
			"snapshot": map[string]interface{}{
				"name":             "Renewal Opp",
				"LastModifiedDate": "2026-03-06T12:00:00Z",
			},
			"changes": map[string]interface{}{
				"CloseDate": map[string]interface{}{
					"old": "2026-04-01",
					"new": "2026-04-15",
				},
			},
		},
	}
	if err := a.handleTapCloudEvent(context.Background(), first); err != nil {
		t.Fatalf("first event failed: %v", err)
	}

	second := events.CloudEvent{
		Type: "ensemble.tap.salesforce.opportunity.updated",
		Time: base.Add(5 * time.Minute),
		Data: map[string]interface{}{
			"entity_id": "opp-1",
			"snapshot": map[string]interface{}{
				"name":             "Renewal Opp",
				"LastModifiedDate": "2026-03-06T12:05:00Z",
			},
			"changes": map[string]interface{}{
				"CloseDate": map[string]interface{}{
					"old": "2026-04-15",
					"new": "2026-04-30",
				},
			},
		},
	}
	if err := a.handleTapCloudEvent(context.Background(), second); err != nil {
		t.Fatalf("second event failed: %v", err)
	}

	node, ok := a.SecurityGraph.GetNode("salesforce:opportunity:opp-1")
	if !ok {
		t.Fatal("expected opportunity node to exist")
	}
	if got := toInt(node.Properties["close_date_push_count"]); got != 2 {
		t.Fatalf("close_date_push_count = %d, want 2", got)
	}
}

func TestHandleTapCloudEvent_ActivitySubjectCreatesNodesAndEdges(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		ID:   "evt-activity-1",
		Type: "ensemble.tap.activity.gong.call_completed",
		Time: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"actor": map[string]interface{}{
				"email": "alice@example.com",
				"name":  "Alice",
			},
			"target": map[string]interface{}{
				"id":   "deal-123",
				"type": "deal",
				"name": "Enterprise Renewal",
			},
			"action": "call_completed",
			"metadata": map[string]interface{}{
				"duration_seconds": 1800,
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	actorNodeID := "person:alice@example.com"
	if node, ok := a.SecurityGraph.GetNode(actorNodeID); !ok || node.Kind != graph.NodeKindUser {
		t.Fatalf("expected actor node %q with kind user", actorNodeID)
	}

	targetNodeID := "gong:deal:deal-123"
	if node, ok := a.SecurityGraph.GetNode(targetNodeID); !ok || node.Kind != graph.NodeKindDeal {
		t.Fatalf("expected target node %q with kind deal", targetNodeID)
	}

	activityNodeID := "activity:gong:call_completed:evt-activity-1"
	activityNode, ok := a.SecurityGraph.GetNode(activityNodeID)
	if !ok {
		t.Fatalf("expected activity node %q to be created", activityNodeID)
	}
	if activityNode.Kind != graph.NodeKindActivity {
		t.Fatalf("expected activity node kind %q, got %q", graph.NodeKindActivity, activityNode.Kind)
	}
	if got := activityNode.Properties["action"]; got != "call_completed" {
		t.Fatalf("expected activity action call_completed, got %v", got)
	}

	actorEdges := a.SecurityGraph.GetOutEdges(actorNodeID)
	if len(actorEdges) == 0 || actorEdges[0].Kind != graph.EdgeKindInteractedWith {
		t.Fatalf("expected actor interacted_with edge, got %#v", actorEdges)
	}
}
