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

	channel, interactionType := parseTapInteractionType("ensemble.tap.interaction.gong.call_completed")
	if channel != "gong" || interactionType != "call_completed" {
		t.Fatalf("unexpected interaction parse result: channel=%q type=%q", channel, interactionType)
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

func TestHandleTapCloudEvent_InteractionSubjectCreatesPeopleAndEdge(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	now := time.Date(2026, 3, 8, 13, 0, 0, 0, time.UTC)
	evt := events.CloudEvent{
		Type: "ensemble.tap.interaction.gong.call",
		Time: now,
		Data: map[string]interface{}{
			"participants": []any{
				map[string]any{"email": "alice@example.com", "name": "Alice"},
				map[string]any{"email": "bob@example.com", "name": "Bob"},
			},
			"duration_seconds": 1800,
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	aliceNode, ok := a.SecurityGraph.GetNode("person:alice@example.com")
	if !ok {
		t.Fatal("expected alice person node")
	}
	if aliceNode.Kind != graph.NodeKindPerson {
		t.Fatalf("expected alice node kind %q, got %q", graph.NodeKindPerson, aliceNode.Kind)
	}

	edge := findInteractionEdge(a.SecurityGraph, "person:alice@example.com", "person:bob@example.com")
	if edge == nil {
		t.Fatal("expected interaction edge between alice and bob")
	}
	if got := toInt(edge.Properties["frequency"]); got != 1 {
		t.Fatalf("expected frequency=1, got %d", got)
	}
	if got := int(toFloatForTest(edge.Properties["total_duration_seconds"])); got != 1800 {
		t.Fatalf("expected total_duration_seconds=1800, got %d", got)
	}
	if channels := stringSliceForTest(edge.Properties["interaction_channels"]); len(channels) == 0 || channels[0] != "gong" {
		t.Fatalf("expected interaction_channels to include gong, got %+v", channels)
	}
	if types := stringSliceForTest(edge.Properties["interaction_types"]); len(types) == 0 || types[0] != "call" {
		t.Fatalf("expected interaction_types to include call, got %+v", types)
	}
}

func TestHandleTapCloudEvent_InteractionSubjectAggregatesAcrossEvents(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	first := events.CloudEvent{
		Type: "ensemble.tap.interaction.slack.message",
		Time: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"snapshot": map[string]any{
				"participants": []any{
					map[string]any{"id": "person:alice@example.com"},
					map[string]any{"id": "person:bob@example.com"},
				},
				"duration_seconds": 60,
			},
		},
	}
	second := events.CloudEvent{
		Type: "ensemble.tap.interaction.github.review",
		Time: time.Date(2026, 3, 8, 15, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"participants": []any{
				"person:bob@example.com",
				"person:alice@example.com",
			},
			"duration_minutes": 10,
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), first); err != nil {
		t.Fatalf("first interaction event failed: %v", err)
	}
	if err := a.handleTapCloudEvent(context.Background(), second); err != nil {
		t.Fatalf("second interaction event failed: %v", err)
	}

	edge := findInteractionEdge(a.SecurityGraph, "person:alice@example.com", "person:bob@example.com")
	if edge == nil {
		t.Fatal("expected interaction edge between alice and bob")
	}
	if got := toInt(edge.Properties["frequency"]); got != 2 {
		t.Fatalf("expected frequency=2, got %d", got)
	}
	if got := toInt(edge.Properties["previous_frequency"]); got != 1 {
		t.Fatalf("expected previous_frequency=1, got %d", got)
	}
	if got := int(toFloatForTest(edge.Properties["total_duration_seconds"])); got != 660 {
		t.Fatalf("expected total_duration_seconds=660, got %d", got)
	}
	if !containsStringForTest(stringSliceForTest(edge.Properties["interaction_channels"]), "slack") ||
		!containsStringForTest(stringSliceForTest(edge.Properties["interaction_channels"]), "github") {
		t.Fatalf("expected channels to include slack and github, got %+v", edge.Properties["interaction_channels"])
	}
	if !containsStringForTest(stringSliceForTest(edge.Properties["interaction_types"]), "message") ||
		!containsStringForTest(stringSliceForTest(edge.Properties["interaction_types"]), "review") {
		t.Fatalf("expected types to include message and review, got %+v", edge.Properties["interaction_types"])
	}
	lastSeen := timeFromProperty(edge.Properties["last_seen"])
	expected := time.Date(2026, 3, 8, 15, 0, 0, 0, time.UTC)
	if !lastSeen.Equal(expected) {
		t.Fatalf("expected last_seen=%s, got %s", expected.Format(time.RFC3339), lastSeen.Format(time.RFC3339))
	}
}

func TestHandleTapCloudEvent_SchemaEventRegistersRuntimeKinds(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		Type: "ensemble.tap.schema.workday.updated",
		Time: time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"integration": "workday",
			"entity_types": []any{
				map[string]any{
					"kind":       "tap_test_employee_v1",
					"categories": []any{"identity", "business"},
					"properties": map[string]any{
						"title":      "string",
						"department": map[string]any{"type": "string"},
					},
					"relationships": []any{
						map[string]any{"kind": "reports_to"},
					},
				},
				map[string]any{
					"kind": "tap_test_service_v1",
				},
			},
			"edge_types": []any{"tap_test_reports_line_v1"},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("schema event failed: %v", err)
	}

	if !graph.IsNodeKindInCategory(graph.NodeKind("tap_test_employee_v1"), graph.NodeCategoryIdentity) {
		t.Fatal("expected dynamic employee kind to be identity")
	}
	if !graph.IsNodeKindInCategory(graph.NodeKind("tap_test_employee_v1"), graph.NodeCategoryBusiness) {
		t.Fatal("expected dynamic employee kind to be business")
	}
	if !graph.IsNodeKindInCategory(graph.NodeKind("tap_test_service_v1"), graph.NodeCategoryResource) {
		t.Fatal("expected inferred service kind to be resource")
	}
	if !graph.GlobalSchemaRegistry().IsEdgeKindRegistered(graph.EdgeKind("tap_test_reports_line_v1")) {
		t.Fatal("expected dynamic edge kind to be registered")
	}
}

func TestIsTapSchemaEventType(t *testing.T) {
	cases := []struct {
		eventType string
		want      bool
	}{
		{eventType: "ensemble.tap.schema.workday.updated", want: true},
		{eventType: "ensemble.tap.integration.schema.updated", want: true},
		{eventType: "ensemble.tap.salesforce.schema.updated", want: true},
		{eventType: "ensemble.tap.salesforce.contact.updated", want: false},
		{eventType: "ensemble.tap.interaction.slack.message", want: false},
	}

	for _, tc := range cases {
		if got := isTapSchemaEventType(tc.eventType); got != tc.want {
			t.Fatalf("isTapSchemaEventType(%q) = %v, want %v", tc.eventType, got, tc.want)
		}
	}
}

func findInteractionEdge(g *graph.Graph, left, right string) *graph.Edge {
	for _, edge := range g.GetOutEdges(left) {
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == right {
			return edge
		}
	}
	for _, edge := range g.GetOutEdges(right) {
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == left {
			return edge
		}
	}
	return nil
}

func toFloatForTest(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	default:
		return 0
	}
}

func stringSliceForTest(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, anyToString(item))
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func containsStringForTest(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func timeFromProperty(value any) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		parsed, err := time.Parse(time.RFC3339, typed)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
