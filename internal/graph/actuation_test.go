package graph

import (
	"testing"
	"time"
)

func TestActuateRecommendation(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: map[string]any{"service_id": "payments"}})
	g.AddNode(&Node{ID: "decision:rollback", Kind: NodeKindDecision, Name: "Rollback", Properties: map[string]any{"decision_type": "rollback"}})

	result, err := ActuateRecommendation(g, RecommendationActuationRequest{
		RecommendationID: "rec-123",
		InsightType:      "graph_freshness",
		Title:            "Reduce sync lag",
		Summary:          "Increase scanner cadence for payments",
		DecisionID:       "decision:rollback",
		TargetIDs:        []string{"service:payments"},
		SourceSystem:     "conductor",
		ObservedAt:       now,
	})
	if err != nil {
		t.Fatalf("actuate recommendation failed: %v", err)
	}
	if result.ActionID == "" {
		t.Fatalf("expected action id, got %#v", result)
	}
	if !result.DecisionLinked || result.TargetsLinked != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}

	actionNode, ok := g.GetNode(result.ActionID)
	if !ok || actionNode == nil {
		t.Fatalf("expected action node %q", result.ActionID)
	}
	if actionNode.Kind != NodeKindAction {
		t.Fatalf("expected action node kind, got %q", actionNode.Kind)
	}

	foundTargetLink := false
	for _, edge := range g.GetOutEdges(result.ActionID) {
		if edge != nil && edge.Kind == EdgeKindTargets && edge.Target == "service:payments" {
			foundTargetLink = true
			break
		}
	}
	if !foundTargetLink {
		t.Fatalf("expected target edge from action, got %#v", g.GetOutEdges(result.ActionID))
	}

	foundDecisionLink := false
	for _, edge := range g.GetOutEdges("decision:rollback") {
		if edge != nil && edge.Kind == EdgeKindExecutedBy && edge.Target == result.ActionID {
			foundDecisionLink = true
			break
		}
	}
	if !foundDecisionLink {
		t.Fatalf("expected decision executed_by edge to action")
	}
}

func TestActuateRecommendationValidation(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: map[string]any{"service_id": "payments"}})

	if _, err := ActuateRecommendation(g, RecommendationActuationRequest{}); err == nil {
		t.Fatal("expected validation error when no title/recommendation/insight")
	}

	if _, err := ActuateRecommendation(g, RecommendationActuationRequest{Title: "Do thing", TargetIDs: []string{"service:missing"}}); err == nil {
		t.Fatal("expected target not found error")
	}
}
