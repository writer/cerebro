package graph

import (
	"testing"
	"time"
)

func TestBuildGraphLeverageReport(t *testing.T) {
	now := time.Date(2026, 3, 9, 20, 0, 0, 0, time.UTC)
	g := New()

	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"email":         "alice@example.com",
		"source_system": "github",
		"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "identity_alias:github:alice", Kind: NodeKindIdentityAlias, Name: "alice", Properties: map[string]any{
		"source_system": "github",
		"external_id":   "alice",
		"email":         "alice@example.com",
		"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments", Properties: map[string]any{
		"service_id":    "payments",
		"source_system": "ci",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "decision:rollback", Kind: NodeKindDecision, Name: "Rollback", Properties: map[string]any{
		"decision_type": "rollback",
		"status":        "approved",
		"source_system": "conductor",
		"observed_at":   now.Add(-48 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-48 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "outcome:rollback", Kind: NodeKindOutcome, Name: "Rollback outcome", Properties: map[string]any{
		"outcome_type":  "deployment_result",
		"verdict":       "positive",
		"source_system": "conductor",
		"observed_at":   now.Add(-3 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-3 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "action:fix-sync", Kind: NodeKindAction, Name: "Fix sync", Properties: map[string]any{
		"action_type":    "recommendation_actuation",
		"status":         "planned",
		"auto_generated": true,
		"source_system":  "agent",
		"observed_at":    now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":     now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&Node{ID: "evidence:latency", Kind: NodeKindEvidence, Name: "Latency spike", Properties: map[string]any{
		"evidence_type": "incident_timeline",
		"source_system": "incident",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})

	g.AddEdge(&Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: EdgeKindAliasOf, Effect: EdgeEffectAllow, Properties: map[string]any{"source_system": "github", "observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339), "valid_from": now.Add(-1 * time.Hour).Format(time.RFC3339)}})
	g.AddEdge(&Edge{ID: "decision-target", Source: "decision:rollback", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow, Properties: map[string]any{"source_system": "conductor", "observed_at": now.Add(-48 * time.Hour).Format(time.RFC3339), "valid_from": now.Add(-48 * time.Hour).Format(time.RFC3339)}})
	g.AddEdge(&Edge{ID: "outcome-evaluates", Source: "outcome:rollback", Target: "decision:rollback", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow, Properties: map[string]any{"source_system": "conductor", "observed_at": now.Add(-3 * time.Hour).Format(time.RFC3339), "valid_from": now.Add(-3 * time.Hour).Format(time.RFC3339)}})
	g.AddEdge(&Edge{ID: "decision-exec", Source: "decision:rollback", Target: "action:fix-sync", Kind: EdgeKindExecutedBy, Effect: EdgeEffectAllow, Properties: map[string]any{"source_system": "conductor", "observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339), "valid_from": now.Add(-2 * time.Hour).Format(time.RFC3339)}})
	g.AddEdge(&Edge{ID: "action-target", Source: "action:fix-sync", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow, Properties: map[string]any{"source_system": "agent", "observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339), "valid_from": now.Add(-2 * time.Hour).Format(time.RFC3339)}})

	if _, err := ReviewIdentityAlias(g, IdentityReviewDecision{
		AliasNodeID:     "identity_alias:github:alice",
		CanonicalNodeID: "person:alice@example.com",
		Verdict:         IdentityReviewVerdictAccepted,
		ObservedAt:      now,
		Reviewer:        "reviewer-1",
		Reason:          "exact email",
	}); err != nil {
		t.Fatalf("review identity failed: %v", err)
	}

	report := BuildGraphLeverageReport(g, GraphLeverageReportOptions{
		Now:                 now,
		FreshnessStaleAfter: 7 * 24 * time.Hour,
		RecentWindow:        24 * time.Hour,
		DecisionStaleAfter:  7 * 24 * time.Hour,
		IdentityQueueLimit:  10,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated timestamp")
	}
	if report.Summary.LeverageScore <= 0 {
		t.Fatalf("expected leverage score > 0, got %#v", report.Summary)
	}
	if report.Ingestion.CoveragePercent <= 0 {
		t.Fatalf("expected ingestion coverage > 0, got %#v", report.Ingestion)
	}
	if report.Ontology.CanonicalKindCoveragePercent <= 0 {
		t.Fatalf("expected ontology canonical coverage > 0, got %#v", report.Ontology)
	}
	if report.Ontology.SchemaValidWritePercent <= 0 {
		t.Fatalf("expected ontology schema valid write percent > 0, got %#v", report.Ontology)
	}
	if len(report.Ontology.Trend) == 0 {
		t.Fatalf("expected ontology trend points, got %#v", report.Ontology)
	}
	if report.Identity.PrecisionPercent <= 0 {
		t.Fatalf("expected identity precision > 0, got %#v", report.Identity)
	}
	if report.ClosedLoop.DecisionsWithOutcomes != 1 {
		t.Fatalf("expected one closed-loop decision, got %#v", report.ClosedLoop)
	}
	if report.Query.TemplateCount == 0 {
		t.Fatalf("expected query templates, got %#v", report.Query)
	}
	if report.Actuation.ActionNodes != 1 {
		t.Fatalf("expected one action node, got %#v", report.Actuation)
	}
	if report.Actuation.ActionsWithOutcomes != 1 {
		t.Fatalf("expected one action with outcomes, got %#v", report.Actuation)
	}
	if report.Actuation.OutcomeCompletionRate <= 0 {
		t.Fatalf("expected positive outcome completion rate, got %#v", report.Actuation)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", report)
	}
}

func TestBuildGraphLeverageReportNilGraph(t *testing.T) {
	report := BuildGraphLeverageReport(nil, GraphLeverageReportOptions{})
	if report.Summary.Healthy {
		t.Fatalf("expected unhealthy report for nil graph, got %#v", report.Summary)
	}
	if len(report.Recommendations) != 1 || report.Recommendations[0].Category != "graph_unavailable" {
		t.Fatalf("expected graph_unavailable recommendation, got %#v", report.Recommendations)
	}
}
