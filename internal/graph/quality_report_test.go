package graph

import (
	"testing"
	"time"
)

func TestBuildGraphQualityReport(t *testing.T) {
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)
	g := New()

	g.AddNode(&Node{
		ID:   "person:alice@example.com",
		Kind: NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "person:bob@example.com",
		Kind: NodeKindPerson,
		Name: "Bob",
		Properties: map[string]any{
			"email":       "bob@example.com",
			"observed_at": now.Add(-45 * 24 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-45 * 24 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "identity_alias:github:alice",
		Kind: NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "identity_alias:slack:bob",
		Kind: NodeKindIdentityAlias,
		Name: "bob",
		Properties: map[string]any{
			"source_system": "slack",
			"external_id":   "U12345",
			"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": now.Add(-3 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-3 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "decision:rollback",
		Kind: NodeKindDecision,
		Name: "Rollback payments",
		Properties: map[string]any{
			"decision_type": "rollback",
			"status":        "approved",
			"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:rollback",
		Kind: NodeKindOutcome,
		Name: "Rollback impact",
		Properties: map[string]any{
			"outcome_type": "deployment_result",
			"verdict":      "positive",
			"observed_at":  now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "node:unknown",
		Kind: NodeKind("test_graph_quality_unknown_kind_v1"),
		Name: "Unknown",
		Properties: map[string]any{
			"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})

	g.AddEdge(&Edge{ID: "alias-alice", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: EdgeKindAliasOf, Effect: EdgeEffectAllow, Properties: map[string]any{
		"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddEdge(&Edge{ID: "rollback-target", Source: "decision:rollback", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow, Properties: map[string]any{
		"observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":  now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddEdge(&Edge{ID: "outcome-evaluates", Source: "outcome:rollback", Target: "decision:rollback", Kind: EdgeKindEvaluates, Effect: EdgeEffectAllow, Properties: map[string]any{
		"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})

	report := BuildGraphQualityReport(g, GraphQualityReportOptions{
		Now:                 now,
		FreshnessStaleAfter: 7 * 24 * time.Hour,
		SchemaHistoryLimit:  20,
	})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at")
	}
	if report.Summary.Nodes != 8 {
		t.Fatalf("expected 8 nodes, got %d", report.Summary.Nodes)
	}
	if report.Summary.Edges != 3 {
		t.Fatalf("expected 3 edges, got %d", report.Summary.Edges)
	}
	if report.Identity.AliasNodes != 2 || report.Identity.LinkedAliases != 1 || report.Identity.UnlinkedAliases != 1 {
		t.Fatalf("unexpected identity metrics: %#v", report.Identity)
	}
	if report.Identity.LinkagePercent != 50 {
		t.Fatalf("expected 50%% alias linkage, got %.1f", report.Identity.LinkagePercent)
	}
	if report.WriteBack.DecisionNodes != 1 || report.WriteBack.DecisionsWithOutcomes != 1 || report.WriteBack.ClosureRatePercent != 100 {
		t.Fatalf("unexpected writeback metrics: %#v", report.WriteBack)
	}
	if report.Temporal.StaleAfterHours != 168 {
		t.Fatalf("expected stale_after_hours=168, got %d", report.Temporal.StaleAfterHours)
	}
	if report.Summary.MaturityGrade == "" {
		t.Fatalf("expected maturity grade, got %#v", report.Summary)
	}
	if len(report.DomainCoverage) == 0 {
		t.Fatalf("expected domain coverage, got %#v", report.DomainCoverage)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", report.Recommendations)
	}
	foundOntologyRecommendation := false
	for _, recommendation := range report.Recommendations {
		if recommendation.Category == "ontology_coverage" {
			foundOntologyRecommendation = true
			break
		}
	}
	if !foundOntologyRecommendation {
		t.Fatalf("expected ontology_coverage recommendation, got %#v", report.Recommendations)
	}
}

func TestBuildGraphQualityReport_NodeOnlyTemporalCompleteness(t *testing.T) {
	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:   "service:billing",
		Kind: NodeKindService,
		Name: "Billing",
		Properties: map[string]any{
			"service_id":  "billing",
			"observed_at": now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})

	report := BuildGraphQualityReport(g, GraphQualityReportOptions{
		Now:                 now,
		FreshnessStaleAfter: 24 * time.Hour,
	})

	if report.Temporal.NodeObservedCoveragePercent != 100 {
		t.Fatalf("expected node observed coverage to be 100, got %.1f", report.Temporal.NodeObservedCoveragePercent)
	}
	if report.Temporal.NodeValidFromCoveragePercent != 100 {
		t.Fatalf("expected node valid_from coverage to be 100, got %.1f", report.Temporal.NodeValidFromCoveragePercent)
	}
	if report.Temporal.MetadataCompletenessPercent != 100 {
		t.Fatalf("expected metadata completeness to be 100 for node-only graph, got %.1f", report.Temporal.MetadataCompletenessPercent)
	}
}

func TestBuildGraphQualityReport_NilGraph(t *testing.T) {
	report := BuildGraphQualityReport(nil, GraphQualityReportOptions{})
	if len(report.Recommendations) != 1 {
		t.Fatalf("expected one recommendation for nil graph, got %#v", report.Recommendations)
	}
	if report.Recommendations[0].Category != "graph_unavailable" {
		t.Fatalf("expected graph_unavailable recommendation, got %#v", report.Recommendations[0])
	}
}
