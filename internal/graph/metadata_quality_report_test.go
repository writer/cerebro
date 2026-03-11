package graph

import (
	"testing"
	"time"
)

func TestBuildGraphMetadataQualityReport(t *testing.T) {
	now := time.Date(2026, 3, 9, 20, 0, 0, 0, time.UTC)
	g := New()

	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "deployment:payments:1",
		Kind: NodeKindDeploymentRun,
		Name: "Deploy #1",
		Properties: map[string]any{
			"deploy_id":       "dep-1",
			"service_id":      "payments",
			"environment":     "production",
			"status":          "mystery_status",
			"source_system":   "github",
			"source_event_id": "evt-deploy-1",
			"observed_at":     "not-a-time",
			"valid_from":      now.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{ID: "company:acme", Kind: NodeKindCompany, Name: "Acme"})

	report := BuildGraphMetadataQualityReport(g, GraphMetadataQualityReportOptions{Now: now, TopKinds: 10})

	if report.GeneratedAt.IsZero() {
		t.Fatal("expected generated_at")
	}
	if report.Summary.Nodes != 3 {
		t.Fatalf("expected 3 nodes, got %d", report.Summary.Nodes)
	}
	if report.Summary.ProfiledKinds < 2 {
		t.Fatalf("expected at least 2 profiled kinds, got %d", report.Summary.ProfiledKinds)
	}
	if report.Summary.RequiredKeyCoveragePercent >= 100 {
		t.Fatalf("expected required key coverage < 100, got %.1f", report.Summary.RequiredKeyCoveragePercent)
	}
	if report.Summary.TimestampValidityPercent >= 100 {
		t.Fatalf("expected timestamp validity < 100, got %.1f", report.Summary.TimestampValidityPercent)
	}
	if report.Summary.EnumValidityPercent >= 100 {
		t.Fatalf("expected enum validity < 100, got %.1f", report.Summary.EnumValidityPercent)
	}
	if len(report.Kinds) == 0 {
		t.Fatalf("expected per-kind rows, got %#v", report.Kinds)
	}
	if len(report.UnprofiledKinds) == 0 {
		t.Fatalf("expected unprofiled kinds, got %#v", report.UnprofiledKinds)
	}
	if !hasMetadataRecommendationCategory(report.Recommendations, "required_keys") {
		t.Fatalf("expected required_keys recommendation, got %#v", report.Recommendations)
	}
}

func TestBuildGraphMetadataQualityReport_NilGraph(t *testing.T) {
	report := BuildGraphMetadataQualityReport(nil, GraphMetadataQualityReportOptions{})
	if len(report.Recommendations) != 1 {
		t.Fatalf("expected one recommendation for nil graph, got %#v", report.Recommendations)
	}
	if report.Recommendations[0].Category != "graph_unavailable" {
		t.Fatalf("expected graph_unavailable recommendation, got %#v", report.Recommendations[0])
	}
}

func TestBuildGraphMetadataQualityReport_EnumZeroStillGeneratesRecommendation(t *testing.T) {
	now := time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:   "deployment:payments:2",
		Kind: NodeKindDeploymentRun,
		Name: "Deploy #2",
		Properties: map[string]any{
			"deploy_id":       "dep-2",
			"service_id":      "payments",
			"environment":     "invalid_env",
			"status":          "invalid_status",
			"source_system":   "ci",
			"source_event_id": "evt-2",
			"observed_at":     now.Format(time.RFC3339),
			"valid_from":      now.Format(time.RFC3339),
		},
	})

	report := BuildGraphMetadataQualityReport(g, GraphMetadataQualityReportOptions{Now: now, TopKinds: 10})
	if report.Summary.EnumValidityPercent != 0 {
		t.Fatalf("expected enum validity 0, got %.1f", report.Summary.EnumValidityPercent)
	}
	if !hasMetadataRecommendationCategory(report.Recommendations, "enum_normalization") {
		t.Fatalf("expected enum_normalization recommendation at 0%% enum validity, got %#v", report.Recommendations)
	}
}

func hasMetadataRecommendationCategory(recommendations []GraphMetadataRecommendation, category string) bool {
	for _, recommendation := range recommendations {
		if recommendation.Category == category {
			return true
		}
	}
	return false
}
