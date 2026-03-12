package graph

import (
	"testing"
	"time"
)

func TestFreshnessBreakdownGroupsByProviderAndKind(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	g := New()
	g.AddNode(&Node{
		ID:       "service:payments",
		Kind:     NodeKindService,
		Provider: "github",
		Properties: map[string]any{
			"observed_at": now.Add(-30 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:       "bucket:logs",
		Kind:     NodeKindBucket,
		Provider: "aws",
		Properties: map[string]any{
			"observed_at": now.Add(-8 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:       "person:alice@example.com",
		Kind:     NodeKindPerson,
		Provider: "github",
		Properties: map[string]any{
			"observed_at": now.Add(-45 * time.Minute).Format(time.RFC3339),
		},
	})

	breakdown := g.FreshnessBreakdown(now, 6*time.Hour, map[string]time.Duration{
		"aws": 1 * time.Hour,
	})
	if breakdown.Overall.TotalNodes != 3 {
		t.Fatalf("expected 3 total nodes, got %+v", breakdown.Overall)
	}
	if len(breakdown.Providers) != 2 {
		t.Fatalf("expected two provider scopes, got %+v", breakdown.Providers)
	}
	if breakdown.Providers[0].Scope != "aws" || breakdown.Providers[0].StaleNodes != 1 {
		t.Fatalf("expected aws scope to be stale, got %+v", breakdown.Providers[0])
	}
	if breakdown.Providers[0].StaleAfterSeconds != (1 * time.Hour).Seconds() {
		t.Fatalf("expected aws stale_after_seconds=3600, got %+v", breakdown.Providers[0])
	}
	if breakdown.Providers[1].Scope != "github" || breakdown.Providers[1].FreshNodes != 2 {
		t.Fatalf("expected github scope to be fresh, got %+v", breakdown.Providers[1])
	}

	foundService := false
	foundBucket := false
	for _, kind := range breakdown.Kinds {
		switch kind.Scope {
		case string(NodeKindService):
			foundService = true
			if kind.FreshNodes != 1 {
				t.Fatalf("expected service kind fresh_nodes=1, got %+v", kind)
			}
		case string(NodeKindBucket):
			foundBucket = true
			if kind.StaleNodes != 1 {
				t.Fatalf("expected bucket kind stale_nodes=1, got %+v", kind)
			}
		}
	}
	if !foundService || !foundBucket {
		t.Fatalf("expected service and bucket kind scopes, got %+v", breakdown.Kinds)
	}
}

func TestFreshnessBreakdownNilGraph(t *testing.T) {
	var g *Graph
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)

	breakdown := g.FreshnessBreakdown(now, 6*time.Hour, nil)
	if !breakdown.GeneratedAt.Equal(now) {
		t.Fatalf("expected generated_at=%s, got %+v", now, breakdown)
	}
	if breakdown.DefaultStaleAfterSeconds != (6 * time.Hour).Seconds() {
		t.Fatalf("expected stale_after_seconds=%f, got %+v", (6 * time.Hour).Seconds(), breakdown)
	}
	if breakdown.Overall.TotalNodes != 0 {
		t.Fatalf("expected zero-value overall metrics for nil graph, got %+v", breakdown.Overall)
	}
	if len(breakdown.Providers) != 0 || len(breakdown.Kinds) != 0 {
		t.Fatalf("expected no provider/kind scopes for nil graph, got %+v", breakdown)
	}
}
