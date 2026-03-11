package graph

import (
	"testing"
	"time"
)

func TestGetOutEdgesAt_RespectsValidityWindow(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "person:alice@example.com",
		Kind: NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
	})
	g.AddEdge(&Edge{
		ID:     "alice-targets-payments",
		Source: "person:alice@example.com",
		Target: "service:payments",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-03T00:00:00Z",
		},
	})

	before := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	if got := len(g.GetOutEdgesAt("person:alice@example.com", before)); got != 0 {
		t.Fatalf("expected no edges before valid_from, got %d", got)
	}

	during := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	if got := len(g.GetOutEdgesAt("person:alice@example.com", during)); got != 1 {
		t.Fatalf("expected one edge during validity, got %d", got)
	}

	after := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	if got := len(g.GetOutEdgesAt("person:alice@example.com", after)); got != 0 {
		t.Fatalf("expected no edges after valid_to, got %d", got)
	}
}

func TestSubgraphAt_FiltersInactiveNodes(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:active",
		Kind: NodeKindService,
		Name: "Active",
		Properties: map[string]any{
			"service_id":  "active",
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "service:expired",
		Kind: NodeKindService,
		Name: "Expired",
		Properties: map[string]any{
			"service_id":  "expired",
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-02T00:00:00Z",
		},
	})

	at := time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC)
	view := g.SubgraphAt(at)
	if view == nil {
		t.Fatal("expected subgraph")
	}
	if _, ok := view.GetNode("service:active"); !ok {
		t.Fatal("expected active service in subgraph")
	}
	if _, ok := view.GetNode("service:expired"); ok {
		t.Fatal("did not expect expired service in subgraph")
	}
}

func TestFreshnessMetrics(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "service:fresh",
		Kind: NodeKindService,
		Name: "Fresh",
		Properties: map[string]any{
			"service_id":  "fresh",
			"observed_at": "2026-03-08T10:00:00Z",
			"valid_from":  "2026-03-08T10:00:00Z",
		},
	})
	g.AddNode(&Node{
		ID:   "service:stale",
		Kind: NodeKindService,
		Name: "Stale",
		Properties: map[string]any{
			"service_id":  "stale",
			"observed_at": "2026-01-01T10:00:00Z",
			"valid_from":  "2026-01-01T10:00:00Z",
		},
	})

	now := time.Date(2026, 3, 8, 22, 0, 0, 0, time.UTC)
	metrics := g.Freshness(now, 7*24*time.Hour)
	if metrics.TotalNodes != 2 {
		t.Fatalf("expected total nodes=2, got %+v", metrics)
	}
	if metrics.FreshNodes != 1 || metrics.StaleNodes != 1 {
		t.Fatalf("expected one fresh and one stale node, got %+v", metrics)
	}
	if metrics.FreshnessPercent <= 0 || metrics.FreshnessPercent >= 100 {
		t.Fatalf("expected partial freshness percent, got %+v", metrics)
	}
}
