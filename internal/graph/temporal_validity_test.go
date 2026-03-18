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

func TestGetAllNodesAt_UsesTypedObservationTemporalBounds(t *testing.T) {
	g := New()
	validFrom := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	validTo := validFrom.Add(2 * time.Hour)
	g.AddNode(&Node{
		ID:   "observation:runtime:future",
		Kind: NodeKindObservation,
		Name: "runtime_signal",
		Properties: map[string]any{
			"observation_type": "runtime_signal",
			"subject_id":       "workload:payments",
			"detail":           "future window",
			"source_system":    "agent",
			"source_event_id":  "evt-future-window",
			"observed_at":      validFrom.Format(time.RFC3339),
			"valid_from":       validFrom.Format(time.RFC3339),
			"valid_to":         validTo.Format(time.RFC3339),
			"recorded_at":      validFrom.Format(time.RFC3339),
			"transaction_from": validFrom.Format(time.RFC3339),
		},
	})

	before := validFrom.Add(-time.Minute)
	if got := g.GetAllNodesAt(before); len(got) != 0 {
		t.Fatalf("expected no active compact observation nodes before valid_from, got %d", len(got))
	}

	during := validFrom.Add(time.Minute)
	if got := g.GetAllNodesAt(during); len(got) != 1 {
		t.Fatalf("expected one active compact observation node during validity, got %d", len(got))
	}

	after := validTo.Add(time.Minute)
	if got := len(g.SubgraphAt(after).GetAllNodes()); got != 0 {
		t.Fatalf("expected compact observation node to be absent after valid_to, got %d nodes", got)
	}
}

func TestGetAllNodesAt_UsesTypedAttackSequenceObservedAtAsStartFallback(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	sequenceEnd := observedAt.Add(2 * time.Hour)
	g.AddNode(&Node{
		ID:   "attack_sequence:runtime:payments",
		Kind: NodeKindAttackSequence,
		Name: "payments sequence",
		Properties: map[string]any{
			"sequence_id":      "runtime:payments",
			"status":           "open",
			"severity":         "high",
			"sequence_end":     sequenceEnd.Format(time.RFC3339),
			"observed_at":      observedAt.Format(time.RFC3339),
			"recorded_at":      observedAt.Format(time.RFC3339),
			"transaction_from": observedAt.Format(time.RFC3339),
		},
	})

	beforeObserved := observedAt.Add(-time.Minute)
	if got := len(g.GetAllNodesAt(beforeObserved)); got != 0 {
		t.Fatalf("expected attack sequence to be inactive before observed_at fallback, got %d nodes", got)
	}

	duringWindow := observedAt.Add(time.Minute)
	if got := len(g.GetAllNodesAt(duringWindow)); got != 1 {
		t.Fatalf("expected attack sequence to be active after observed_at fallback, got %d nodes", got)
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
