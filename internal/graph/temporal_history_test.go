package graph

import (
	"testing"
	"time"
)

func TestTemporalHistoryDeltaTrendStreak(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 8, 9, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "customer:acme",
		Kind:       NodeKindCustomer,
		Properties: map[string]any{"health_score": 80.0},
	})

	now = base.Add(24 * time.Hour)
	g.SetNodeProperty("customer:acme", "health_score", 70.0)
	now = base.Add(48 * time.Hour)
	g.SetNodeProperty("customer:acme", "health_score", 55.0)
	now = base.Add(72 * time.Hour)

	history := g.GetNodePropertyHistory("customer:acme", "health_score", 0)
	if len(history) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(history))
	}
	if history[0].Value != 80.0 || history[1].Value != 70.0 || history[2].Value != 55.0 {
		t.Fatalf("unexpected history values: %#v", history)
	}

	delta, ok := g.TemporalDelta("customer:acme", "health_score", 0)
	if !ok {
		t.Fatal("expected delta to be available")
	}
	if delta != -25.0 {
		t.Fatalf("expected delta -25.0, got %f", delta)
	}

	trend, ok := g.TemporalTrend("customer:acme", "health_score", 0)
	if !ok {
		t.Fatal("expected trend to be available")
	}
	if trend != "decreasing" {
		t.Fatalf("expected decreasing trend, got %q", trend)
	}

	streak, ok := g.TemporalStreak("customer:acme", "health_score", "<=", 70.0, 0)
	if !ok {
		t.Fatal("expected streak to be available")
	}
	if streak != 2 {
		t.Fatalf("expected streak 2, got %d", streak)
	}

	if _, ok := g.TemporalStreak("customer:acme", "health_score", "!=", 70.0, 0); ok {
		t.Fatal("expected invalid operator to return ok=false")
	}
}

func TestTemporalHistoryWindowFiltering(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 8, 9, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "customer:globex",
		Kind:       NodeKindCustomer,
		Properties: map[string]any{"open_tickets": 100},
	})

	now = base.Add(1 * time.Hour)
	g.SetNodeProperty("customer:globex", "open_tickets", 90)
	now = base.Add(2 * time.Hour)
	g.SetNodeProperty("customer:globex", "open_tickets", 80)
	now = base.Add(150 * time.Minute)

	history := g.GetNodePropertyHistory("customer:globex", "open_tickets", 1*time.Hour)
	if len(history) != 1 {
		t.Fatalf("expected 1 recent snapshot, got %d", len(history))
	}
	if history[0].Value != 80 {
		t.Fatalf("expected recent value 80, got %#v", history[0].Value)
	}

	delta, ok := g.TemporalDelta("customer:globex", "open_tickets", 90*time.Minute)
	if !ok {
		t.Fatal("expected delta over 90m window")
	}
	if delta != -10 {
		t.Fatalf("expected delta -10, got %f", delta)
	}
}

func TestCompactTemporalHistoryRollup(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	now := time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "customer:initech",
		Kind:       NodeKindCustomer,
		Properties: map[string]any{"health_score": 70.0},
	})

	g.mu.Lock()
	node := g.nodes["customer:initech"]
	node.PropertyHistory["health_score"] = []PropertySnapshot{
		{Timestamp: now.Add(-10 * time.Hour), Value: 100.0},
		{Timestamp: now.Add(-9*time.Hour - 30*time.Minute), Value: 95.0},
		{Timestamp: now.Add(-8*time.Hour - 10*time.Minute), Value: 90.0},
		{Timestamp: now.Add(-2 * time.Hour), Value: 80.0},
		{Timestamp: now.Add(-30 * time.Minute), Value: 70.0},
	}
	g.mu.Unlock()

	g.CompactTemporalHistory(3*time.Hour, 1*time.Hour)

	history := g.GetNodePropertyHistory("customer:initech", "health_score", 0)
	if len(history) != 4 {
		t.Fatalf("expected 4 compacted snapshots, got %d", len(history))
	}
	if history[0].Value != 95.0 || history[1].Value != 90.0 || history[2].Value != 80.0 || history[3].Value != 70.0 {
		t.Fatalf("unexpected compacted values: %#v", history)
	}
}

func TestAddNodeUpdatePreservesPropertyHistory(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 8, 9, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:         "person:alice@example.com",
		Kind:       NodeKindPerson,
		Properties: map[string]any{"team": "red"},
	})

	now = base.Add(1 * time.Hour)
	g.AddNode(&Node{
		ID:         "person:alice@example.com",
		Kind:       NodeKindPerson,
		Properties: map[string]any{"team": "blue"},
	})

	history := g.GetNodePropertyHistory("person:alice@example.com", "team", 0)
	if len(history) != 2 {
		t.Fatalf("expected history to retain both snapshots, got %d (%#v)", len(history), history)
	}
	if history[0].Value != "red" || history[1].Value != "blue" {
		t.Fatalf("unexpected history values: %#v", history)
	}
}

func TestSnapshotDeepCopiesPropertyHistory(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 8, 9, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{
		ID:   "customer:hooli",
		Kind: NodeKindCustomer,
		Properties: map[string]any{
			"meta": map[string]any{"stage": "initial"},
		},
	})
	now = base.Add(1 * time.Hour)
	g.SetNodeProperty("customer:hooli", "meta", map[string]any{"stage": "updated"})

	snapshot := CreateSnapshot(g)
	snapshotNode := findSnapshotNode(snapshot, "customer:hooli")
	if snapshotNode == nil {
		t.Fatal("expected node in snapshot")
	}

	g.mu.Lock()
	current := g.nodes["customer:hooli"]
	meta := current.PropertyHistory["meta"][0].Value.(map[string]any)
	meta["stage"] = "mutated"
	g.mu.Unlock()

	snapshotMeta := snapshotNode.PropertyHistory["meta"][0].Value.(map[string]any)
	if snapshotMeta["stage"] != "initial" {
		t.Fatalf("expected snapshot history to be isolated, got %#v", snapshotMeta)
	}
}

func findSnapshotNode(snapshot *Snapshot, id string) *Node {
	if snapshot == nil {
		return nil
	}
	for _, node := range snapshot.Nodes {
		if node != nil && node.ID == id {
			return node
		}
	}
	return nil
}
