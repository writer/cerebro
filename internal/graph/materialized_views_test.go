package graph

import (
	"testing"
	"time"
)

func TestBlastRadiusTopNUsesCachedViewUntilGraphVersionChanges(t *testing.T) {
	origNow := temporalNowUTC
	defer func() { temporalNowUTC = origNow }()

	base := time.Date(2026, 3, 17, 12, 30, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }

	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice", Account: "acct-a"})
	g.AddNode(&Node{ID: "user:bob", Kind: NodeKindUser, Name: "Bob", Account: "acct-a"})
	g.AddNode(&Node{ID: "bucket:one", Kind: NodeKindBucket, Name: "One", Account: "acct-a", Risk: RiskHigh})
	g.AddNode(&Node{ID: "db:two", Kind: NodeKindDatabase, Name: "Two", Account: "acct-b", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "alice->one", Source: "user:alice", Target: "bucket:one", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "alice->two", Source: "user:alice", Target: "db:two", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "bob->one", Source: "user:bob", Target: "bucket:one", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	first := BlastRadiusTopN(g, 10, 2)
	if len(first.Entries) != 2 {
		t.Fatalf("len(first.Entries) = %d, want 2", len(first.Entries))
	}
	if first.Entries[0].PrincipalID != "user:alice" {
		t.Fatalf("first entry principal = %q, want user:alice", first.Entries[0].PrincipalID)
	}
	if first.GeneratedAt != base {
		t.Fatalf("first.GeneratedAt = %s, want %s", first.GeneratedAt, base)
	}

	now = base.Add(1 * time.Minute)
	cached := BlastRadiusTopN(g, 10, 2)
	if cached.GeneratedAt != first.GeneratedAt {
		t.Fatalf("cached.GeneratedAt = %s, want cached timestamp %s", cached.GeneratedAt, first.GeneratedAt)
	}

	cached.Entries[0].PrincipalName = "tampered"
	again := BlastRadiusTopN(g, 10, 2)
	if again.Entries[0].PrincipalName != "Alice" {
		t.Fatalf("cached mutation leaked into stored view, got %q", again.Entries[0].PrincipalName)
	}

	now = base.Add(2 * time.Minute)
	g.AddNode(&Node{ID: "secret:three", Kind: NodeKindSecret, Name: "Three", Account: "acct-a", Risk: RiskMedium})
	g.AddEdge(&Edge{ID: "bob->three", Source: "user:bob", Target: "secret:three", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	updated := BlastRadiusTopN(g, 10, 2)
	if updated.GeneratedAt != now {
		t.Fatalf("updated.GeneratedAt = %s, want %s", updated.GeneratedAt, now)
	}
	if updated.Entries[0].PrincipalID != "user:alice" {
		t.Fatalf("updated first entry principal = %q, want user:alice", updated.Entries[0].PrincipalID)
	}
	if updated.Entries[1].PrincipalID != "user:bob" {
		t.Fatalf("updated second entry principal = %q, want user:bob", updated.Entries[1].PrincipalID)
	}
	if updated.Entries[1].ReachableCount != 2 {
		t.Fatalf("updated bob reachable_count = %d, want 2", updated.Entries[1].ReachableCount)
	}
}

func TestBlastRadiusTopNRespectsLimitAndSortOrder(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:alpha", Kind: NodeKindUser, Name: "Alpha", Account: "acct-a"})
	g.AddNode(&Node{ID: "user:beta", Kind: NodeKindUser, Name: "Beta", Account: "acct-a"})
	g.AddNode(&Node{ID: "user:gamma", Kind: NodeKindUser, Name: "Gamma", Account: "acct-a"})
	g.AddNode(&Node{ID: "bucket:a", Kind: NodeKindBucket, Account: "acct-a", Risk: RiskHigh})
	g.AddNode(&Node{ID: "bucket:b", Kind: NodeKindBucket, Account: "acct-a", Risk: RiskCritical})
	g.AddNode(&Node{ID: "bucket:c", Kind: NodeKindBucket, Account: "acct-a", Risk: RiskLow})
	g.AddEdge(&Edge{ID: "alpha->a", Source: "user:alpha", Target: "bucket:a", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "alpha->b", Source: "user:alpha", Target: "bucket:b", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "beta->a", Source: "user:beta", Target: "bucket:a", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "beta->c", Source: "user:beta", Target: "bucket:c", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "gamma->c", Source: "user:gamma", Target: "bucket:c", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	view := BlastRadiusTopN(g, 2, 2)
	if len(view.Entries) != 2 {
		t.Fatalf("len(view.Entries) = %d, want 2", len(view.Entries))
	}
	if view.Entries[0].PrincipalID != "user:alpha" {
		t.Fatalf("first entry principal = %q, want user:alpha", view.Entries[0].PrincipalID)
	}
	if view.Entries[1].PrincipalID != "user:beta" {
		t.Fatalf("second entry principal = %q, want user:beta", view.Entries[1].PrincipalID)
	}
	if view.Entries[0].RiskSummary.Critical != 1 {
		t.Fatalf("alpha critical count = %d, want 1", view.Entries[0].RiskSummary.Critical)
	}
}
