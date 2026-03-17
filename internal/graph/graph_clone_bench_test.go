package graph

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkGraphClonePropertyHistory(b *testing.B) {
	base := newGraphClonePropertyHistoryBenchmarkGraph(800, 6)

	b.Run("clone_structural_sharing", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cloned := base.Clone()
			if cloned.NodeCount() != base.NodeCount() {
				b.Fatalf("unexpected clone node count: got %d want %d", cloned.NodeCount(), base.NodeCount())
			}
		}
	})

	b.Run("snapshot_roundtrip", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cloned := RestoreFromSnapshot(CreateSnapshot(base))
			if cloned.NodeCount() != base.NodeCount() {
				b.Fatalf("unexpected clone node count: got %d want %d", cloned.NodeCount(), base.NodeCount())
			}
		}
	})

	b.Run("clone_then_mutate", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			candidate := base.Clone()
			if !candidate.SetNodeProperty("customer:0000", "health_score", float64(i)) {
				b.Fatal("expected clone mutation to succeed")
			}
		}
	})

	b.Run("fork_then_mutate", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			candidate := base.Fork()
			if !candidate.SetNodeProperty("customer:0000", "health_score", float64(i)) {
				b.Fatal("expected fork mutation to succeed")
			}
		}
	})
}

func newGraphClonePropertyHistoryBenchmarkGraph(nodes, historyDepth int) *Graph {
	origNow := temporalNowUTC
	base := time.Date(2026, 3, 17, 13, 0, 0, 0, time.UTC)
	now := base
	temporalNowUTC = func() time.Time { return now }
	defer func() { temporalNowUTC = origNow }()

	g := New()
	for i := 0; i < nodes; i++ {
		nodeID := fmt.Sprintf("customer:%04d", i)
		g.AddNode(&Node{
			ID:         nodeID,
			Kind:       NodeKindCustomer,
			Properties: map[string]any{"health_score": float64(100 + i)},
		})
		for step := 1; step < historyDepth; step++ {
			now = base.Add(time.Duration(step) * time.Minute)
			g.SetNodeProperty(nodeID, "health_score", float64(100+i-step))
		}
	}
	return g
}
