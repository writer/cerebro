package graph

import (
	"strconv"
	"testing"
)

func BenchmarkGraphAddEdgeSameIDUpdate(b *testing.B) {
	g := New()
	g.AddEdge(&Edge{
		ID:     "edge-1",
		Source: "node:a",
		Target: "node:b",
		Kind:   EdgeKindTargets,
		Effect: EdgeEffectAllow,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.AddEdge(&Edge{
			ID:     "edge-1",
			Source: "node:a",
			Target: "node:b",
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
		})
	}
}

func BenchmarkGraphAddEdgeDistinctIDs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		g := New()
		for j := 0; j < 1024; j++ {
			g.AddEdge(&Edge{
				ID:     "edge-" + strconv.Itoa(j),
				Source: "node:a",
				Target: "node:b",
				Kind:   EdgeKindTargets,
				Effect: EdgeEffectAllow,
			})
		}
	}
}
