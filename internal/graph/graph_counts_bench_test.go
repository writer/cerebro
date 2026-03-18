package graph

import (
	"strconv"
	"testing"
)

func BenchmarkGraphNodeCount(b *testing.B) {
	g := New()
	for i := 0; i < 100000; i++ {
		g.AddNode(&Node{ID: "node:" + strconv.Itoa(i), Kind: NodeKindWorkload})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.NodeCount()
	}
}

func BenchmarkGraphEdgeCount(b *testing.B) {
	g := New()
	for i := 0; i < 100001; i++ {
		g.AddNode(&Node{ID: "node:" + strconv.Itoa(i), Kind: NodeKindWorkload})
	}
	for i := 0; i < 100000; i++ {
		g.AddEdge(&Edge{
			ID:     "edge:" + strconv.Itoa(i),
			Source: "node:" + strconv.Itoa(i),
			Target: "node:" + strconv.Itoa(i+1),
			Kind:   EdgeKindTargets,
			Effect: EdgeEffectAllow,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.EdgeCount()
	}
}
