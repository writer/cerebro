package graph

import (
	"fmt"
	"testing"
)

func BenchmarkEffectiveAccess(b *testing.B) {
	g := newEffectiveAccessBenchmarkGraph(6, 4)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := EffectiveAccess(g, "user:start", "bucket:target", 8)
		if !result.Allowed {
			b.Fatal("expected effective access path")
		}
	}
}

func newEffectiveAccessBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "bucket:target", Kind: NodeKindBucket, Account: "111"})

	currentLevel := []string{"user:start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("query-%d-%d-%d", level, parentIdx, childIdx)
				g.AddNode(&Node{ID: nodeID, Kind: NodeKindRole, Account: "111"})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, nodeID),
					Source: parentID,
					Target: nodeID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
				})
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	lastNodeID := currentLevel[len(currentLevel)-1]
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->bucket:target", lastNodeID),
		Source: lastNodeID,
		Target: "bucket:target",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	return g
}
