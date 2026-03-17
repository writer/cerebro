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

func BenchmarkCascadingBlastRadius(b *testing.B) {
	g := newCascadingBlastRadiusBenchmarkGraph(6, 3)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := CascadingBlastRadius(g, "user:start", 8)
		if result.TotalImpact == 0 {
			b.Fatal("expected cascading blast radius impact")
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

func newCascadingBlastRadiusBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Account: "111"})

	currentLevel := []string{"user:start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("cascade-%d-%d-%d", level, parentIdx, childIdx)
				account := "111"
				if level%2 == 1 && childIdx == fanout-1 {
					account = "222"
				}
				g.AddNode(&Node{
					ID:      nodeID,
					Kind:    NodeKindRole,
					Account: account,
					Risk:    RiskMedium,
				})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, nodeID),
					Source: parentID,
					Target: nodeID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
				})
				if level > 0 {
					g.AddEdge(&Edge{
						ID:     fmt.Sprintf("%s->%s-cycle", nodeID, parentID),
						Source: nodeID,
						Target: parentID,
						Kind:   EdgeKindCanAssume,
						Effect: EdgeEffectAllow,
					})
				}
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	for i, nodeID := range currentLevel {
		resourceID := fmt.Sprintf("bucket:cascade-%d", i)
		g.AddNode(&Node{
			ID:      resourceID,
			Kind:    NodeKindBucket,
			Account: "111",
			Risk:    RiskHigh,
			Properties: map[string]any{
				"contains_pii": i%2 == 0,
			},
		})
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("%s->%s-data", nodeID, resourceID),
			Source: nodeID,
			Target: resourceID,
			Kind:   EdgeKindCanRead,
			Effect: EdgeEffectAllow,
		})
	}

	return g
}
