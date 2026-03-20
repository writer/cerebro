package graph

import (
	"fmt"
	"testing"
)

func BenchmarkImpactPathAnalyzerAnalyze(b *testing.B) {
	g := newImpactPathBenchmarkGraph(5, 4)
	analyzer := NewImpactPathAnalyzer(g)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := analyzer.Analyze("start", ImpactScenarioRevenueImpact, 6)
		if len(result.Paths) == 0 {
			b.Fatal("expected impact paths")
		}
	}
}

func newImpactPathBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "start", Kind: NodeKindSubscription, Name: "Start"})

	currentLevel := []string{"start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("impact-%d-%d-%d", level, parentIdx, childIdx)
				kind := NodeKindApplication
				if level == levels-1 {
					kind = NodeKindCustomer
				}
				g.AddNode(&Node{
					ID:         nodeID,
					Kind:       kind,
					Name:       nodeID,
					Properties: map[string]any{"arr": float64((level + 1) * 10000)},
				})
				edgeKind := EdgeKindSubscribedTo
				if level > 0 {
					edgeKind = EdgeKindOwns
				}
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, nodeID),
					Source: parentID,
					Target: nodeID,
					Kind:   edgeKind,
					Effect: EdgeEffectAllow,
				})
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	return g
}
