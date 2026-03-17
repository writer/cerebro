package graph

import (
	"fmt"
	"testing"
)

func BenchmarkAttackPathSimulatorFindShortestPath(b *testing.B) {
	g, entry, target := newAttackPathTraversalBenchmarkGraph(6, 4)
	sim := NewAttackPathSimulator(g)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		path := sim.findShortestPath(entry, target, 8)
		if path == nil {
			b.Fatal("expected shortest path")
		}
	}
}

func newAttackPathTraversalBenchmarkGraph(levels, fanout int) (*Graph, *Node, *Node) {
	g := New()
	internet := &Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"}
	target := &Node{ID: "target", Kind: NodeKindDatabase, Name: "Target", Risk: RiskCritical}
	g.AddNode(internet)
	g.AddNode(target)

	currentLevel := []string{internet.ID}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("n-%d-%d-%d", level, parentIdx, childIdx)
				g.AddNode(&Node{ID: nodeID, Kind: NodeKindInstance, Name: nodeID, Risk: RiskMedium})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, nodeID),
					Source: parentID,
					Target: nodeID,
					Kind:   EdgeKindCanWrite,
					Effect: EdgeEffectAllow,
				})
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	lastNodeID := currentLevel[len(currentLevel)-1]
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->%s", lastNodeID, target.ID),
		Source: lastNodeID,
		Target: target.ID,
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	return g, internet, target
}
