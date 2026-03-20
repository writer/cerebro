package graph

import (
	"fmt"
	"runtime"
	"testing"
)

func BenchmarkAttackPathSimulatorFindShortestPath(b *testing.B) {
	g, entry, target := newAttackPathTraversalBenchmarkGraph(6, 4)
	sim := NewAttackPathSimulator(g)
	configs := []struct {
		name    string
		workers int
	}{
		{name: "workers_1", workers: 1},
		{name: "workers_auto", workers: runtime.GOMAXPROCS(0)},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			previous := parallelTraversalWorkerOverride
			parallelTraversalWorkerOverride = config.workers
			defer func() {
				parallelTraversalWorkerOverride = previous
			}()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				path := sim.findShortestPath(entry, target, 8)
				if path == nil {
					b.Fatal("expected shortest path")
				}
			}
		})
	}
}

func BenchmarkAttackPathSimulatorFindChokepoints(b *testing.B) {
	g := New()
	for i := range 6 {
		entryID := fmt.Sprintf("entry-%d", i)
		g.AddNode(&Node{ID: entryID, Kind: NodeKindUser, Name: entryID})
	}
	g.AddNode(&Node{ID: "pivot", Kind: NodeKindRole, Name: "Pivot"})
	for i := range 12 {
		targetID := fmt.Sprintf("target-%d", i)
		g.AddNode(&Node{ID: targetID, Kind: NodeKindDatabase, Name: targetID, Risk: RiskCritical})
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("pivot-%s", targetID),
			Source: "pivot",
			Target: targetID,
			Kind:   EdgeKindCanRead,
			Effect: EdgeEffectAllow,
		})
	}
	for i := range 6 {
		entryID := fmt.Sprintf("entry-%d", i)
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("%s-pivot", entryID),
			Source: entryID,
			Target: "pivot",
			Kind:   EdgeKindCanAssume,
			Effect: EdgeEffectAllow,
		})
	}

	sim := NewAttackPathSimulator(g)
	result := sim.Simulate(6)
	if len(result.Paths) == 0 {
		b.Fatal("expected attack paths")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		chokepoints := sim.findChokepoints(result.Paths)
		if len(chokepoints) == 0 {
			b.Fatal("expected chokepoints")
		}
	}
}

func BenchmarkAttackPathSimulatorKShortestPaths(b *testing.B) {
	g, entry, target := newAttackPathKShortestBenchmarkGraph(72, 8)
	sim := NewAttackPathSimulator(g)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		paths := sim.KShortestPaths(entry.ID, target.ID, 3, 96)
		if len(paths) == 0 {
			b.Fatal("expected k-shortest paths")
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

func newAttackPathKShortestBenchmarkGraph(chainLen, altLen int) (*Graph, *Node, *Node) {
	g := New()
	entry := &Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"}
	target := &Node{ID: "target", Kind: NodeKindDatabase, Name: "Target", Risk: RiskCritical}
	g.AddNode(entry)
	g.AddNode(target)

	prevID := entry.ID
	for i := 0; i < chainLen; i++ {
		nodeID := fmt.Sprintf("chain-%d", i)
		g.AddNode(&Node{ID: nodeID, Kind: NodeKindRole, Name: nodeID})
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("%s->%s", prevID, nodeID),
			Source: prevID,
			Target: nodeID,
			Kind:   EdgeKindCanAssume,
			Effect: EdgeEffectAllow,
		})
		prevID = nodeID
	}
	lastChainID := fmt.Sprintf("chain-%d", chainLen-1)
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->%s", lastChainID, target.ID),
		Source: lastChainID,
		Target: target.ID,
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	spurID := fmt.Sprintf("chain-%d", chainLen-2)
	rejoinID := fmt.Sprintf("chain-%d", chainLen-5)
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->%s", spurID, rejoinID),
		Source: spurID,
		Target: rejoinID,
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	})
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->%s", rejoinID, target.ID),
		Source: rejoinID,
		Target: target.ID,
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	prevID = spurID
	for i := 0; i < altLen; i++ {
		nodeID := fmt.Sprintf("alt-%d", i)
		g.AddNode(&Node{ID: nodeID, Kind: NodeKindRole, Name: nodeID})
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("%s->%s", prevID, nodeID),
			Source: prevID,
			Target: nodeID,
			Kind:   EdgeKindCanAssume,
			Effect: EdgeEffectAllow,
		})
		prevID = nodeID
	}
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->%s", prevID, target.ID),
		Source: prevID,
		Target: target.ID,
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	return g, entry, target
}
