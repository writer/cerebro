package graph

import (
	"fmt"
	"runtime"
	"testing"
)

func BenchmarkParallelTraverser_1K(b *testing.B) {
	benchmarkParallelTraverser(b, 1_000)
}

func BenchmarkParallelTraverser_10K(b *testing.B) {
	benchmarkParallelTraverser(b, 10_000)
}

func BenchmarkParallelTraverser_100K(b *testing.B) {
	benchmarkParallelTraverser(b, 100_000)
}

func benchmarkParallelTraverser(b *testing.B, nodeCount int) {
	g, rootID, maxDepth := newParallelTraversalBenchmarkGraph(nodeCount)
	workerCounts := []int{1, runtime.GOMAXPROCS(0)}
	seen := make(map[int]struct{}, len(workerCounts))

	for _, workers := range workerCounts {
		if workers < 1 {
			workers = 1
		}
		if _, ok := seen[workers]; ok {
			continue
		}
		seen[workers] = struct{}{}

		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			traverser := ParallelTraverser{
				Workers:   workers,
				MaxDepth:  maxDepth,
				Direction: ParallelTraversalDirectionOutgoing,
			}
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				result := traverser.Traverse(g, rootID)
				if got := len(result.Visits); got != nodeCount {
					b.Fatalf("expected %d visits, got %d", nodeCount, got)
				}
			}
		})
	}
}

func newParallelTraversalBenchmarkGraph(nodeCount int) (*Graph, string, int) {
	g := New()
	if nodeCount <= 0 {
		return g, "", 0
	}

	const fanout = 4
	rootID := "node:000000"
	g.AddNode(&Node{ID: rootID, Kind: NodeKindRole})

	frontier := []string{rootID}
	nextID := 1
	maxDepth := 0

	for len(frontier) > 0 && nextID < nodeCount {
		nextFrontier := make([]string, 0, len(frontier)*fanout)
		for _, parentID := range frontier {
			for edgeIndex := 0; edgeIndex < fanout && nextID < nodeCount; edgeIndex++ {
				childID := fmt.Sprintf("node:%06d", nextID)
				g.AddNode(&Node{ID: childID, Kind: NodeKindRole})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("edge:%s:%s", parentID, childID),
					Source: parentID,
					Target: childID,
					Kind:   EdgeKindDependsOn,
					Effect: EdgeEffectAllow,
				})
				nextFrontier = append(nextFrontier, childID)
				nextID++
			}
		}
		frontier = nextFrontier
		maxDepth++
	}

	return g, rootID, maxDepth
}
