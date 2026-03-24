package graph

import (
	"fmt"
	"runtime"
	"testing"
)

func BenchmarkShortestPathBetweenSets(b *testing.B) {
	adjacency := make(map[string]map[string]struct{})
	link := func(source, target string) {
		if adjacency[source] == nil {
			adjacency[source] = make(map[string]struct{})
		}
		adjacency[source][target] = struct{}{}
	}

	const levels = 6
	const fanout = 4
	currentLevel := []string{"source"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parent := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				child := fmt.Sprintf("n-%d-%d-%d", level, parentIdx, childIdx)
				link(parent, child)
				nextLevel = append(nextLevel, child)
			}
		}
		currentLevel = nextLevel
	}
	for _, leaf := range currentLevel {
		link(leaf, "target")
	}

	sources := map[string]struct{}{"source": {}}
	targets := map[string]struct{}{"target": {}}

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
				path := shortestPathBetweenSets(adjacency, sources, targets)
				if len(path) == 0 {
					b.Fatal("expected path")
				}
			}
		})
	}
}
