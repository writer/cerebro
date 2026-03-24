package graph

import (
	"fmt"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestTraversalWorkQueueStealsFromAnotherWorker(t *testing.T) {
	queue := newTraversalWorkQueue(2, 8)
	if !queue.push(0, 10) || !queue.push(0, 11) {
		t.Fatal("expected worker queue seed to succeed")
	}

	if got, ok := queue.next(1); !ok || got != 10 {
		t.Fatalf("queue.next(1) = (%d, %t), want 10,true", got, ok)
	}
	if got, ok := queue.next(0); !ok || got != 11 {
		t.Fatalf("queue.next(0) = (%d, %t), want 11,true", got, ok)
	}
}

func TestParallelProcessOrderedMatchesSequential(t *testing.T) {
	items := make([]int, 256)
	for index := range items {
		items[index] = index
	}

	previous := parallelTraversalWorkerOverride
	parallelTraversalWorkerOverride = 8
	defer func() {
		parallelTraversalWorkerOverride = previous
	}()

	parallel := parallelProcessOrdered(items, func(item int) []int {
		return []int{item, item * item}
	})
	sequential := sequentialProcessOrdered(items, func(item int) []int {
		return []int{item, item * item}
	})

	if !reflect.DeepEqual(sequential, parallel) {
		t.Fatalf("parallel results = %v, want %v", parallel, sequential)
	}
}

func TestParallelMapOrderedUntilStopsAtEarliestMatchingIndex(t *testing.T) {
	items := make([]int, 256)
	for index := range items {
		items[index] = index
	}

	previous := parallelTraversalWorkerOverride
	parallelTraversalWorkerOverride = 8
	defer func() {
		parallelTraversalWorkerOverride = previous
	}()

	results := parallelMapOrderedUntil(items, func(item int) int {
		return item
	}, func(result int) bool {
		return result == 23
	})

	want := make([]int, 24)
	for index := range want {
		want[index] = index
	}
	if !reflect.DeepEqual(want, results) {
		t.Fatalf("parallelMapOrderedUntil() = %v, want %v", results, want)
	}
}

func TestParallelTraverserMatchesSequentialOutgoingBFSOnCycle(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:root", Kind: NodeKindUser})
	g.AddNode(&Node{ID: "role:a", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "role:b", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "role:c", Kind: NodeKindRole})
	g.AddNode(&Node{ID: "bucket:target", Kind: NodeKindBucket})

	g.AddEdge(&Edge{ID: "root-a", Source: "user:root", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "root-b", Source: "user:root", Target: "role:b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "a-c", Source: "role:a", Target: "role:c", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "c-a", Source: "role:c", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "c-target", Source: "role:c", Target: "bucket:target", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "b-a", Source: "role:b", Target: "role:a", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})

	traverser := ParallelTraverser{
		Workers:    4,
		MaxDepth:   4,
		Direction:  ParallelTraversalDirectionOutgoing,
		TrackPaths: true,
	}
	result := traverser.Traverse(g, "user:root")
	if result.StoppedEarly {
		t.Fatal("expected full traversal without early stop")
	}

	gotDepths := make(map[string]int, len(result.Visits))
	var targetPath []string
	for _, visit := range result.Visits {
		if existingDepth, exists := gotDepths[visit.NodeID]; exists {
			t.Fatalf("node %s visited more than once at depths %d and %d", visit.NodeID, existingDepth, visit.Depth)
		}
		gotDepths[visit.NodeID] = visit.Depth
		if visit.NodeID == "bucket:target" {
			targetPath = append([]string(nil), visit.Path...)
		}
	}

	wantDepths := sequentialTraversalDepths(g, "user:root", 4, ParallelTraversalDirectionOutgoing)
	if !reflect.DeepEqual(wantDepths, gotDepths) {
		t.Fatalf("parallel traversal depths = %v, want %v", gotDepths, wantDepths)
	}

	wantPath := []string{"user:root", "role:a", "role:c", "bucket:target"}
	if !reflect.DeepEqual(wantPath, targetPath) {
		t.Fatalf("target path = %v, want %v", targetPath, wantPath)
	}
}

func TestParallelTraverserStopsAfterMatchingVisit(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "user:root", Kind: NodeKindUser})

	for index := 0; index < 256; index++ {
		midID := fmt.Sprintf("role:mid-%03d", index)
		leafID := fmt.Sprintf("bucket:leaf-%03d", index)
		if index == 63 {
			leafID = "bucket:target"
		}
		g.AddNode(&Node{ID: midID, Kind: NodeKindRole})
		g.AddNode(&Node{ID: leafID, Kind: NodeKindBucket})
		g.AddEdge(&Edge{ID: fmt.Sprintf("root-%03d", index), Source: "user:root", Target: midID, Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
		g.AddEdge(&Edge{ID: fmt.Sprintf("mid-leaf-%03d", index), Source: midID, Target: leafID, Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	}

	var levelTwoExpansions atomic.Int64
	traverser := ParallelTraverser{
		Workers:   4,
		MaxDepth:  2,
		Direction: ParallelTraversalDirectionOutgoing,
		Filter: func(_ *Edge, _ *Node, next *Node, _ NodeOrdinal, _ NodeOrdinal, depth int) bool {
			if depth == 2 {
				if next != nil && next.ID != "bucket:target" {
					time.Sleep(2 * time.Millisecond)
				}
				levelTwoExpansions.Add(1)
			}
			return true
		},
		Stop: func(visit ParallelTraversalVisit) bool {
			return visit.NodeID == "bucket:target"
		},
	}

	result := traverser.Traverse(g, "user:root")
	if !result.StoppedEarly {
		t.Fatal("expected traversal to stop after target visit")
	}

	foundTarget := false
	for _, visit := range result.Visits {
		if visit.NodeID == "bucket:target" {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		t.Fatal("expected traversal to include target visit before stopping")
	}

	if got := levelTwoExpansions.Load(); got <= 0 || got >= 128 {
		t.Fatalf("expected bounded level-two work after early stop, got %d expansions", got)
	}
}

func TestParallelTraverserDoesNotLeakGoroutines(t *testing.T) {
	g, rootID, maxDepth := newParallelTraversalBenchmarkGraph(4_096)
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		workers = 2
	}
	traverser := ParallelTraverser{
		Workers:   workers,
		MaxDepth:  maxDepth,
		Direction: ParallelTraversalDirectionOutgoing,
	}

	baseline := stableGoroutineCount()
	for i := 0; i < 25; i++ {
		result := traverser.Traverse(g, rootID)
		if got := len(result.Visits); got != 4_096 {
			t.Fatalf("expected 4096 visits, got %d", got)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		after := stableGoroutineCount()
		if after == baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count mismatch after traversal: before=%d after=%d", baseline, after)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stableGoroutineCount() int {
	runtime.GC()
	runtime.Gosched()
	time.Sleep(10 * time.Millisecond)
	return runtime.NumGoroutine()
}

func sequentialTraversalDepths(g *Graph, rootID string, maxDepth int, direction ParallelTraversalDirection) map[string]int {
	totals := make(map[string]int)
	if g == nil {
		return totals
	}
	snapshot := g.csrEdgeSnapshot()
	if snapshot == nil {
		return totals
	}
	rootOrdinal, ok := snapshot.lookupOrdinal(rootID)
	if !ok {
		return totals
	}

	visited := newOrdinalVisitSet(snapshot.nodeIDs)
	visited.markOrdinal(rootOrdinal)
	totals[rootID] = 0

	type item struct {
		ordinal NodeOrdinal
		nodeID  string
		depth   int
	}
	frontier := []item{{ordinal: rootOrdinal, nodeID: rootID, depth: 0}}
	for len(frontier) > 0 {
		current := frontier[0]
		frontier = frontier[1:]
		if current.depth >= maxDepth {
			continue
		}

		visitNeighbor := func(nextOrdinal NodeOrdinal, nextID string, edge *Edge) {
			if edge == nil || edge.IsDeny() || visited.hasOrdinal(nextOrdinal) {
				return
			}
			visited.markOrdinal(nextOrdinal)
			totals[nextID] = current.depth + 1
			frontier = append(frontier, item{ordinal: nextOrdinal, nodeID: nextID, depth: current.depth + 1})
		}

		if direction == ParallelTraversalDirectionOutgoing || direction == ParallelTraversalDirectionBoth {
			snapshot.forEachOutEdgeOrdinal(current.ordinal, func(edge *Edge, nextOrdinal NodeOrdinal, nextID string) bool {
				visitNeighbor(nextOrdinal, nextID, edge)
				return true
			})
		}
		if direction == ParallelTraversalDirectionIncoming || direction == ParallelTraversalDirectionBoth {
			snapshot.forEachInEdgeOrdinal(current.ordinal, func(edge *Edge, nextOrdinal NodeOrdinal, nextID string) bool {
				visitNeighbor(nextOrdinal, nextID, edge)
				return true
			})
		}
	}

	return totals
}
