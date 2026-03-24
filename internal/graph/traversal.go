package graph

import (
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	minParallelTraversalItems   = 64
	maxParallelTraversalWorkers = 8
)

var parallelTraversalWorkerOverride int

func traversalWorkerCount(itemCount int) int {
	if itemCount <= 0 {
		return 0
	}
	if parallelTraversalWorkerOverride > 0 {
		if parallelTraversalWorkerOverride > itemCount {
			return itemCount
		}
		return parallelTraversalWorkerOverride
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 2 || itemCount < minParallelTraversalItems {
		return 1
	}
	if workers > maxParallelTraversalWorkers {
		workers = maxParallelTraversalWorkers
	}
	if workers > itemCount {
		return itemCount
	}
	return workers
}

func parallelProcessOrdered[T any, R any](items []T, process func(T) []R) []R {
	if len(items) == 0 {
		return nil
	}

	results := parallelMapOrdered(items, process)

	total := 0
	for _, local := range results {
		total += len(local)
	}

	ordered := make([]R, 0, total)
	for _, local := range results {
		ordered = append(ordered, local...)
	}
	return ordered
}

func parallelMapOrdered[T any, R any](items []T, process func(T) R) []R {
	return parallelMapOrderedUntil(items, process, nil)
}

func parallelMapOrderedUntil[T any, R any](items []T, process func(T) R, stop func(R) bool) []R {
	if len(items) == 0 {
		return nil
	}

	workers := traversalWorkerCount(len(items))
	if workers <= 1 {
		return sequentialMapOrderedUntil(items, process, stop)
	}

	queue := newTraversalWorkQueue(workers, len(items))
	queue.seedContiguous(len(items))
	results := make([]R, len(items))
	var (
		wg    sync.WaitGroup
		limit atomic.Int64
	)
	limit.Store(int64(len(items)))

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				index, ok := queue.next(worker)
				if !ok {
					return
				}
				if int64(index) >= limit.Load() {
					continue
				}
				result := process(items[index])
				results[index] = result
				if stop == nil || !stop(result) {
					continue
				}
				nextLimit := int64(index + 1)
				for {
					currentLimit := limit.Load()
					if nextLimit >= currentLimit || limit.CompareAndSwap(currentLimit, nextLimit) {
						break
					}
				}
			}
		}(worker)
	}

	wg.Wait()
	return results[:int(limit.Load())]
}

func sequentialMapOrderedUntil[T any, R any](items []T, process func(T) R, stop func(R) bool) []R {
	results := make([]R, 0, len(items))
	for _, item := range items {
		result := process(item)
		results = append(results, result)
		if stop != nil && stop(result) {
			break
		}
	}
	return results
}

func sequentialProcessOrdered[T any, R any](items []T, process func(T) []R) []R {
	ordered := make([]R, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, process(item)...)
	}
	return ordered
}

type ParallelTraversalDirection int

const (
	ParallelTraversalDirectionOutgoing ParallelTraversalDirection = iota
	ParallelTraversalDirectionIncoming
	ParallelTraversalDirectionBoth
)

type ParallelTraversalFilter func(edge *Edge, current *Node, next *Node, currentOrdinal, nextOrdinal NodeOrdinal, depth int) bool

type ParallelTraversalVisit struct {
	Node          *Node
	NodeID        string
	Ordinal       NodeOrdinal
	Depth         int
	ParentID      string
	ParentOrdinal NodeOrdinal
	Edge          *Edge
	Path          []string
}

type ParallelTraversalResult struct {
	Visits       []ParallelTraversalVisit
	StoppedEarly bool
	WorkersUsed  int
	WorkSteals   int64
}

type ParallelTraverser struct {
	Workers    int
	MaxDepth   int
	Direction  ParallelTraversalDirection
	TrackPaths bool
	Filter     ParallelTraversalFilter
	Stop       func(ParallelTraversalVisit) bool
}

type parallelTraversalFrontierItem struct {
	nodeID  string
	ordinal NodeOrdinal
	depth   int
	path    []string
}

type parallelTraversalExpansion struct {
	visit   ParallelTraversalVisit
	next    parallelTraversalFrontierItem
	hasNext bool
	stop    bool
}

type concurrentOrdinalBitmap struct {
	words []atomic.Uint64
}

func newConcurrentOrdinalBitmap(nodeIDs *NodeIDIndex) *concurrentOrdinalBitmap {
	wordCount := 0
	if nodeIDs != nil {
		wordCount = (nodeIDs.Len() + 63) / 64
	}
	return &concurrentOrdinalBitmap{
		words: make([]atomic.Uint64, wordCount),
	}
}

func (b *concurrentOrdinalBitmap) mark(ordinal NodeOrdinal) bool {
	if b == nil {
		return false
	}
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok || word < 0 || word >= len(b.words) {
		return false
	}
	for {
		current := b.words[word].Load()
		if current&mask != 0 {
			return false
		}
		if b.words[word].CompareAndSwap(current, current|mask) {
			return true
		}
	}
}

func (t ParallelTraverser) Traverse(g *Graph, rootIDs ...string) ParallelTraversalResult {
	if g == nil || len(rootIDs) == 0 {
		return ParallelTraversalResult{}
	}

	return t.traverseSnapshot(g, g.csrEdgeSnapshot(), rootIDs...)
}

func (t ParallelTraverser) traverseSnapshot(g *Graph, snapshot *csrEdgeSnapshot, rootIDs ...string) ParallelTraversalResult {
	result := ParallelTraversalResult{}
	if g == nil || len(rootIDs) == 0 || snapshot == nil || snapshot.nodeIDs == nil {
		return result
	}

	visited := newConcurrentOrdinalBitmap(snapshot.nodeIDs)
	frontier := make([]parallelTraversalFrontierItem, 0, len(rootIDs))
	maxDepth := t.maxDepth()

	for _, rootID := range rootIDs {
		rootOrdinal, ok := snapshot.lookupOrdinal(rootID)
		if !ok || !visited.mark(rootOrdinal) {
			continue
		}
		root, ok := g.GetNode(rootID)
		if !ok {
			continue
		}

		visit := ParallelTraversalVisit{
			Node:    root,
			NodeID:  rootID,
			Ordinal: rootOrdinal,
			Depth:   0,
		}
		if t.TrackPaths {
			visit.Path = []string{rootID}
		}
		result.Visits = append(result.Visits, visit)

		frontier = append(frontier, parallelTraversalFrontierItem{
			nodeID:  rootID,
			ordinal: rootOrdinal,
			depth:   0,
			path:    visit.Path,
		})

		if t.Stop != nil && t.Stop(visit) {
			result.StoppedEarly = true
			return result
		}
	}

	for len(frontier) > 0 && frontier[0].depth < maxDepth {
		expansions, workersUsed, workSteals := t.expandFrontier(g, snapshot, frontier, visited, maxDepth)
		if workersUsed > result.WorkersUsed {
			result.WorkersUsed = workersUsed
		}
		result.WorkSteals += workSteals

		nextFrontier := make([]parallelTraversalFrontierItem, 0, len(expansions))
		for _, local := range expansions {
			for _, expansion := range local {
				result.Visits = append(result.Visits, expansion.visit)
				if expansion.hasNext {
					nextFrontier = append(nextFrontier, expansion.next)
				}
				if expansion.stop {
					result.StoppedEarly = true
					return result
				}
			}
		}
		frontier = nextFrontier
	}

	return result
}

func (t ParallelTraverser) maxDepth() int {
	if t.MaxDepth < 0 {
		return 0
	}
	return t.MaxDepth
}

func (t ParallelTraverser) workerCount(itemCount int) int {
	if itemCount <= 0 {
		return 0
	}
	if t.Workers > 0 {
		if t.Workers > itemCount {
			return itemCount
		}
		return t.Workers
	}
	return traversalWorkerCount(itemCount)
}

func (t ParallelTraverser) expandFrontier(g *Graph, snapshot *csrEdgeSnapshot, frontier []parallelTraversalFrontierItem, visited *concurrentOrdinalBitmap, maxDepth int) ([][]parallelTraversalExpansion, int, int64) {
	workers := t.workerCount(len(frontier))
	if workers <= 1 {
		return t.expandFrontierSequential(g, snapshot, frontier, visited, maxDepth), 1, 0
	}

	results := make([][]parallelTraversalExpansion, len(frontier))
	queue := newTraversalWorkQueue(workers, len(frontier))
	queue.seedContiguous(len(frontier))

	var (
		wg       sync.WaitGroup
		stopFlag atomic.Bool
		steals   atomic.Int64
	)

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				if stopFlag.Load() {
					return
				}
				index, ok, stolen := queue.nextWithSteal(worker)
				if !ok {
					return
				}
				if stolen {
					steals.Add(1)
				}
				if stopFlag.Load() {
					return
				}

				expansions := t.expandFrontierItem(g, snapshot, frontier[index], visited, maxDepth)
				results[index] = expansions
				if parallelTraversalExpansionsStop(expansions) {
					stopFlag.Store(true)
					return
				}
			}
		}(worker)
	}

	wg.Wait()
	return results, workers, steals.Load()
}

func (t ParallelTraverser) expandFrontierSequential(g *Graph, snapshot *csrEdgeSnapshot, frontier []parallelTraversalFrontierItem, visited *concurrentOrdinalBitmap, maxDepth int) [][]parallelTraversalExpansion {
	results := make([][]parallelTraversalExpansion, len(frontier))
	for index, item := range frontier {
		results[index] = t.expandFrontierItem(g, snapshot, item, visited, maxDepth)
		if parallelTraversalExpansionsStop(results[index]) {
			break
		}
	}
	return results
}

func (t ParallelTraverser) expandFrontierItem(g *Graph, snapshot *csrEdgeSnapshot, item parallelTraversalFrontierItem, visited *concurrentOrdinalBitmap, maxDepth int) []parallelTraversalExpansion {
	if g == nil || snapshot == nil || item.ordinal == InvalidNodeOrdinal || item.depth >= maxDepth {
		return nil
	}

	current, _ := g.GetNode(item.nodeID)
	nextDepth := item.depth + 1
	expansions := make([]parallelTraversalExpansion, 0)

	visitNeighbor := func(edge *Edge, nextOrdinal NodeOrdinal, nextID string) bool {
		if edge == nil || edge.IsDeny() {
			return true
		}

		nextNode, ok := g.GetNode(nextID)
		if !ok {
			return true
		}
		if t.Filter != nil && !t.Filter(edge, current, nextNode, item.ordinal, nextOrdinal, nextDepth) {
			return true
		}
		if !visited.mark(nextOrdinal) {
			return true
		}

		visit := ParallelTraversalVisit{
			Node:          nextNode,
			NodeID:        nextID,
			Ordinal:       nextOrdinal,
			Depth:         nextDepth,
			ParentID:      item.nodeID,
			ParentOrdinal: item.ordinal,
			Edge:          edge,
		}
		if t.TrackPaths {
			visit.Path = make([]string, len(item.path)+1)
			copy(visit.Path, item.path)
			visit.Path[len(item.path)] = nextID
		}

		expansion := parallelTraversalExpansion{
			visit: visit,
			next: parallelTraversalFrontierItem{
				nodeID:  nextID,
				ordinal: nextOrdinal,
				depth:   nextDepth,
				path:    visit.Path,
			},
			hasNext: nextDepth < maxDepth,
		}
		if t.Stop != nil && t.Stop(visit) {
			expansion.stop = true
			expansions = append(expansions, expansion)
			return false
		}

		expansions = append(expansions, expansion)
		return true
	}

	if t.Direction == ParallelTraversalDirectionOutgoing || t.Direction == ParallelTraversalDirectionBoth {
		snapshot.forEachOutEdgeOrdinal(item.ordinal, func(edge *Edge, nextOrdinal NodeOrdinal, nextID string) bool {
			return visitNeighbor(edge, nextOrdinal, nextID)
		})
	}
	if t.Direction == ParallelTraversalDirectionIncoming || t.Direction == ParallelTraversalDirectionBoth {
		snapshot.forEachInEdgeOrdinal(item.ordinal, func(edge *Edge, nextOrdinal NodeOrdinal, nextID string) bool {
			return visitNeighbor(edge, nextOrdinal, nextID)
		})
	}

	return expansions
}

func parallelTraversalExpansionsStop(expansions []parallelTraversalExpansion) bool {
	for _, expansion := range expansions {
		if expansion.stop {
			return true
		}
	}
	return false
}
