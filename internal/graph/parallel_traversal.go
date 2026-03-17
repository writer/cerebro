package graph

import (
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	minParallelTraversalItems   = 64
	minParallelTraversalChunk   = 8
	maxParallelTraversalWorkers = 4
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

	workers := traversalWorkerCount(len(items))
	if workers <= 1 {
		return sequentialProcessOrdered(items, process)
	}

	chunkSize := len(items) / workers
	if chunkSize < minParallelTraversalChunk {
		chunkSize = minParallelTraversalChunk
	}
	if chunkSize >= len(items) {
		return sequentialProcessOrdered(items, process)
	}

	chunkCount := (len(items) + chunkSize - 1) / chunkSize
	if chunkCount < workers {
		workers = chunkCount
	}

	results := make([][]R, chunkCount)
	var nextChunk atomic.Int64
	var wg sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				chunk := int(nextChunk.Add(1) - 1)
				if chunk >= chunkCount {
					return
				}

				start := chunk * chunkSize
				end := start + chunkSize
				if end > len(items) {
					end = len(items)
				}

				local := make([]R, 0, end-start)
				for _, item := range items[start:end] {
					local = append(local, process(item)...)
				}
				results[chunk] = local
			}
		}()
	}

	wg.Wait()

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

func sequentialProcessOrdered[T any, R any](items []T, process func(T) []R) []R {
	ordered := make([]R, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, process(item)...)
	}
	return ordered
}
