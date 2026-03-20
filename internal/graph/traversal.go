package graph

import (
	"runtime"
	"sync"
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

	workers := traversalWorkerCount(len(items))
	if workers <= 1 {
		return sequentialProcessOrdered(items, process)
	}

	queue := newTraversalWorkQueue(workers, len(items))
	queue.seedContiguous(len(items))
	results := make([][]R, len(items))
	var wg sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				index, ok := queue.next(worker)
				if !ok {
					return
				}
				results[index] = process(items[index])
			}
		}(worker)
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
