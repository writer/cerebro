package graph

import (
	"reflect"
	"testing"
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
