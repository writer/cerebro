package pipeline

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestStreamSliceMarksBackpressureWhenBufferFills(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	signal := &BackpressureSignal{}
	out := StreamSlice(ctx, []int{1, 2, 3}, 1, signal)
	time.Sleep(10 * time.Millisecond)
	if !signal.Active() {
		cancel()
		t.Fatal("expected intake stream to report backpressure when bounded buffer fills")
	}
	cancel()
	<-out
}

func TestStreamSliceDrainsItemsAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := StreamSlice(ctx, []int{1, 2, 3}, 1, nil)

	var got []int
	for value := range out {
		got = append(got, value)
	}

	if !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("stream output = %v, want [1 2 3]", got)
	}
}

func TestStagePreservesPerKeyOrdering(t *testing.T) {
	type item struct {
		Key string
		Seq int
	}

	input := make(chan item, 6)
	for _, candidate := range []item{
		{Key: "a", Seq: 1},
		{Key: "b", Seq: 1},
		{Key: "a", Seq: 2},
		{Key: "a", Seq: 3},
		{Key: "b", Seq: 2},
	} {
		input <- candidate
	}
	close(input)

	stage := StartStage(context.Background(), input, StageConfig[item, item]{
		Workers: 2,
		Buffer:  1,
		Key: func(value item) string {
			return value.Key
		},
		Transform: func(_ context.Context, value item) (item, bool) {
			if value.Key == "a" && value.Seq == 1 {
				time.Sleep(10 * time.Millisecond)
			}
			return value, true
		},
	})

	var mu sync.Mutex
	got := make(map[string][]int)
	for value := range stage.Output() {
		mu.Lock()
		got[value.Key] = append(got[value.Key], value.Seq)
		mu.Unlock()
	}
	stage.Wait()

	if !reflect.DeepEqual(got["a"], []int{1, 2, 3}) {
		t.Fatalf("key a order = %v, want [1 2 3]", got["a"])
	}
	if !reflect.DeepEqual(got["b"], []int{1, 2}) {
		t.Fatalf("key b order = %v, want [1 2]", got["b"])
	}
}

func TestStageDrainsInFlightWorkAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	input := make(chan int, 3)
	input <- 1
	input <- 2
	input <- 3
	close(input)

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	stage := StartStage(ctx, input, StageConfig[int, int]{
		Workers: 1,
		Buffer:  1,
		Transform: func(_ context.Context, value int) (int, bool) {
			if value == 1 {
				close(firstStarted)
				<-releaseFirst
			}
			return value, true
		},
	})

	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first item transform to start")
	}

	cancel()
	close(releaseFirst)

	var got []int
	for value := range stage.Output() {
		got = append(got, value)
	}
	stage.Wait()

	if !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("stage output = %v, want [1 2 3]", got)
	}
}

func TestBatchSinkFlushesOnBatchSizeAndClose(t *testing.T) {
	in := make(chan int, 5)
	for _, value := range []int{1, 2, 3, 4, 5} {
		in <- value
	}
	close(in)

	var (
		mu      sync.Mutex
		batches [][]int
	)
	sink := StartBatchSink(context.Background(), in, BatchConfig[int]{
		BatchSize: 2,
		Flush: func(_ context.Context, batch []int) {
			mu.Lock()
			batches = append(batches, append([]int(nil), batch...))
			mu.Unlock()
		},
	})
	sink.Wait()

	want := [][]int{{1, 2}, {3, 4}, {5}}
	if !reflect.DeepEqual(batches, want) {
		t.Fatalf("batches = %#v, want %#v", batches, want)
	}
}

func TestBatchSinkDoesNotReuseFlushedBatchBackingArray(t *testing.T) {
	in := make(chan int, 4)
	for _, value := range []int{1, 2, 3, 4} {
		in <- value
	}
	close(in)

	var batches [][]int
	sink := StartBatchSink(context.Background(), in, BatchConfig[int]{
		BatchSize: 2,
		Flush: func(_ context.Context, batch []int) {
			batches = append(batches, batch)
		},
	})
	sink.Wait()

	want := [][]int{{1, 2}, {3, 4}}
	if !reflect.DeepEqual(batches, want) {
		t.Fatalf("batches = %#v, want %#v", batches, want)
	}
}

func TestBatchSinkDrainsInputAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	in := make(chan int, 2)
	in <- 1
	in <- 2
	close(in)

	var batches [][]int
	sink := StartBatchSink(ctx, in, BatchConfig[int]{
		BatchSize: 1,
		Flush: func(_ context.Context, batch []int) {
			batches = append(batches, append([]int(nil), batch...))
		},
	})
	sink.Wait()

	want := [][]int{{1}, {2}}
	if !reflect.DeepEqual(batches, want) {
		t.Fatalf("batches = %#v, want %#v", batches, want)
	}
}

func TestBatchSinkFlushUsesUncancelledContextAfterCancellation(t *testing.T) {
	type contextKey string

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey("key"), "value"))
	cancel()

	in := make(chan int, 1)
	in <- 1
	close(in)

	var flushCtx context.Context
	sink := StartBatchSink(ctx, in, BatchConfig[int]{
		BatchSize: 1,
		Flush: func(ctx context.Context, batch []int) {
			flushCtx = ctx
		},
	})
	sink.Wait()

	if flushCtx == nil {
		t.Fatal("expected flush context to be captured")
	}
	if err := flushCtx.Err(); err != nil {
		t.Fatalf("flush context err = %v, want nil", err)
	}
	if got := flushCtx.Value(contextKey("key")); got != "value" {
		t.Fatalf("flush context value = %v, want value", got)
	}
}
