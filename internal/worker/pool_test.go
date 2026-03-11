package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_BasicExecution(t *testing.T) {
	pool := NewPool(4, nil)
	pool.Start(context.Background())

	var counter int64
	for i := 0; i < 10; i++ {
		pool.Submit(func(ctx context.Context) (interface{}, error) {
			atomic.AddInt64(&counter, 1)
			return nil, nil
		})
	}

	errs := pool.Wait()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %d", len(errs))
	}
	if counter != 10 {
		t.Errorf("expected counter to be 10, got %d", counter)
	}
}

func TestPool_ErrorAggregation(t *testing.T) {
	pool := NewPool(2, nil)
	pool.Start(context.Background())

	pool.Submit(func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("error 1")
	})
	pool.Submit(func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("error 2")
	})
	pool.Submit(func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})

	errs := pool.Wait()
	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errs))
	}

	results := pool.Results()
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestPool_ContextCancellation(t *testing.T) {
	pool := NewPool(2, nil)
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	var started int64
	var completed int64

	for i := 0; i < 100; i++ {
		pool.Submit(func(ctx context.Context) (interface{}, error) {
			atomic.AddInt64(&started, 1)
			select {
			case <-time.After(100 * time.Millisecond):
				atomic.AddInt64(&completed, 1)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return nil, nil
		})
	}

	// Cancel after short delay
	time.AfterFunc(50*time.Millisecond, cancel)

	pool.Wait()

	// Not all tasks should complete
	if completed >= 100 {
		t.Error("expected some tasks to be canceled")
	}
}

func TestPool_NotStarted(t *testing.T) {
	pool := NewPool(2, nil)

	// Submit without starting
	pool.Submit(func(ctx context.Context) (interface{}, error) {
		return nil, nil
	})

	errs := pool.Wait()
	if len(errs) != 1 {
		t.Errorf("expected 1 error for not started pool, got %d", len(errs))
	}
}

func TestPool_Duration(t *testing.T) {
	pool := NewPool(1, nil)
	pool.Start(context.Background())

	pool.Submit(func(ctx context.Context) (interface{}, error) {
		time.Sleep(50 * time.Millisecond)
		return nil, nil
	})

	pool.Wait()

	if pool.Duration() < 50*time.Millisecond {
		t.Error("expected duration to be at least 50ms")
	}
}

func TestSemaphore_Acquire(t *testing.T) {
	sem := NewSemaphore(2)

	// Should be able to acquire twice
	if err := sem.Acquire(context.Background()); err != nil {
		t.Errorf("first acquire failed: %v", err)
	}
	if err := sem.Acquire(context.Background()); err != nil {
		t.Errorf("second acquire failed: %v", err)
	}

	// Third should block, use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := sem.Acquire(ctx)
	if err == nil {
		t.Error("expected acquire to fail due to timeout")
	}
}

func TestSemaphore_TryAcquire(t *testing.T) {
	sem := NewSemaphore(1)

	if !sem.TryAcquire() {
		t.Error("first TryAcquire should succeed")
	}

	if sem.TryAcquire() {
		t.Error("second TryAcquire should fail")
	}

	sem.Release()

	if !sem.TryAcquire() {
		t.Error("TryAcquire after Release should succeed")
	}
}

func TestSemaphore_Release(t *testing.T) {
	sem := NewSemaphore(1)
	if err := sem.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	sem.Release()

	// Should be able to acquire again
	if !sem.TryAcquire() {
		t.Error("should be able to acquire after release")
	}

	// Release when empty should not panic
	sem.Release()
	sem.Release()
}
