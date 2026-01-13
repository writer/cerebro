// Package worker provides utilities for managing concurrent work with proper
// error handling and context cancellation.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Pool manages a set of concurrent workers with error aggregation.
type Pool struct {
	workers   int
	logger    *slog.Logger
	wg        sync.WaitGroup
	mu        sync.Mutex
	errors    []error
	results   []interface{}
	ctx       context.Context
	cancel    context.CancelFunc
	started   bool
	startTime time.Time
	endTime   time.Time
}

// NewPool creates a new worker pool.
func NewPool(workers int, logger *slog.Logger) *Pool {
	if workers <= 0 {
		workers = 1
	}
	return &Pool{
		workers: workers,
		logger:  logger,
		errors:  make([]error, 0),
		results: make([]interface{}, 0),
	}
}

// Start initializes the pool with a context.
func (p *Pool) Start(ctx context.Context) {
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.started = true
	p.startTime = time.Now()
}

// Submit submits a task to be executed by the pool.
// The task function receives the pool's context.
func (p *Pool) Submit(task func(ctx context.Context) (interface{}, error)) {
	if !p.started {
		p.mu.Lock()
		p.errors = append(p.errors, fmt.Errorf("pool not started"))
		p.mu.Unlock()
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		select {
		case <-p.ctx.Done():
			return
		default:
		}

		result, err := task(p.ctx)

		p.mu.Lock()
		if err != nil {
			p.errors = append(p.errors, err)
			if p.logger != nil {
				p.logger.Warn("worker task failed", "error", err)
			}
		} else if result != nil {
			p.results = append(p.results, result)
		}
		p.mu.Unlock()
	}()
}

// Wait blocks until all tasks complete and returns aggregated errors.
func (p *Pool) Wait() []error {
	p.wg.Wait()
	p.endTime = time.Now()
	if p.cancel != nil {
		p.cancel()
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	return p.errors
}

// Results returns collected results after Wait.
func (p *Pool) Results() []interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.results
}

// Cancel cancels all pending work.
func (p *Pool) Cancel() {
	if p.cancel != nil {
		p.cancel()
	}
}

// Duration returns the total duration of the pool's execution.
func (p *Pool) Duration() time.Duration {
	if p.endTime.IsZero() {
		return time.Since(p.startTime)
	}
	return p.endTime.Sub(p.startTime)
}

// Semaphore provides a simple counting semaphore for limiting concurrency.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore creates a semaphore with the given capacity.
func NewSemaphore(n int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, n)}
}

// Acquire blocks until a slot is available or context is canceled.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release releases a slot.
func (s *Semaphore) Release() {
	select {
	case <-s.ch:
	default:
	}
}

// TryAcquire attempts to acquire without blocking.
func (s *Semaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}
