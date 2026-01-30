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

// ErrorHandler is a callback function invoked when a task returns an error.
// It receives the error and can be used for real-time error handling/logging.
type ErrorHandler func(err error)

// Pool manages a set of concurrent workers with error aggregation.
type Pool struct {
	workers      int
	logger       *slog.Logger
	wg           sync.WaitGroup
	mu           sync.Mutex
	errors       []error
	results      []interface{}
	ctx          context.Context
	cancel       context.CancelFunc
	started      bool
	startTime    time.Time
	endTime      time.Time
	sem          chan struct{} // semaphore to limit concurrent workers
	errorHandler ErrorHandler  // optional callback for real-time error handling
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
		sem:     make(chan struct{}, workers),
	}
}

// Start initializes the pool with a context.
func (p *Pool) Start(ctx context.Context) {
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.started = true
	p.startTime = time.Now()
}

// OnError sets a callback that will be invoked for each error as it occurs.
// This allows real-time error handling without waiting for Wait() to complete.
// The handler is called synchronously after updating the pool state.
func (p *Pool) OnError(handler ErrorHandler) {
	p.mu.Lock()
	p.errorHandler = handler
	p.mu.Unlock()
}

// Submit submits a task to be executed by the pool.
// The task function receives the pool's context.
// Blocks if all workers are busy until a slot becomes available.
func (p *Pool) Submit(task func(ctx context.Context) (interface{}, error)) {
	if !p.started {
		p.mu.Lock()
		p.errors = append(p.errors, fmt.Errorf("pool not started"))
		p.mu.Unlock()
		return
	}

	// Acquire semaphore slot (blocks if at capacity)
	select {
	case p.sem <- struct{}{}:
	case <-p.ctx.Done():
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.sem }() // release semaphore slot

		select {
		case <-p.ctx.Done():
			return
		default:
		}

		result, err := task(p.ctx)

		var handler ErrorHandler
		p.mu.Lock()
		if err != nil {
			p.errors = append(p.errors, err)
			if p.logger != nil {
				p.logger.Warn("worker task failed", "error", err)
			}
			handler = p.errorHandler
		} else if result != nil {
			p.results = append(p.results, result)
		}
		p.mu.Unlock()

		if err != nil && handler != nil {
			handler(err)
		}
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

// ErrorCount returns the current number of errors without copying the slice.
func (p *Pool) ErrorCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.errors)
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
