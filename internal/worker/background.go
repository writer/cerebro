package worker

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// TaskResult represents the outcome of a background task.
type TaskResult struct {
	Name      string
	StartedAt time.Time
	EndedAt   time.Time
	Error     error
}

// BackgroundRunner manages background tasks with error tracking and metrics.
type BackgroundRunner struct {
	logger  *slog.Logger
	tasks   []TaskResult
	mu      sync.Mutex
	running int32
}

// NewBackgroundRunner creates a new background runner.
func NewBackgroundRunner(logger *slog.Logger) *BackgroundRunner {
	return &BackgroundRunner{
		logger: logger,
		tasks:  make([]TaskResult, 0),
	}
}

// Run executes a task in the background with error tracking.
func (r *BackgroundRunner) Run(name string, task func(ctx context.Context) error) {
	r.mu.Lock()
	r.running++
	r.mu.Unlock()

	go func() {
		result := TaskResult{
			Name:      name,
			StartedAt: time.Now(),
		}

		defer func() {
			if recovered := recover(); recovered != nil {
				result.Error = fmt.Errorf("panic: %v", recovered)
				if r.logger != nil {
					r.logger.Error("background task panicked",
						"task", name,
						"panic", fmt.Sprintf("%v", recovered),
						"stack", string(debug.Stack()))
				}
			}

			result.EndedAt = time.Now()
			r.mu.Lock()
			r.running--
			r.tasks = append(r.tasks, result)
			r.mu.Unlock()

			if result.Error != nil {
				if r.logger != nil {
					r.logger.Warn("background task failed",
						"task", name,
						"error", result.Error,
						"duration_ms", result.EndedAt.Sub(result.StartedAt).Milliseconds())
				}
			} else {
				if r.logger != nil {
					r.logger.Debug("background task completed",
						"task", name,
						"duration_ms", result.EndedAt.Sub(result.StartedAt).Milliseconds())
				}
			}
		}()

		result.Error = task(context.Background())
	}()
}

// RunWithContext executes a task with a specific context.
func (r *BackgroundRunner) RunWithContext(ctx context.Context, name string, task func(ctx context.Context) error) {
	r.mu.Lock()
	r.running++
	r.mu.Unlock()

	go func() {
		result := TaskResult{
			Name:      name,
			StartedAt: time.Now(),
		}

		defer func() {
			if recovered := recover(); recovered != nil {
				result.Error = fmt.Errorf("panic: %v", recovered)
				if r.logger != nil {
					r.logger.Error("background task panicked",
						"task", name,
						"panic", fmt.Sprintf("%v", recovered),
						"stack", string(debug.Stack()))
				}
			}

			result.EndedAt = time.Now()
			r.mu.Lock()
			r.running--
			r.tasks = append(r.tasks, result)
			r.mu.Unlock()

			if result.Error != nil && r.logger != nil {
				r.logger.Warn("background task failed",
					"task", name,
					"error", result.Error,
					"duration_ms", result.EndedAt.Sub(result.StartedAt).Milliseconds())
			}
		}()

		result.Error = task(ctx)
	}()
}

// Running returns the number of currently running tasks.
func (r *BackgroundRunner) Running() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int(r.running)
}

// Results returns all completed task results.
func (r *BackgroundRunner) Results() []TaskResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	results := make([]TaskResult, len(r.tasks))
	copy(results, r.tasks)
	return results
}

// Errors returns all failed task results.
func (r *BackgroundRunner) Errors() []TaskResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	errors := make([]TaskResult, 0)
	for _, t := range r.tasks {
		if t.Error != nil {
			errors = append(errors, t)
		}
	}
	return errors
}

// Clear clears all recorded task results.
func (r *BackgroundRunner) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tasks = make([]TaskResult, 0)
}
