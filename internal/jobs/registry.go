package jobs

import (
	"context"
	"fmt"
	"sync"
)

// JobHandler processes a job and returns the result.
type JobHandler func(ctx context.Context, payload string) (string, error)

// JobRegistry manages job type handlers.
type JobRegistry struct {
	mu       sync.RWMutex
	handlers map[JobType]JobHandler
}

// NewJobRegistry creates a new job registry.
func NewJobRegistry() *JobRegistry {
	return &JobRegistry{
		handlers: make(map[JobType]JobHandler),
	}
}

// Register registers a handler for a job type.
func (r *JobRegistry) Register(jobType JobType, handler JobHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[jobType] = handler
}

// Get returns the handler for a job type.
func (r *JobRegistry) Get(jobType JobType) (JobHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[jobType]
	return h, ok
}

// Execute executes a job using the registered handler.
func (r *JobRegistry) Execute(ctx context.Context, job *Job) (string, error) {
	handler, ok := r.Get(job.Type)
	if !ok {
		return "", fmt.Errorf("no handler registered for job type: %s", job.Type)
	}
	return handler(ctx, job.Payload)
}

// RegisteredTypes returns all registered job types.
func (r *JobRegistry) RegisteredTypes() []JobType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]JobType, 0, len(r.handlers))
	for t := range r.handlers {
		types = append(types, t)
	}
	return types
}
