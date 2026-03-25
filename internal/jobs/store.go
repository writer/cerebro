package jobs

import (
	"context"
	"errors"
	"time"
)

// Store defines the persistence interface for job state management.
type Store interface {
	CreateJob(ctx context.Context, job *Job) error
	GetJob(ctx context.Context, jobID string) (*Job, error)
	ClaimJob(ctx context.Context, jobID, workerID string, lease time.Duration) (*Job, bool, error)
	ExtendLease(ctx context.Context, jobID, workerID string, lease time.Duration) error
	CompleteJob(ctx context.Context, jobID, result string) error
	FailJob(ctx context.Context, jobID, message string) error
	RetryJob(ctx context.Context, jobID, message string) error
	CompleteJobOwned(ctx context.Context, jobID, workerID string, attempt int, result string) error
	FailJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error
	RetryJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error
}

var (
	ErrJobLeaseLost = errors.New("job lease lost")
	ErrJobNotFound  = errors.New("job not found")
)
