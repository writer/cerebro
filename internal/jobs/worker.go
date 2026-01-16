package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/writerinternal/cerebro/internal/agents"
	"github.com/writerinternal/cerebro/internal/worker"
)

type Worker struct {
	queue             Queue
	store             Store
	tools             *agents.SecurityTools
	concurrency       int
	visibilityTimeout time.Duration
	pollWait          time.Duration
	logger            *slog.Logger
	workerID          string
}

type WorkerOptions struct {
	Concurrency       int
	VisibilityTimeout time.Duration
	PollWait          time.Duration
	WorkerID          string
	Logger            *slog.Logger
}

func NewWorker(queue Queue, store Store, tools *agents.SecurityTools, opts WorkerOptions) *Worker {
	workerID := opts.WorkerID
	if workerID == "" {
		workerID = uuid.NewString()
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	visibilityTimeout := opts.VisibilityTimeout
	if visibilityTimeout <= 0 {
		visibilityTimeout = 30 * time.Second
	}
	pollWait := opts.PollWait
	if pollWait <= 0 {
		pollWait = 10 * time.Second
	}

	return &Worker{
		queue:             queue,
		store:             store,
		tools:             tools,
		concurrency:       concurrency,
		visibilityTimeout: visibilityTimeout,
		pollWait:          pollWait,
		logger:            opts.Logger,
		workerID:          workerID,
	}
}

func (w *Worker) Start(ctx context.Context) error {
	sem := worker.NewSemaphore(w.concurrency)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		messages, err := w.queue.Receive(ctx, w.concurrency, w.pollWait, w.visibilityTimeout)
		if err != nil {
			w.logError("receive failed", err)
			continue
		}
		if len(messages) == 0 {
			continue
		}

		for _, msg := range messages {
			if err := sem.Acquire(ctx); err != nil {
				return err
			}
			go func(m QueueMessage) {
				defer sem.Release()
				w.handleMessage(ctx, m)
			}(msg)
		}
	}
}

func (w *Worker) handleMessage(ctx context.Context, msg QueueMessage) {
	var jobMsg JobMessage
	if err := json.Unmarshal([]byte(msg.Body), &jobMsg); err != nil {
		w.logError("invalid job message", err)
		_ = w.queue.Delete(ctx, msg.ReceiptHandle)
		return
	}

	job, claimed, err := w.store.ClaimJob(ctx, jobMsg.JobID, w.workerID, w.visibilityTimeout)
	if err != nil {
		w.logError("failed to claim job", err)
		return
	}
	if !claimed {
		_ = w.queue.Delete(ctx, msg.ReceiptHandle)
		return
	}

	if job.MaxAttempts <= 0 {
		job.MaxAttempts = 3
	}

	result, err := w.executeJob(ctx, job)
	if err != nil {
		w.handleFailure(ctx, job, msg, err)
		return
	}

	if err := w.store.CompleteJob(ctx, job.ID, result); err != nil {
		w.logError("failed to update job", err)
		return
	}
	if err := w.queue.Delete(ctx, msg.ReceiptHandle); err != nil {
		w.logError("failed to delete message", err)
	}
}

func (w *Worker) executeJob(ctx context.Context, job *Job) (string, error) {
	switch job.Type {
	case JobTypeInspectResource:
		return w.inspectResource(ctx, job.Payload)
	default:
		return "", fmt.Errorf("unsupported job type: %s", job.Type)
	}
}

func (w *Worker) inspectResource(ctx context.Context, payload string) (string, error) {
	var data InspectResourcePayload
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return "", err
	}

	params := agents.InspectCloudResourceParams{
		Resource:   data.Resource.Resource,
		Provider:   data.Resource.Provider,
		Service:    data.Resource.Service,
		Identifier: data.Resource.Identifier,
		Region:     data.Overrides.AWSRegion,
		Project:    data.Overrides.GCPProject,
		Zone:       data.Overrides.GCPZone,
		Cluster:    data.Overrides.Cluster,
	}
	if params.Resource == "" {
		params.Resource = data.Resource.Identifier
	}

	return w.tools.InspectCloudResource(ctx, params)
}

func (w *Worker) handleFailure(ctx context.Context, job *Job, msg QueueMessage, err error) {
	message := err.Error()
	if job.Attempt >= job.MaxAttempts {
		if err := w.store.FailJob(ctx, job.ID, message); err != nil {
			w.logError("failed to mark job failed", err)
			return
		}
		if err := w.queue.Delete(ctx, msg.ReceiptHandle); err != nil {
			w.logError("failed to delete message", err)
		}
		return
	}

	if err := w.store.RetryJob(ctx, job.ID, message); err != nil {
		w.logError("failed to mark job retry", err)
	}
}

func (w *Worker) logError(msg string, err error) {
	if w.logger != nil {
		w.logger.Error(msg, "error", err)
	}
}
