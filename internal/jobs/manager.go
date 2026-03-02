package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	queue  Queue
	store  Store
	logger *slog.Logger
}

type EnqueueOptions struct {
	GroupID      string
	MaxAttempts  int
	Overrides    InspectOverrides
	RepoURL      string
	Truncated    bool
	FilesScanned int
}

func NewManager(queue Queue, store Store, logger *slog.Logger) *Manager {
	return &Manager{
		queue:  queue,
		store:  store,
		logger: logger,
	}
}

func (m *Manager) EnqueueInspectResources(ctx context.Context, resources []ResourceRef, opts EnqueueOptions) (*JobBatch, error) {
	if len(resources) == 0 {
		return nil, fmt.Errorf("no resources to enqueue")
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 3
	}

	groupID := opts.GroupID
	if groupID == "" {
		groupID = uuid.NewString()
	}

	jobIDs := make([]string, 0, len(resources))
	queuedAt := time.Now().UTC()

	for _, res := range resources {
		payload, err := json.Marshal(InspectResourcePayload{
			Resource:  res,
			Overrides: opts.Overrides,
		})
		if err != nil {
			return nil, err
		}

		job := &Job{
			ID:          uuid.NewString(),
			Type:        JobTypeInspectResource,
			Status:      StatusQueued,
			Payload:     string(payload),
			Attempt:     0,
			MaxAttempts: opts.MaxAttempts,
			GroupID:     groupID,
			CreatedAt:   queuedAt.Unix(),
			UpdatedAt:   queuedAt.Unix(),
		}

		if err := m.store.CreateJob(ctx, job); err != nil {
			return nil, err
		}

		if err := m.queue.Enqueue(ctx, JobMessage{JobID: job.ID, GroupID: groupID}); err != nil {
			return nil, err
		}

		jobIDs = append(jobIDs, job.ID)
	}

	if m.logger != nil {
		m.logger.Info("jobs enqueued", "count", len(jobIDs), "group_id", groupID)
	}

	return &JobBatch{
		GroupID:      groupID,
		JobIDs:       jobIDs,
		QueuedAt:     queuedAt,
		TotalJobs:    len(jobIDs),
		MaxAttempts:  opts.MaxAttempts,
		RepoURL:      opts.RepoURL,
		FilesScanned: opts.FilesScanned,
		Truncated:    opts.Truncated,
	}, nil
}

func (m *Manager) WaitForJobs(ctx context.Context, jobIDs []string, pollInterval time.Duration) ([]*Job, error) {
	if len(jobIDs) == 0 {
		return nil, fmt.Errorf("no jobs to wait for")
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	results := make(map[string]*Job, len(jobIDs))
	remaining := make(map[string]struct{}, len(jobIDs))
	for _, id := range jobIDs {
		remaining[id] = struct{}{}
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		for id := range remaining {
			job, err := m.store.GetJob(ctx, id)
			if err != nil {
				return nil, err
			}
			results[id] = job
			if job.Status.Terminal() {
				delete(remaining, id)
			}
		}

		if len(remaining) == 0 {
			break
		}

		select {
		case <-ctx.Done():
			return mapToSlice(results, jobIDs), ctx.Err()
		case <-ticker.C:
		}
	}

	return mapToSlice(results, jobIDs), nil
}

func mapToSlice(results map[string]*Job, order []string) []*Job {
	jobs := make([]*Job, 0, len(order))
	for _, id := range order {
		if job, ok := results[id]; ok {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func (m *Manager) EnqueueNativeSync(ctx context.Context, payload NativeSyncPayload, opts EnqueueOptions) (*Job, error) {
	payload.Provider = strings.ToLower(strings.TrimSpace(payload.Provider))
	if payload.Provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 3
	}

	groupID := strings.TrimSpace(opts.GroupID)
	if groupID == "" {
		groupID = strings.TrimSpace(payload.ScheduleName)
	}
	if groupID == "" {
		groupID = uuid.NewString()
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	job := &Job{
		ID:          uuid.NewString(),
		Type:        JobTypeNativeSync,
		Status:      StatusQueued,
		Payload:     string(payloadBytes),
		Attempt:     0,
		MaxAttempts: opts.MaxAttempts,
		GroupID:     groupID,
		CreatedAt:   now.Unix(),
		UpdatedAt:   now.Unix(),
	}

	if err := m.store.CreateJob(ctx, job); err != nil {
		return nil, err
	}

	if err := m.queue.Enqueue(ctx, JobMessage{JobID: job.ID, GroupID: groupID}); err != nil {
		return nil, err
	}

	if m.logger != nil {
		m.logger.Info("native sync job enqueued", "job_id", job.ID, "provider", payload.Provider, "group_id", groupID)
	}

	return job, nil
}
