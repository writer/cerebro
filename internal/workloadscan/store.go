package workloadscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

const executionNamespace = "workload_scan"
const distributedDedupNamespace = executionNamespace + "_distributed_dedup"

type RunStore interface {
	SaveRun(ctx context.Context, run *RunRecord) error
	LoadRun(ctx context.Context, runID string) (*RunRecord, error)
	ListRuns(ctx context.Context, opts RunListOptions) ([]RunRecord, error)
	CompareAndSwapRun(ctx context.Context, current, next *RunRecord) (bool, error)
	ClaimDistributedDedup(ctx context.Context, dedupKey, runID string, ttl time.Duration) (bool, error)
	ReleaseDistributedDedup(ctx context.Context, dedupKey string) error
	AppendEvent(ctx context.Context, runID string, event RunEvent) (RunEvent, error)
	LoadEvents(ctx context.Context, runID string) ([]RunEvent, error)
	Close() error
}

type SQLiteRunStore struct {
	store     executionstore.Store
	ownsStore bool
}

func NewSQLiteRunStore(path string) (*SQLiteRunStore, error) {
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	runStore := NewSQLiteRunStoreWithExecutionStore(store)
	runStore.ownsStore = true
	return runStore, nil
}

func NewSQLiteRunStoreWithExecutionStore(store executionstore.Store) *SQLiteRunStore {
	return &SQLiteRunStore{store: store}
}

func (s *SQLiteRunStore) SaveRun(ctx context.Context, run *RunRecord) error {
	if s == nil || s.store == nil || run == nil {
		return nil
	}
	env, err := marshalRunEnvelope(run)
	if err != nil {
		return err
	}
	return s.store.UpsertRun(ctx, env)
}

func (s *SQLiteRunStore) LoadRun(ctx context.Context, runID string) (*RunRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	env, err := s.store.LoadRun(ctx, executionNamespace, runID)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, nil
	}
	var run RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return nil, fmt.Errorf("decode workload scan run: %w", err)
	}
	return &run, nil
}

func (s *SQLiteRunStore) ListRuns(ctx context.Context, opts RunListOptions) ([]RunRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	query := executionstore.RunListOptions{
		Statuses:           runStatusesToStrings(opts.Statuses),
		Limit:              opts.Limit,
		Offset:             opts.Offset,
		OrderBySubmittedAt: opts.OrderBySubmittedAt,
	}
	if opts.ActiveOnly {
		query.ExcludeStatuses = []string{string(RunStatusSucceeded), string(RunStatusFailed)}
	}
	envs, err := s.store.ListRuns(ctx, executionNamespace, query)
	if err != nil {
		return nil, err
	}
	runs := make([]RunRecord, 0, len(envs))
	for _, env := range envs {
		var run RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode workload scan run payload: %w", err)
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (s *SQLiteRunStore) CompareAndSwapRun(ctx context.Context, current, next *RunRecord) (bool, error) {
	if s == nil || s.store == nil || current == nil || next == nil {
		return false, nil
	}
	currentEnv, err := marshalRunEnvelope(current)
	if err != nil {
		return false, err
	}
	nextEnv, err := marshalRunEnvelope(next)
	if err != nil {
		return false, err
	}
	return s.store.CompareAndSwapRun(ctx, currentEnv, nextEnv)
}

func (s *SQLiteRunStore) ClaimDistributedDedup(ctx context.Context, dedupKey, runID string, ttl time.Duration) (bool, error) {
	if s == nil || s.store == nil {
		return true, nil
	}
	dedupKey = strings.TrimSpace(dedupKey)
	runID = strings.TrimSpace(runID)
	if dedupKey == "" {
		return false, fmt.Errorf("distributed dedup key is required")
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	now := time.Now().UTC()
	claimed, _, err := s.store.ClaimProcessedEvent(ctx, executionstore.ProcessedEventRecord{
		Namespace:   distributedDedupNamespace,
		EventKey:    dedupKey,
		Status:      executionstore.ProcessedEventStatusProcessing,
		PayloadHash: runID,
		FirstSeenAt: now,
		LastSeenAt:  now,
		ProcessedAt: now,
		ExpiresAt:   now.Add(ttl),
	}, 0)
	return claimed, err
}

func (s *SQLiteRunStore) ReleaseDistributedDedup(ctx context.Context, dedupKey string) error {
	if s == nil || s.store == nil {
		return nil
	}
	dedupKey = strings.TrimSpace(dedupKey)
	if dedupKey == "" {
		return nil
	}
	return s.store.DeleteProcessedEvent(ctx, distributedDedupNamespace, dedupKey)
}

func (s *SQLiteRunStore) AppendEvent(ctx context.Context, runID string, event RunEvent) (RunEvent, error) {
	if s == nil || s.store == nil {
		return event, nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("encode workload scan event: %w", err)
	}
	env, err := s.store.SaveEvent(ctx, executionstore.EventEnvelope{
		Namespace:  executionNamespace,
		RunID:      runID,
		Sequence:   event.Sequence,
		RecordedAt: event.RecordedAt,
		Payload:    payload,
	})
	if err != nil {
		return event, err
	}
	event.Sequence = env.Sequence
	event.RecordedAt = env.RecordedAt
	return event, nil
}

func (s *SQLiteRunStore) LoadEvents(ctx context.Context, runID string) ([]RunEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	envs, err := s.store.LoadEvents(ctx, executionNamespace, runID)
	if err != nil {
		return nil, err
	}
	events := make([]RunEvent, 0, len(envs))
	for _, env := range envs {
		var event RunEvent
		if err := json.Unmarshal(env.Payload, &event); err != nil {
			return nil, fmt.Errorf("decode workload scan event payload: %w", err)
		}
		events = append(events, event)
	}
	return events, nil
}

func (s *SQLiteRunStore) Close() error {
	if s == nil || s.store == nil || !s.ownsStore {
		return nil
	}
	return s.store.Close()
}

func marshalRunEnvelope(run *RunRecord) (executionstore.RunEnvelope, error) {
	payload, err := json.Marshal(run)
	if err != nil {
		return executionstore.RunEnvelope{}, fmt.Errorf("encode workload scan run: %w", err)
	}
	return executionstore.RunEnvelope{
		Namespace:   executionNamespace,
		RunID:       run.ID,
		Kind:        string(run.Provider),
		Status:      string(run.Status),
		Stage:       string(run.Stage),
		SubmittedAt: run.SubmittedAt,
		StartedAt:   run.StartedAt,
		CompletedAt: run.CompletedAt,
		UpdatedAt:   run.UpdatedAt,
		Payload:     payload,
	}, nil
}

func runStatusesToStrings(statuses []RunStatus) []string {
	if len(statuses) == 0 {
		return nil
	}
	values := make([]string, 0, len(statuses))
	for _, status := range statuses {
		values = append(values, string(status))
	}
	return values
}
