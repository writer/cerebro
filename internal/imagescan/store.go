package imagescan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/writer/cerebro/internal/executionstore"
)

const executionNamespace = "image_scan"

type RunStore interface {
	SaveRun(ctx context.Context, run *RunRecord) error
	LoadRun(ctx context.Context, runID string) (*RunRecord, error)
	ListRuns(ctx context.Context, opts RunListOptions) ([]RunRecord, error)
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
	payload, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("encode image scan run: %w", err)
	}
	return s.store.UpsertRun(ctx, executionstore.RunEnvelope{
		Namespace:   executionNamespace,
		RunID:       run.ID,
		Kind:        string(run.Registry),
		Status:      string(run.Status),
		Stage:       string(run.Stage),
		SubmittedAt: run.SubmittedAt,
		StartedAt:   run.StartedAt,
		CompletedAt: run.CompletedAt,
		UpdatedAt:   run.UpdatedAt,
		Payload:     payload,
	})
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
		return nil, fmt.Errorf("decode image scan run: %w", err)
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
			return nil, fmt.Errorf("decode image scan run payload: %w", err)
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (s *SQLiteRunStore) AppendEvent(ctx context.Context, runID string, event RunEvent) (RunEvent, error) {
	if s == nil || s.store == nil {
		return event, nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("encode image scan event: %w", err)
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
			return nil, fmt.Errorf("decode image scan event payload: %w", err)
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
