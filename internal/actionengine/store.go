package actionengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/executionstore"
)

const DefaultNamespace = "action_engine"

type Store interface {
	SaveExecution(ctx context.Context, execution *Execution) error
	LoadExecution(ctx context.Context, executionID string) (*Execution, error)
	ListExecutions(ctx context.Context, limit int) ([]Execution, error)
	AppendEvent(ctx context.Context, event Event) (Event, error)
	LoadEvents(ctx context.Context, executionID string) ([]Event, error)
}

type SQLiteStore struct {
	store     *executionstore.SQLiteStore
	namespace string
}

func NewSQLiteStore(path, namespace string) (*SQLiteStore, error) {
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = DefaultNamespace
	}
	return &SQLiteStore{store: store, namespace: namespace}, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

func (s *SQLiteStore) SaveExecution(ctx context.Context, execution *Execution) error {
	if s == nil || s.store == nil || execution == nil {
		return nil
	}
	payload, err := json.Marshal(execution)
	if err != nil {
		return fmt.Errorf("marshal action execution: %w", err)
	}
	env := executionstore.RunEnvelope{
		Namespace:   s.namespace,
		RunID:       strings.TrimSpace(execution.ID),
		Kind:        "action_execution",
		Status:      string(execution.Status),
		Stage:       executionStage(execution),
		SubmittedAt: execution.StartedAt.UTC(),
		StartedAt:   timePointer(execution.StartedAt),
		CompletedAt: execution.CompletedAt,
		UpdatedAt:   executionUpdatedAt(execution),
		Payload:     payload,
	}
	return s.store.UpsertRun(ctx, env)
}

func (s *SQLiteStore) LoadExecution(ctx context.Context, executionID string) (*Execution, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	env, err := s.store.LoadRun(ctx, s.namespace, strings.TrimSpace(executionID))
	if err != nil || env == nil {
		return nil, err
	}
	var execution Execution
	if err := json.Unmarshal(env.Payload, &execution); err != nil {
		return nil, fmt.Errorf("unmarshal action execution: %w", err)
	}
	return &execution, nil
}

func (s *SQLiteStore) ListExecutions(ctx context.Context, limit int) ([]Execution, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	runs, err := s.store.ListRuns(ctx, s.namespace, executionstore.RunListOptions{
		Limit:              limit,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		return nil, err
	}
	executions := make([]Execution, 0, len(runs))
	for _, run := range runs {
		var execution Execution
		if err := json.Unmarshal(run.Payload, &execution); err != nil {
			return nil, fmt.Errorf("unmarshal action execution list item: %w", err)
		}
		executions = append(executions, execution)
	}
	return executions, nil
}

func (s *SQLiteStore) AppendEvent(ctx context.Context, event Event) (Event, error) {
	if s == nil || s.store == nil {
		return event, nil
	}
	if event.RecordedAt.IsZero() {
		event.RecordedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("marshal action event: %w", err)
	}
	env, err := s.store.SaveEvent(ctx, executionstore.EventEnvelope{
		Namespace:  s.namespace,
		RunID:      strings.TrimSpace(event.ExecutionID),
		RecordedAt: event.RecordedAt.UTC(),
		Payload:    payload,
	})
	if err != nil {
		return event, err
	}
	event.Sequence = env.Sequence
	return event, nil
}

func (s *SQLiteStore) LoadEvents(ctx context.Context, executionID string) ([]Event, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	envs, err := s.store.LoadEvents(ctx, s.namespace, strings.TrimSpace(executionID))
	if err != nil {
		return nil, err
	}
	events := make([]Event, 0, len(envs))
	for _, env := range envs {
		var event Event
		if err := json.Unmarshal(env.Payload, &event); err != nil {
			return nil, fmt.Errorf("unmarshal action event: %w", err)
		}
		event.Sequence = env.Sequence
		events = append(events, event)
	}
	return events, nil
}

func executionStage(execution *Execution) string {
	switch execution.Status {
	case StatusAwaitingApproval:
		return "approval"
	case StatusRunning:
		return "running"
	case StatusCompleted, StatusFailed, StatusCanceled:
		return "completed"
	default:
		return "created"
	}
}

func executionUpdatedAt(execution *Execution) time.Time {
	if execution == nil {
		return time.Now().UTC()
	}
	if execution.CompletedAt != nil && !execution.CompletedAt.IsZero() {
		return execution.CompletedAt.UTC()
	}
	if execution.ApprovedAt != nil && !execution.ApprovedAt.IsZero() {
		return execution.ApprovedAt.UTC()
	}
	if execution.StartedAt.IsZero() {
		return time.Now().UTC()
	}
	return execution.StartedAt.UTC()
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}
