package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

const runtimeIngestNamespace = executionstore.NamespaceRuntimeIngest

type IngestRunStatus string

const (
	IngestRunStatusQueued    IngestRunStatus = "queued"
	IngestRunStatusRunning   IngestRunStatus = "running"
	IngestRunStatusCompleted IngestRunStatus = "completed"
	IngestRunStatusFailed    IngestRunStatus = "failed"
)

type IngestRunRecord struct {
	ID               string            `json:"id"`
	Source           string            `json:"source"`
	Status           IngestRunStatus   `json:"status"`
	Stage            string            `json:"stage"`
	SubmittedAt      time.Time         `json:"submitted_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at"`
	ObservationCount int               `json:"observation_count,omitempty"`
	FindingCount     int               `json:"finding_count,omitempty"`
	Error            string            `json:"error,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	LastCheckpoint   *IngestCheckpoint `json:"last_checkpoint,omitempty"`
}

type IngestCheckpoint struct {
	Cursor     string            `json:"cursor"`
	RecordedAt time.Time         `json:"recorded_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type IngestEvent struct {
	Type       string         `json:"type"`
	Sequence   int64          `json:"sequence"`
	RecordedAt time.Time      `json:"recorded_at"`
	Data       map[string]any `json:"data,omitempty"`
}

type IngestRunListOptions struct {
	Statuses           []IngestRunStatus
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
	ActiveOnly         bool
}

type IngestStore interface {
	Close() error
	SaveRun(context.Context, *IngestRunRecord) error
	LoadRun(context.Context, string) (*IngestRunRecord, error)
	ListRuns(context.Context, IngestRunListOptions) ([]IngestRunRecord, error)
	AppendEvent(context.Context, string, IngestEvent) (IngestEvent, error)
	LoadEvents(context.Context, string) ([]IngestEvent, error)
	SaveCheckpoint(context.Context, string, IngestCheckpoint) (IngestCheckpoint, error)
	LoadCheckpoint(context.Context, string) (*IngestCheckpoint, error)
}

type SQLiteIngestStore struct {
	store     executionstore.Store
	ownsStore bool
}

func NewSQLiteIngestStore(path string) (*SQLiteIngestStore, error) {
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	ingestStore := NewSQLiteIngestStoreWithExecutionStore(store)
	ingestStore.ownsStore = true
	return ingestStore, nil
}

func NewSQLiteIngestStoreWithExecutionStore(store executionstore.Store) *SQLiteIngestStore {
	return &SQLiteIngestStore{store: store}
}

func (s *SQLiteIngestStore) Close() error {
	if s == nil || s.store == nil || !s.ownsStore {
		return nil
	}
	return s.store.Close()
}

func (s *SQLiteIngestStore) SaveRun(ctx context.Context, run *IngestRunRecord) error {
	if s == nil || s.store == nil || run == nil {
		return nil
	}
	env, err := runtimeIngestRunEnvelope(run)
	if err != nil {
		return err
	}
	return s.store.UpsertRun(ctx, env)
}

func (s *SQLiteIngestStore) LoadRun(ctx context.Context, runID string) (*IngestRunRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	env, err := s.store.LoadRun(ctx, runtimeIngestNamespace, strings.TrimSpace(runID))
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, nil
	}
	return runtimeIngestRunFromEnvelope(env)
}

func (s *SQLiteIngestStore) ListRuns(ctx context.Context, opts IngestRunListOptions) ([]IngestRunRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	query := executionstore.RunListOptions{
		Statuses:           ingestStatusesToStrings(opts.Statuses),
		Limit:              opts.Limit,
		Offset:             opts.Offset,
		OrderBySubmittedAt: opts.OrderBySubmittedAt,
	}
	if opts.ActiveOnly {
		query.ExcludeStatuses = []string{string(IngestRunStatusCompleted), string(IngestRunStatusFailed)}
	}
	envs, err := s.store.ListRuns(ctx, runtimeIngestNamespace, query)
	if err != nil {
		return nil, err
	}
	runs := make([]IngestRunRecord, 0, len(envs))
	for _, env := range envs {
		run, err := runtimeIngestRunFromEnvelope(&env)
		if err != nil {
			return nil, err
		}
		runs = append(runs, *run)
	}
	return runs, nil
}

func (s *SQLiteIngestStore) AppendEvent(ctx context.Context, runID string, event IngestEvent) (IngestEvent, error) {
	if s == nil || s.store == nil {
		return event, nil
	}
	if event.RecordedAt.IsZero() {
		event.RecordedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("encode runtime ingest event: %w", err)
	}
	env, err := s.store.SaveEvent(ctx, executionstore.EventEnvelope{
		Namespace:  runtimeIngestNamespace,
		RunID:      strings.TrimSpace(runID),
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

func (s *SQLiteIngestStore) LoadEvents(ctx context.Context, runID string) ([]IngestEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	envs, err := s.store.LoadEvents(ctx, runtimeIngestNamespace, strings.TrimSpace(runID))
	if err != nil {
		return nil, err
	}
	events := make([]IngestEvent, 0, len(envs))
	for _, env := range envs {
		var event IngestEvent
		if err := json.Unmarshal(env.Payload, &event); err != nil {
			return nil, fmt.Errorf("decode runtime ingest event payload: %w", err)
		}
		event.Sequence = env.Sequence
		event.RecordedAt = env.RecordedAt
		events = append(events, event)
	}
	return events, nil
}

func (s *SQLiteIngestStore) SaveCheckpoint(ctx context.Context, runID string, checkpoint IngestCheckpoint) (IngestCheckpoint, error) {
	if s == nil || s.store == nil {
		return checkpoint, nil
	}
	if checkpoint.RecordedAt.IsZero() {
		checkpoint.RecordedAt = time.Now().UTC()
	}
	runID = strings.TrimSpace(runID)
	const maxCheckpointAttempts = 8
	for attempt := 0; attempt < maxCheckpointAttempts; attempt++ {
		currentEnv, err := s.store.LoadRun(ctx, runtimeIngestNamespace, runID)
		if err != nil {
			return checkpoint, err
		}
		if currentEnv == nil {
			return checkpoint, fmt.Errorf("runtime ingest run not found")
		}
		run, err := runtimeIngestRunFromEnvelope(currentEnv)
		if err != nil {
			return checkpoint, err
		}
		run.LastCheckpoint = &IngestCheckpoint{
			Cursor:     checkpoint.Cursor,
			RecordedAt: checkpoint.RecordedAt,
			Metadata:   cloneRuntimeStringMap(checkpoint.Metadata),
		}
		run.UpdatedAt = checkpoint.RecordedAt
		nextEnv, err := runtimeIngestRunEnvelope(run)
		if err != nil {
			return checkpoint, err
		}
		swapped, err := s.store.CompareAndSwapRun(ctx, *currentEnv, nextEnv)
		if err != nil {
			return checkpoint, err
		}
		if swapped {
			_, err = s.AppendEvent(ctx, runID, IngestEvent{
				Type:       "checkpoint_saved",
				RecordedAt: checkpoint.RecordedAt,
				Data: map[string]any{
					"cursor":   checkpoint.Cursor,
					"metadata": cloneRuntimeStringMap(checkpoint.Metadata),
				},
			})
			if err != nil {
				return checkpoint, err
			}
			return checkpoint, nil
		}
	}
	return checkpoint, fmt.Errorf("save runtime ingest checkpoint: concurrent update conflict")
}

func runtimeIngestRunEnvelope(run *IngestRunRecord) (executionstore.RunEnvelope, error) {
	payload, err := json.Marshal(run)
	if err != nil {
		return executionstore.RunEnvelope{}, fmt.Errorf("encode runtime ingest run: %w", err)
	}
	return executionstore.RunEnvelope{
		Namespace:   runtimeIngestNamespace,
		RunID:       strings.TrimSpace(run.ID),
		Kind:        strings.TrimSpace(run.Source),
		Status:      string(run.Status),
		Stage:       strings.TrimSpace(run.Stage),
		SubmittedAt: run.SubmittedAt,
		StartedAt:   run.StartedAt,
		CompletedAt: run.CompletedAt,
		UpdatedAt:   run.UpdatedAt,
		Payload:     payload,
	}, nil
}

func runtimeIngestRunFromEnvelope(env *executionstore.RunEnvelope) (*IngestRunRecord, error) {
	if env == nil {
		return nil, nil
	}
	var run IngestRunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return nil, fmt.Errorf("decode runtime ingest run: %w", err)
	}
	return &run, nil
}

func (s *SQLiteIngestStore) LoadCheckpoint(ctx context.Context, runID string) (*IngestCheckpoint, error) {
	run, err := s.LoadRun(ctx, runID)
	if err != nil || run == nil {
		return nil, err
	}
	return run.LastCheckpoint, nil
}

func ingestStatusesToStrings(statuses []IngestRunStatus) []string {
	if len(statuses) == 0 {
		return nil
	}
	values := make([]string, 0, len(statuses))
	for _, status := range statuses {
		values = append(values, string(status))
	}
	return values
}
