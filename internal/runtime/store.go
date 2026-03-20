package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

const runtimeIngestNamespace = executionstore.NamespaceRuntimeIngest
const (
	runtimeReplayNamespace         = executionstore.NamespaceRuntimeReplay
	runtimeMaterializeNamespace    = executionstore.NamespaceRuntimeMaterialization
	runtimeProcessedEventNamespace = executionstore.NamespaceProcessedRuntimeEvent
)

const (
	runtimeProcessedEventTTL        = 7 * 24 * time.Hour
	runtimeProcessingClaimTTL       = 5 * time.Minute
	runtimeProcessedEventMaxRecords = 100000
)

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

type IngestJobType string

const (
	IngestJobTypeReplay          IngestJobType = "replay"
	IngestJobTypeMaterialization IngestJobType = "materialization"
)

type IngestJobRecord struct {
	ID               string            `json:"id"`
	Type             IngestJobType     `json:"type"`
	Source           string            `json:"source"`
	Status           IngestRunStatus   `json:"status"`
	Stage            string            `json:"stage"`
	SubmittedAt      time.Time         `json:"submitted_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at"`
	ParentRunID      string            `json:"parent_run_id,omitempty"`
	ObservationCount int               `json:"observation_count,omitempty"`
	PromotedCount    int               `json:"promoted_count,omitempty"`
	Error            string            `json:"error,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type IngestRunListOptions struct {
	Statuses           []IngestRunStatus
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
	ActiveOnly         bool
}

type IngestJobListOptions struct {
	Types              []IngestJobType
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
	SaveJob(context.Context, *IngestJobRecord) error
	LoadJob(context.Context, string) (*IngestJobRecord, error)
	ListJobs(context.Context, IngestJobListOptions) ([]IngestJobRecord, error)
	AppendEvent(context.Context, string, IngestEvent) (IngestEvent, error)
	LoadEvents(context.Context, string) ([]IngestEvent, error)
	SaveCheckpoint(context.Context, string, IngestCheckpoint) (IngestCheckpoint, error)
	LoadCheckpoint(context.Context, string) (*IngestCheckpoint, error)
	ClaimSourceEventProcessing(context.Context, string, string, string, time.Time) (bool, error)
	MarkSourceEventProcessed(context.Context, string, string, string, time.Time) error
}

type SQLiteIngestStore struct {
	store               executionstore.Store
	ownsStore           bool
	processedEventBloom *processedEventBloom
}

func NewSQLiteIngestStore(path string) (*SQLiteIngestStore, error) {
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	ingestStore, err := NewSQLiteIngestStoreWithExecutionStore(store)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	ingestStore.ownsStore = true
	return ingestStore, nil
}

func NewSQLiteIngestStoreWithExecutionStore(store executionstore.Store) (*SQLiteIngestStore, error) {
	return newSQLiteIngestStoreWithExecutionStore(store)
}

func NewSQLiteIngestStoreWithoutBloom(store executionstore.Store) *SQLiteIngestStore {
	return &SQLiteIngestStore{store: store}
}

func newSQLiteIngestStoreWithExecutionStore(store executionstore.Store) (*SQLiteIngestStore, error) {
	ingestStore := &SQLiteIngestStore{
		store:               store,
		processedEventBloom: newProcessedEventBloom(runtimeProcessedEventMaxRecords, runtimeProcessedEventBloomFalsePositiveRate),
	}
	if err := ingestStore.reloadProcessedEventBloom(context.Background()); err != nil {
		return nil, err
	}
	return ingestStore, nil
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

func (s *SQLiteIngestStore) SaveJob(ctx context.Context, job *IngestJobRecord) error {
	if s == nil || s.store == nil || job == nil {
		return nil
	}
	env, err := runtimeIngestJobEnvelope(job)
	if err != nil {
		return err
	}
	return s.store.UpsertRun(ctx, env)
}

func (s *SQLiteIngestStore) LoadJob(ctx context.Context, jobID string) (*IngestJobRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	jobID = strings.TrimSpace(jobID)
	for _, namespace := range []string{runtimeReplayNamespace, runtimeMaterializeNamespace} {
		env, err := s.store.LoadRun(ctx, namespace, jobID)
		if err != nil {
			return nil, err
		}
		if env == nil {
			continue
		}
		return runtimeIngestJobFromEnvelope(env)
	}
	return nil, nil
}

func (s *SQLiteIngestStore) ListJobs(ctx context.Context, opts IngestJobListOptions) ([]IngestJobRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}

	query := executionstore.RunListOptions{
		Limit:              opts.Limit,
		Offset:             opts.Offset,
		Statuses:           ingestStatusesToStrings(opts.Statuses),
		OrderBySubmittedAt: opts.OrderBySubmittedAt,
	}
	if opts.ActiveOnly {
		query.ExcludeStatuses = []string{string(IngestRunStatusCompleted), string(IngestRunStatusFailed)}
	}

	namespaces := runtimeJobNamespaces(opts.Types)
	if len(opts.Types) > 0 && len(namespaces) == 0 {
		return []IngestJobRecord{}, nil
	}
	query.Namespaces = namespaces
	envs, err := s.store.ListAllRuns(ctx, query)
	if err != nil {
		return nil, err
	}
	jobs := make([]IngestJobRecord, 0, len(envs))
	for _, env := range envs {
		job, err := runtimeIngestJobFromEnvelope(&env)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *job)
	}
	return jobs, nil
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

func (s *SQLiteIngestStore) checkDuplicateSourceEvent(ctx context.Context, source, eventID, payloadHash string) (bool, error) {
	if s == nil || s.store == nil {
		return false, nil
	}
	eventKey := runtimeProcessedEventKey(source, eventID)
	if eventKey == "" {
		return false, nil
	}
	lookupAt := time.Now().UTC()
	record, err := s.store.LookupProcessedEvent(ctx, runtimeProcessedEventNamespace, eventKey, lookupAt)
	if err != nil {
		return false, err
	}
	if record == nil {
		return false, nil
	}
	s.rememberProcessedEventBloomKey(eventKey)
	payloadHash = strings.TrimSpace(payloadHash)
	recordHash := strings.TrimSpace(record.PayloadHash)
	if payloadHash != "" && recordHash != "" && recordHash != payloadHash {
		return false, nil
	}
	if strings.TrimSpace(record.Status) != executionstore.ProcessedEventStatusProcessed {
		return true, nil
	}
	if err := s.store.TouchProcessedEvent(ctx, runtimeProcessedEventNamespace, eventKey, lookupAt, runtimeProcessedEventTTL); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteIngestStore) ClaimSourceEventProcessing(ctx context.Context, source, eventID, payloadHash string, observedAt time.Time) (bool, error) {
	if s == nil || s.store == nil {
		return false, nil
	}
	eventKey := runtimeProcessedEventKey(source, eventID)
	if eventKey == "" {
		return false, nil
	}
	claimAt := time.Now().UTC()
	if observedAt.IsZero() {
		observedAt = claimAt
	} else {
		observedAt = observedAt.UTC()
	}
	record := executionstore.ProcessedEventRecord{
		Namespace:      runtimeProcessedEventNamespace,
		EventKey:       eventKey,
		Status:         executionstore.ProcessedEventStatusProcessing,
		PayloadHash:    strings.TrimSpace(payloadHash),
		FirstSeenAt:    observedAt,
		LastSeenAt:     observedAt,
		ProcessedAt:    claimAt,
		ExpiresAt:      claimAt.Add(runtimeProcessingClaimTTL),
		DuplicateCount: 0,
	}
	// Fast-claim is an optimization only; durable claim remains the source of truth.
	if claimed, attempted, err := s.tryFastClaimProcessedEvent(ctx, record); err == nil && attempted && claimed {
		return false, nil
	}
	claimed, existing, err := s.store.ClaimProcessedEvent(ctx, record, runtimeProcessedEventMaxRecords)
	if err != nil {
		return false, err
	}
	if claimed {
		s.rememberProcessedEventBloomKey(eventKey)
		return false, nil
	}
	if existing == nil {
		return false, nil
	}
	s.rememberProcessedEventBloomKey(eventKey)
	recordHash := strings.TrimSpace(existing.PayloadHash)
	payloadHash = strings.TrimSpace(payloadHash)
	if payloadHash != "" && recordHash != "" && recordHash != payloadHash {
		return false, nil
	}
	if strings.TrimSpace(existing.Status) == executionstore.ProcessedEventStatusProcessed {
		if err := s.store.TouchProcessedEvent(ctx, runtimeProcessedEventNamespace, eventKey, claimAt, runtimeProcessedEventTTL); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *SQLiteIngestStore) MarkSourceEventProcessed(ctx context.Context, source, eventID, payloadHash string, observedAt time.Time) error {
	if s == nil || s.store == nil {
		return nil
	}
	eventKey := runtimeProcessedEventKey(source, eventID)
	if eventKey == "" {
		return nil
	}
	processedAt := time.Now().UTC()
	if observedAt.IsZero() {
		observedAt = processedAt
	} else {
		observedAt = observedAt.UTC()
	}
	err := s.store.RememberProcessedEvent(ctx, executionstore.ProcessedEventRecord{
		Namespace:   runtimeProcessedEventNamespace,
		EventKey:    eventKey,
		Status:      executionstore.ProcessedEventStatusProcessed,
		PayloadHash: strings.TrimSpace(payloadHash),
		FirstSeenAt: observedAt,
		LastSeenAt:  observedAt,
		ProcessedAt: processedAt,
		ExpiresAt:   processedAt.Add(runtimeProcessedEventTTL),
	}, runtimeProcessedEventMaxRecords)
	if err != nil {
		return err
	}
	s.rememberProcessedEventBloomKey(eventKey)
	return nil
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

func runtimeIngestJobEnvelope(job *IngestJobRecord) (executionstore.RunEnvelope, error) {
	namespace, err := runtimeJobNamespace(job.Type)
	if err != nil {
		return executionstore.RunEnvelope{}, err
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return executionstore.RunEnvelope{}, fmt.Errorf("encode runtime ingest job: %w", err)
	}
	return executionstore.RunEnvelope{
		Namespace:   namespace,
		RunID:       strings.TrimSpace(job.ID),
		Kind:        strings.TrimSpace(job.Source),
		Status:      string(job.Status),
		Stage:       strings.TrimSpace(job.Stage),
		SubmittedAt: job.SubmittedAt,
		StartedAt:   job.StartedAt,
		CompletedAt: job.CompletedAt,
		UpdatedAt:   job.UpdatedAt,
		Payload:     payload,
	}, nil
}

func runtimeIngestJobFromEnvelope(env *executionstore.RunEnvelope) (*IngestJobRecord, error) {
	if env == nil {
		return nil, nil
	}
	var job IngestJobRecord
	if err := json.Unmarshal(env.Payload, &job); err != nil {
		return nil, fmt.Errorf("decode runtime ingest job: %w", err)
	}
	if job.Type == "" {
		switch env.Namespace {
		case runtimeReplayNamespace:
			job.Type = IngestJobTypeReplay
		case runtimeMaterializeNamespace:
			job.Type = IngestJobTypeMaterialization
		}
	}
	return &job, nil
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

func runtimeJobNamespace(jobType IngestJobType) (string, error) {
	switch jobType {
	case IngestJobTypeReplay:
		return runtimeReplayNamespace, nil
	case IngestJobTypeMaterialization:
		return runtimeMaterializeNamespace, nil
	default:
		return "", fmt.Errorf("unsupported runtime ingest job type: %q", strings.TrimSpace(string(jobType)))
	}
}

func runtimeJobNamespaces(types []IngestJobType) []string {
	if len(types) == 0 {
		return []string{runtimeReplayNamespace, runtimeMaterializeNamespace}
	}
	namespaces := make([]string, 0, len(types))
	for _, jobType := range types {
		namespace, err := runtimeJobNamespace(jobType)
		if err != nil || slices.Contains(namespaces, namespace) {
			continue
		}
		namespaces = append(namespaces, namespace)
	}
	if len(namespaces) == 0 {
		return nil
	}
	return namespaces
}

func runtimeProcessedEventKey(source, eventID string) string {
	source = strings.TrimSpace(source)
	eventID = strings.TrimSpace(eventID)
	if source == "" || eventID == "" {
		return ""
	}
	return source + "|" + eventID
}

func (s *SQLiteIngestStore) tryFastClaimProcessedEvent(ctx context.Context, record executionstore.ProcessedEventRecord) (bool, bool, error) {
	if s == nil || s.store == nil || s.processedEventBloom == nil {
		return false, false, nil
	}
	if s.processedEventBloom.maybeContains(record.EventKey) {
		return false, false, nil
	}
	fastStore, ok := s.store.(processedEventFastClaimStore)
	if !ok {
		return false, false, nil
	}
	claimed, err := fastStore.TryClaimProcessedEvent(ctx, record, runtimeProcessedEventMaxRecords)
	if err != nil {
		return false, true, err
	}
	if claimed {
		s.rememberProcessedEventBloomKey(record.EventKey)
	}
	return claimed, true, nil
}

func (s *SQLiteIngestStore) reloadProcessedEventBloom(ctx context.Context) error {
	if s == nil || s.store == nil || s.processedEventBloom == nil {
		return nil
	}
	lister, ok := s.store.(processedEventKeyLister)
	if !ok {
		return nil
	}
	keys, err := lister.ListActiveProcessedEventKeys(ctx, runtimeProcessedEventNamespace, time.Now().UTC(), runtimeProcessedEventMaxRecords)
	if err != nil {
		return err
	}
	s.processedEventBloom.replace(keys)
	return nil
}

func (s *SQLiteIngestStore) rememberProcessedEventBloomKey(eventKey string) {
	if s == nil || s.processedEventBloom == nil {
		return
	}
	if needsRebuild := s.processedEventBloom.add(eventKey); needsRebuild {
		_ = s.reloadProcessedEventBloom(context.Background())
	}
}
