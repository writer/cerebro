package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type recordRejectedProjectionError struct{ code string }

func (e recordRejectedProjectionError) Error() string { return "projector rejected record" }

func (e recordRejectedProjectionError) Is(target error) bool {
	return target == ports.ErrSourceProjectionRecordRejected
}

func (e recordRejectedProjectionError) ProjectionErrorCode() string { return e.code }

type selectiveProjector struct {
	failures map[string]error
	result   ports.ProjectionResult
	events   []*cerebrov1.EventEnvelope
}

func (p *selectiveProjector) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if err := p.failures[event.GetId()]; err != nil {
		return ports.ProjectionResult{}, err
	}
	p.events = append(p.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return p.result, nil
}

type projectionDeadLetterStore struct {
	ports.AppendLogDeadLetterStore
	err     error
	records []ports.AppendLogDeadLetter
}

func (s *projectionDeadLetterStore) RecordAppendLogDeadLetter(_ context.Context, record ports.AppendLogDeadLetter) error {
	if s.err != nil {
		return s.err
	}
	s.records = append(s.records, record)
	return nil
}

type projectionDeadLetterFixture struct {
	service   *Service
	store     *runtimeStore
	log       *appendLog
	projector *selectiveProjector
	manifests *projector
}

const projectionDeadLetterRuntimeID = "writer-projection-dlq"

func newProjectionDeadLetterFixture(t *testing.T, eventCount int, rejected map[string]error, deadLetters ports.AppendLogDeadLetterStore) projectionDeadLetterFixture {
	t.Helper()
	events := make([]*cerebrov1.EventEnvelope, 0, eventCount)
	for index := range eventCount {
		events = append(events, runtimeTestEvent(fmt.Sprintf("event-%d", index+1), "projection_dlq", "projection_dlq.record"))
	}
	source := admissionTestSource{
		id:         "projection_dlq",
		events:     events,
		checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: "candidate-checkpoint"},
	}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		projectionDeadLetterRuntimeID: {
			Id:         projectionDeadLetterRuntimeID,
			SourceId:   source.id,
			TenantId:   "writer",
			Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: "committed-checkpoint"},
		},
	}}
	log := &appendLog{}
	selective := &selectiveProjector{failures: rejected, result: ports.ProjectionResult{EntitiesProjected: 1}}
	recorder := &projectorWithCollection{selectiveProjector: selective, manifests: &projector{}}
	service := New(registry, store, log, recorder)
	if deadLetters != nil {
		service.WithProjectionDeadLetterStore(deadLetters)
	}
	return projectionDeadLetterFixture{service: service, store: store, log: log, projector: selective, manifests: recorder.manifests}
}

type projectorWithCollection struct {
	*selectiveProjector
	manifests *projector
}

func (p *projectorWithCollection) RecordSourceCollection(ctx context.Context, manifest ports.SourceCollectionManifest) error {
	return p.manifests.RecordSourceCollection(ctx, manifest)
}

func (f projectionDeadLetterFixture) sync() (*cerebrov1.SyncSourceRuntimeResponse, error) {
	return f.service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: projectionDeadLetterRuntimeID})
}

func (f projectionDeadLetterFixture) requireNoProgress(t *testing.T) {
	t.Helper()
	stored := f.store.runtimes[projectionDeadLetterRuntimeID]
	if got := stored.GetCheckpoint().GetCursorOpaque(); got != "committed-checkpoint" {
		t.Fatalf("checkpoint = %q, want committed-checkpoint", got)
	}
	if got := stored.GetConfig()[runtimeStatusConfigKey]; got != "failed" {
		t.Fatalf("runtime status = %q, want failed", got)
	}
}

func rejectedEvents(ids ...string) map[string]error {
	failures := make(map[string]error, len(ids))
	for _, id := range ids {
		failures[id] = fmt.Errorf("rust projection returned 422: %w", recordRejectedProjectionError{code: "invalid_legacy_projection"})
	}
	return failures
}

func TestSyncDeadLettersRecordScopedProjectionRejection(t *testing.T) {
	deadLetters := &projectionDeadLetterStore{}
	fixture := newProjectionDeadLetterFixture(t, 3, rejectedEvents("event-2"), deadLetters)

	response, err := fixture.sync()
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if response.GetEventsAppended() != 3 || len(fixture.log.events) != 3 {
		t.Fatalf("events appended = %d/%d, want 3", response.GetEventsAppended(), len(fixture.log.events))
	}
	projected := make([]string, 0, len(fixture.projector.events))
	for _, event := range fixture.projector.events {
		projected = append(projected, event.GetId())
	}
	if !slices.Equal(projected, []string{"event-1", "event-3"}) {
		t.Fatalf("projected events = %v, want [event-1 event-3]", projected)
	}
	if response.GetEntitiesProjected() != 2 {
		t.Fatalf("entities projected = %d, want 2", response.GetEntitiesProjected())
	}
	if len(deadLetters.records) != 1 {
		t.Fatalf("dead letters = %d, want 1", len(deadLetters.records))
	}
	record := deadLetters.records[0]
	if record.Operation != ports.AppendLogDeadLetterOperationSourceProjection ||
		record.EventID != "event-2" || record.EventKind != "projection_dlq.record" ||
		record.TenantID != "writer" || record.SourceID != "projection_dlq" ||
		record.RuntimeID != projectionDeadLetterRuntimeID ||
		record.ErrorCategory != "invalid_legacy_projection" ||
		record.Status != ports.AppendLogDeadLetterStatusPending || record.Event == nil {
		t.Fatalf("dead letter = %#v", record)
	}
	stored := fixture.store.runtimes[projectionDeadLetterRuntimeID]
	if got := stored.GetCheckpoint().GetCursorOpaque(); got != "candidate-checkpoint" {
		t.Fatalf("checkpoint = %q, want candidate-checkpoint", got)
	}
	if got := stored.GetConfig()[runtimeStatusConfigKey]; got != "completed" {
		t.Fatalf("runtime status = %q, want completed", got)
	}
	if got := stored.GetConfig()[runtimeRecordsProjectionDeadLetteredConfigKey]; got != "1" {
		t.Fatalf("projection dead-lettered status = %q, want 1", got)
	}
	if len(fixture.manifests.manifests) != 1 {
		t.Fatalf("collection manifests = %d, want 1", len(fixture.manifests.manifests))
	}
	manifest := fixture.manifests.manifests[0]
	if manifest.Status != "incomplete" || !slices.Contains(manifest.IncompletenessReasons, CollectionIncompleteProjectionDeadLettered) {
		t.Fatalf("collection manifest = %#v, want incomplete with projection_dead_lettered", manifest)
	}
}

func TestSyncProjectionFailuresThatAreNotDeadLettered(t *testing.T) {
	storeFailure := fmt.Errorf("record capacity: %w", ports.ErrAppendLogDeadLetterBacklogHardLimit)
	systemic := errors.New("rust projection returned 503 Service Unavailable")
	tests := []struct {
		name        string
		failures    map[string]error
		deadLetters *projectionDeadLetterStore
		wantErrs    []error
	}{
		{
			name:        "systemic projector failure",
			failures:    map[string]error{"event-2": systemic},
			deadLetters: &projectionDeadLetterStore{},
			wantErrs:    []error{systemic},
		},
		{
			name:     "no dead-letter store",
			failures: rejectedEvents("event-2"),
			wantErrs: []error{ports.ErrSourceProjectionRecordRejected},
		},
		{
			name:        "dead-letter store write failure",
			failures:    rejectedEvents("event-2"),
			deadLetters: &projectionDeadLetterStore{err: storeFailure},
			wantErrs:    []error{ports.ErrSourceProjectionRecordRejected, ports.ErrAppendLogDeadLetterBacklogHardLimit},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var store ports.AppendLogDeadLetterStore
			if test.deadLetters != nil {
				store = test.deadLetters
			}
			fixture := newProjectionDeadLetterFixture(t, 3, test.failures, store)

			_, err := fixture.sync()
			for _, want := range test.wantErrs {
				if !errors.Is(err, want) {
					t.Fatalf("Sync() error = %v, want %v", err, want)
				}
			}
			if test.deadLetters != nil && len(test.deadLetters.records) != 0 {
				t.Fatalf("dead letters = %d, want 0", len(test.deadLetters.records))
			}
			fixture.requireNoProgress(t)
			if len(fixture.manifests.manifests) != 0 {
				t.Fatal("failed sync must not record a collection manifest")
			}
		})
	}
}

func TestSyncProjectionDeadLetterPageBound(t *testing.T) {
	ids := func(count int) []string {
		values := make([]string, 0, count)
		for index := range count {
			values = append(values, fmt.Sprintf("event-%d", index+1))
		}
		return values
	}
	tests := []struct {
		name            string
		events          int
		rejected        int
		wantErr         bool
		wantDeadLetters int
	}{
		{name: "small page fully rejected stays under floor", events: 8, rejected: 8, wantDeadLetters: 8},
		{name: "many rejections under percentage", events: 50, rejected: 12, wantDeadLetters: 12},
		{name: "over floor and percentage", events: 20, rejected: 12, wantErr: true, wantDeadLetters: 10},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deadLetters := &projectionDeadLetterStore{}
			fixture := newProjectionDeadLetterFixture(t, test.events, rejectedEvents(ids(test.rejected)...), deadLetters)

			_, err := fixture.sync()
			if test.wantErr {
				if !errors.Is(err, ErrProjectionRejectionRateExceeded) || !errors.Is(err, ports.ErrSourceProjectionRecordRejected) {
					t.Fatalf("Sync() error = %v, want ErrProjectionRejectionRateExceeded", err)
				}
				fixture.requireNoProgress(t)
			} else if err != nil {
				t.Fatalf("Sync() error = %v", err)
			}
			if len(deadLetters.records) != test.wantDeadLetters {
				t.Fatalf("dead letters = %d, want %d", len(deadLetters.records), test.wantDeadLetters)
			}
		})
	}
}

func TestSyncProjectionDeadLetterIDIsStableAcrossRetries(t *testing.T) {
	deadLetters := &projectionDeadLetterStore{}
	fixture := newProjectionDeadLetterFixture(t, 2, rejectedEvents("event-1"), deadLetters)

	if _, err := fixture.sync(); err != nil {
		t.Fatalf("first Sync() error = %v", err)
	}
	if _, err := fixture.sync(); err != nil {
		t.Fatalf("second Sync() error = %v", err)
	}
	if len(deadLetters.records) != 2 {
		t.Fatalf("dead letter writes = %d, want 2", len(deadLetters.records))
	}
	first, second := deadLetters.records[0], deadLetters.records[1]
	if first.Event.GetAttributes()[ports.EventAttributeSourceCollectionID] == second.Event.GetAttributes()[ports.EventAttributeSourceCollectionID] {
		t.Fatal("test precondition: retried syncs should carry distinct collection IDs")
	}
	if first.ID != second.ID {
		t.Fatalf("retried dead letter ID = %q, want %q", second.ID, first.ID)
	}
}
