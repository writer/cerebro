package recovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestAppendRecordsExhaustedPublish(t *testing.T) {
	inner := &recordingLog{err: &ports.AppendLogPublishExhaustedError{
		Operation:     "append",
		Subject:       "sec.findings.v1.recorded",
		ErrorCategory: "no_response",
		RetryCount:    3,
		MaxAttempts:   4,
		Err:           errors.New("publish event: no response"),
	}}
	store := &recordingStore{}
	log := Wrap(inner, store)
	event := recoveryTestEvent("finding-1")

	err := log.Append(context.Background(), event)
	if err == nil {
		t.Fatal("Append() error = nil, want original publish error")
	}
	if len(store.records) != 1 {
		t.Fatalf("dead letter records = %d, want 1", len(store.records))
	}
	record := store.records[0]
	if record.Subject != "sec.findings.v1.recorded" || record.EventID != "finding-1" || record.EventKind != "sec.findings.v1.recorded" {
		t.Fatalf("record event fields = %#v", record)
	}
	if record.RuntimeID != "runtime-1" || record.SourceID != "github" || record.TenantID != "writer" || record.JobID != "job-1" {
		t.Fatalf("record context fields = %#v", record)
	}
	if record.RetryCount != 3 || record.MaxAttempts != 4 || record.ErrorCategory != "no_response" {
		t.Fatalf("record retry fields = %#v", record)
	}
	if record.ErrorMessage != "append log publish exhausted; category=no_response; attempts=3/4" {
		t.Fatalf("record error message = %q, want bounded retry diagnostic", record.ErrorMessage)
	}
	if record.ID == "" || record.PayloadHash == "" || record.PayloadBytes == 0 || record.Event == nil {
		t.Fatalf("record durability fields missing: %#v", record)
	}
	if inner.events[0] == record.Event {
		t.Fatal("record reused event pointer; want cloned event")
	}
}

func TestDeadLetterDiagnosticDoesNotPersistWrappedError(t *testing.T) {
	secret := "Bearer test-sensitive-value" // #nosec G101 -- credential-shaped test data verifies diagnostic redaction.
	diagnostic := deadLetterDiagnostic(&ports.AppendLogPublishExhaustedError{
		Subject:       "sec.findings.v1.recorded",
		ErrorCategory: "no_response",
		RetryCount:    3,
		MaxAttempts:   4,
		Err:           errors.New("authorization=" + secret + " response={unbounded-body}"),
	})
	if strings.Contains(diagnostic, secret) || strings.Contains(diagnostic, "authorization") || strings.Contains(diagnostic, "unbounded-body") {
		t.Fatalf("deadLetterDiagnostic() leaked wrapped error: %q", diagnostic)
	}
}

func TestAppendDoesNotRecordNonExhaustedError(t *testing.T) {
	inner := &recordingLog{err: errors.New("validation failed")}
	store := &recordingStore{}
	log := Wrap(inner, store)

	err := log.Append(context.Background(), recoveryTestEvent("finding-1"))
	if err == nil {
		t.Fatal("Append() error = nil, want original error")
	}
	if len(store.records) != 0 {
		t.Fatalf("dead letter records = %d, want 0", len(store.records))
	}
}

func TestAppendReturnsStoreFailureWithOriginalError(t *testing.T) {
	publishErr := errors.New("publish event: no response")
	inner := &recordingLog{err: &ports.AppendLogPublishExhaustedError{
		Subject:       "sec.findings.v1.recorded",
		ErrorCategory: "no_response",
		Err:           publishErr,
	}}
	storeErr := errors.New("postgres unavailable")
	log := Wrap(inner, &recordingStore{recordErr: storeErr})

	err := log.Append(context.Background(), recoveryTestEvent("finding-1"))
	if !errors.Is(err, storeErr) {
		t.Fatalf("Append() error = %v, want joined store error", err)
	}
	if !errors.Is(err, publishErr) {
		t.Fatalf("Append() error = %v, want original publish error", err)
	}
}

func TestAppendBatchRecordsFailedEvent(t *testing.T) {
	inner := &recordingLog{
		failOnID: "finding-2",
		err: &ports.AppendLogPublishExhaustedError{
			Subject:       "sec.findings.v1.recorded",
			ErrorCategory: "no_response",
			Err:           errors.New("publish event: no response"),
		},
	}
	store := &recordingStore{}
	log := Wrap(inner, store).(ports.AppendLogBatcher)

	err := log.AppendBatch(context.Background(), []*cerebrov1.EventEnvelope{
		recoveryTestEvent("finding-1"),
		recoveryTestEvent("finding-2"),
	})
	if err == nil {
		t.Fatal("AppendBatch() error = nil, want failed event error")
	}
	if len(store.records) != 1 || store.records[0].EventID != "finding-2" {
		t.Fatalf("recorded events = %#v, want only failed event finding-2", store.records)
	}
}

func TestReplayDelegatesToInnerReplayer(t *testing.T) {
	event := recoveryTestEvent("finding-1")
	inner := &recordingLog{replayEvents: []*cerebrov1.EventEnvelope{event}}
	log := Wrap(inner, &recordingStore{}).(ports.EventReplayer)

	got, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "runtime-1"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(got) != 1 || got[0].GetId() != "finding-1" {
		t.Fatalf("Replay() events = %#v", got)
	}
	if inner.replayRequests != 1 {
		t.Fatalf("inner replay requests = %d, want 1", inner.replayRequests)
	}
}

func recoveryTestEvent(id string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:       id,
		TenantId: "writer",
		SourceId: "github",
		Kind:     "sec.findings.v1.recorded",
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: "runtime-1",
			ports.EventAttributeJobID:           "job-1",
		},
	}
}

type recordingLog struct {
	err            error
	failOnID       string
	events         []*cerebrov1.EventEnvelope
	replayEvents   []*cerebrov1.EventEnvelope
	replayRequests int
}

func (l *recordingLog) Ping(context.Context) error { return nil }

func (l *recordingLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	if l.failOnID == "" || event.GetId() == l.failOnID {
		return l.err
	}
	return nil
}

func (l *recordingLog) Replay(context.Context, ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	l.replayRequests++
	return l.replayEvents, nil
}

type recordingStore struct {
	records   []ports.AppendLogDeadLetter
	recordErr error
}

func (s *recordingStore) RecordAppendLogDeadLetter(_ context.Context, record ports.AppendLogDeadLetter) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	s.records = append(s.records, record)
	return nil
}

func (s *recordingStore) ListAppendLogDeadLetters(context.Context, ports.AppendLogDeadLetterFilter) ([]ports.AppendLogDeadLetter, error) {
	return nil, nil
}

func (s *recordingStore) GetAppendLogDeadLetter(context.Context, string) (ports.AppendLogDeadLetter, error) {
	return ports.AppendLogDeadLetter{}, nil
}

func (s *recordingStore) ClaimAppendLogDeadLetterReplay(context.Context, string, string, string, time.Duration) (ports.AppendLogDeadLetter, error) {
	return ports.AppendLogDeadLetter{}, nil
}

func (s *recordingStore) RenewAppendLogDeadLetterReplay(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *recordingStore) CompleteAppendLogDeadLetterReplay(context.Context, string, string, string, string) error {
	return nil
}

func (s *recordingStore) ReleaseAppendLogDeadLetterReplay(context.Context, string, string, string) error {
	return nil
}

func (s *recordingStore) DiscardAppendLogDeadLetter(context.Context, string, string, string) error {
	return nil
}

func (s *recordingStore) GetAppendLogDeadLetterBacklog(context.Context) (ports.AppendLogDeadLetterBacklog, error) {
	return ports.AppendLogDeadLetterBacklog{}, nil
}

func (s *recordingStore) CleanupAppendLogDeadLetters(context.Context, ports.AppendLogDeadLetterCleanupRequest) (ports.AppendLogDeadLetterCleanupResult, error) {
	return ports.AppendLogDeadLetterCleanupResult{}, nil
}
