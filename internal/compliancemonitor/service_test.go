package compliancemonitor

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestUpdateMonitorAppendsCanonicalRevisionBeforeProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 123456789, time.UTC)
	store := newDefinitionMonitorStore()
	appendLog := &definitionAppendLog{beforeAppend: func() {
		if store.putCalls != 0 {
			t.Fatal("monitor projection ran before append")
		}
	}}
	service, err := New(store, appendLog)
	if err != nil {
		t.Fatal(err)
	}
	monitor := validDefinitionMonitor(now)
	stored, err := service.UpdateMonitor(context.Background(), monitor, 0, "operator-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || store.putCalls != 1 || len(appendLog.events) != 1 {
		t.Fatalf("stored=%#v putCalls=%d events=%d", stored, store.putCalls, len(appendLog.events))
	}
	payload, err := workflowevents.DecodeComplianceAggregate(appendLog.events[0])
	if err != nil {
		t.Fatal(err)
	}
	if payload.Kind != workflowevents.EventKindComplianceMonitorUpdated || payload.AggregateType != monitorAggregateType || payload.AggregateVersion != 1 || payload.Operation != operationCreated || payload.RevisionID != "monitor-1:v1" {
		t.Fatalf("monitor aggregate = %#v", payload)
	}
	if payload.RecordedAt != "2026-07-11T10:00:00.123Z" {
		t.Fatalf("recorded_at = %q", payload.RecordedAt)
	}
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(payload.PayloadJSON), &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"resources", "resource_contents", "evidence_contents", "raw_evidence"} {
		if _, ok := snapshot[forbidden]; ok {
			t.Fatalf("monitor event contains forbidden field %q", forbidden)
		}
	}
	if snapshot["plan_revision_id"] != "plan-revision-1" || snapshot["next_run_at"] != "2026-07-11T11:00:00.123Z" {
		t.Fatalf("monitor snapshot = %#v", snapshot)
	}
}

func TestMonitorUpdatedEventRejectsOutOfRangeVersion(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	if _, err := monitorUpdatedEvent(validDefinitionMonitor(now), math.MaxUint64, operationUpdated, "operator-1", now); err == nil {
		t.Fatal("out-of-range monitor event version unexpectedly accepted")
	}
}

func TestUpdateMonitorAppendFailureDoesNotProject(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	store := newDefinitionMonitorStore()
	appendLog := &definitionAppendLog{err: errors.New("log unavailable")}
	service, err := New(store, appendLog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateMonitor(context.Background(), validDefinitionMonitor(now), 0, "", now); err == nil {
		t.Fatal("UpdateMonitor() error = nil")
	}
	if store.putCalls != 0 {
		t.Fatalf("projection calls = %d, want 0", store.putCalls)
	}
}

func TestUpdateMonitorRetryReusesEventAfterProjectionFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	store := newDefinitionMonitorStore()
	store.putErr = errors.New("projection unavailable")
	appendLog := &definitionAppendLog{}
	service, err := New(store, appendLog)
	if err != nil {
		t.Fatal(err)
	}
	monitor := validDefinitionMonitor(now)
	if _, err := service.UpdateMonitor(context.Background(), monitor, 0, "operator-1", now); err == nil {
		t.Fatal("first UpdateMonitor() error = nil")
	}
	store.putErr = nil
	stored, err := service.UpdateMonitor(context.Background(), monitor, 0, "operator-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || len(appendLog.events) != 2 {
		t.Fatalf("stored=%#v events=%d", stored, len(appendLog.events))
	}
	if !sameEnvelope(appendLog.events[0], appendLog.events[1]) {
		t.Fatal("projection retry changed the appended monitor event")
	}
}

func TestUpdateMonitorRecoversCommittedProjectionResponseFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	store := newDefinitionMonitorStore()
	store.commitThenErr = errors.New("response lost")
	service, err := New(store, &definitionAppendLog{})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := service.UpdateMonitor(context.Background(), validDefinitionMonitor(now), 0, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Version != 1 {
		t.Fatalf("stored = %#v", stored)
	}
}

func TestUpdateMonitorReplayOfProjectedRevisionIsIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	store := newDefinitionMonitorStore()
	appendLog := &definitionAppendLog{}
	service, err := New(store, appendLog)
	if err != nil {
		t.Fatal(err)
	}
	monitor := validDefinitionMonitor(now)
	if _, err := service.UpdateMonitor(context.Background(), monitor, 0, "operator-1", now); err != nil {
		t.Fatal(err)
	}
	stored, err := service.UpdateMonitor(context.Background(), monitor, 0, "operator-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || len(appendLog.events) != 2 || !sameEnvelope(appendLog.events[0], appendLog.events[1]) {
		t.Fatalf("stored=%#v events=%d", stored, len(appendLog.events))
	}
}

func TestUpdateMonitorUsesExpectedVersionForDeterministicOperation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	store := newDefinitionMonitorStore()
	store.projected = validDefinitionMonitor(now)
	store.projected.Version = 1
	appendLog := &definitionAppendLog{}
	service, err := New(store, appendLog)
	if err != nil {
		t.Fatal(err)
	}
	updated := validDefinitionMonitor(now)
	updated.Enabled = false
	stored, err := service.UpdateMonitor(context.Background(), updated, 1, "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := workflowevents.DecodeComplianceAggregate(appendLog.events[0])
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 2 || payload.AggregateVersion != 2 || payload.Operation != operationUpdated || payload.RevisionID != "monitor-1:v2" {
		t.Fatalf("stored=%#v payload=%#v", stored, payload)
	}
}

func TestNewRequiresAppendLog(t *testing.T) {
	t.Parallel()
	if _, err := New(newDefinitionMonitorStore(), nil); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("New() error = %v", err)
	}
}

type definitionMonitorStore struct {
	*memoryMonitorStore
	projected     *ports.ComplianceMonitor
	putCalls      int
	putErr        error
	commitThenErr error
}

func newDefinitionMonitorStore() *definitionMonitorStore {
	return &definitionMonitorStore{memoryMonitorStore: &memoryMonitorStore{}}
}

func (s *definitionMonitorStore) ProjectComplianceMonitor(_ context.Context, monitor *ports.ComplianceMonitor, expectedVersion uint64) (*ports.ComplianceMonitor, error) {
	s.putCalls++
	if s.putErr != nil {
		return nil, s.putErr
	}
	if s.projected != nil && s.projected.Version != expectedVersion {
		return nil, ports.ErrComplianceMonitorConflict
	}
	clone := *monitor
	s.projected = &clone
	if s.commitThenErr != nil {
		return nil, s.commitThenErr
	}
	return &clone, nil
}

func (s *definitionMonitorStore) GetComplianceMonitor(_ context.Context, tenantID, monitorID string) (*ports.ComplianceMonitor, error) {
	if s.projected == nil || s.projected.TenantID != tenantID || s.projected.ID != monitorID {
		return nil, ports.ErrComplianceMonitorNotFound
	}
	clone := *s.projected
	return &clone, nil
}

type definitionAppendLog struct {
	events       []*cerebrov1.EventEnvelope
	err          error
	beforeAppend func()
}

func (l *definitionAppendLog) Ping(context.Context) error { return nil }
func (l *definitionAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if l.beforeAppend != nil {
		l.beforeAppend()
	}
	l.events = append(l.events, event)
	return l.err
}

func validDefinitionMonitor(now time.Time) *ports.ComplianceMonitor {
	return &ports.ComplianceMonitor{
		ID: "monitor-1", TenantID: "tenant-1", ProgramID: "program-1", PlanRevisionID: "plan-revision-1",
		TriggerKind: ports.ComplianceTriggerTime, IntervalSeconds: 3600, ExpectedCoverage: "required",
		MaximumEvidenceAge: 24 * time.Hour, GracePeriod: time.Hour, EscalationOwner: "owner-1",
		Enabled: true, NextRunAt: now.Add(time.Hour),
	}
}

func sameEnvelope(left, right *cerebrov1.EventEnvelope) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.GetId() == right.GetId() && left.GetKind() == right.GetKind() &&
		reflect.DeepEqual(left.GetPayload(), right.GetPayload()) && reflect.DeepEqual(left.GetAttributes(), right.GetAttributes())
}
