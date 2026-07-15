package compliancemonitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var ErrServiceUnavailable = errors.New("compliance monitor service unavailable")
var ErrInvalidMonitor = errors.New("invalid compliance monitor")

const (
	monitorAggregateType = "compliance_monitor"
	triggerAggregateType = "compliance_monitor_trigger"
	operationCreated     = "created"
	operationUpdated     = "updated"
	operationTimeTrigger = "time_triggered"
	operationChange      = "change_triggered"
)

// Service is the canonical write boundary for compliance monitors. Definition
// changes and trigger acknowledgements cannot reach the Postgres projection
// without first passing through the durable workflow event log.
type Service struct {
	store       ports.ComplianceMonitorStore
	appendLog   ports.AppendLog
	assessments AssessmentRequester
}

type ScheduledAssessmentRequest struct {
	TenantID       string
	ProgramID      string
	PlanRevisionID string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	IdempotencyKey string
	RequestedBy    string
	MonitorRun     ports.ComplianceMonitorRun
	ChangeWindow   *ports.ComplianceChangeWindow
}

type ScheduledAssessment struct {
	TenantID string
	RunID    string
	JobID    string
}

type AssessmentRequester interface {
	RequestScheduledAssessment(context.Context, ScheduledAssessmentRequest) (ScheduledAssessment, error)
	StartScheduledAssessment(context.Context, ScheduledAssessment) error
}

// New requires both the projection store and append log. A nil append log is
// never treated as an opt-out because Postgres is not monitor authority.
func New(store ports.ComplianceMonitorStore, appendLog ports.AppendLog) (*Service, error) {
	if store == nil || appendLog == nil {
		return nil, ErrServiceUnavailable
	}
	return &Service{store: store, appendLog: appendLog}, nil
}

// WithJobs enables time and change trigger scheduling on the same append-first
// boundary. Monitor definition updates do not require the job runtime.
func (s *Service) WithJobs(jobs *platformjobs.Service) *Service {
	if s != nil {
		if jobs == nil {
			s.assessments = nil
		} else {
			s.assessments = jobAssessmentRequester{jobs: jobs}
		}
	}
	return s
}

func (s *Service) WithAssessmentRequester(requester AssessmentRequester) *Service {
	if s != nil {
		s.assessments = requester
	}
	return s
}

type jobAssessmentRequester struct {
	jobs *platformjobs.Service
}

func (r jobAssessmentRequester) RequestScheduledAssessment(ctx context.Context, request ScheduledAssessmentRequest) (ScheduledAssessment, error) {
	if r.jobs == nil {
		return ScheduledAssessment{}, ErrServiceUnavailable
	}
	payload := map[string]any{
		"program_id":            request.ProgramID,
		"plan_revision_id":      request.PlanRevisionID,
		"monitor_id":            request.MonitorRun.MonitorID,
		"plan_lease_owner":      request.MonitorRun.LeaseOwner,
		"plan_lease_occurrence": request.MonitorRun.OccurrenceKey,
	}
	if request.ChangeWindow == nil {
		payload["scheduled_for"] = request.PeriodEnd.UTC().Format(time.RFC3339Nano)
	} else {
		payload["change_window_version"] = request.ChangeWindow.Version
		payload["change_window_opened_at"] = request.ChangeWindow.OpenedAt.UTC().Format(time.RFC3339Nano)
		payload["change_signal_count"] = request.ChangeWindow.SignalCount
		payload["change_scope_digest"] = request.ChangeWindow.ScopeDigest
	}
	job, _, err := r.jobs.Create(ctx, ports.CreateJobRequest{
		Kind:           platformjobs.KindComplianceAssessment,
		TenantID:       request.TenantID,
		SubjectType:    subjectType,
		SubjectID:      request.MonitorRun.MonitorID,
		IdempotencyKey: request.IdempotencyKey,
		Payload:        payload,
	})
	if err != nil {
		return ScheduledAssessment{}, err
	}
	return ScheduledAssessment{TenantID: request.TenantID, JobID: job.ID}, nil
}

func (r jobAssessmentRequester) StartScheduledAssessment(ctx context.Context, assessment ScheduledAssessment) error {
	if r.jobs == nil {
		return ErrServiceUnavailable
	}
	job, err := r.jobs.Get(ctx, assessment.JobID)
	if err != nil {
		return err
	}
	r.jobs.StartAsync(ctx, job)
	return nil
}

// UpdateMonitor appends a deterministic monitor revision before projecting it
// to Postgres. Repeating the same expected version and definition is replay
// safe when the first projection committed but its result was not observed.
func (s *Service) UpdateMonitor(ctx context.Context, monitor *ports.ComplianceMonitor, expectedVersion uint64, actorID string, recordedAt time.Time) (*ports.ComplianceMonitor, error) {
	if s == nil || s.store == nil || s.appendLog == nil {
		return nil, ErrServiceUnavailable
	}
	if monitor != nil && strings.TrimSpace(monitor.ID) == "" {
		id, err := compliance.NewIdentifier(compliance.IdentifierMonitor)
		if err != nil {
			return nil, err
		}
		copy := *monitor
		copy.ID = id
		monitor = &copy
	}
	normalized, targetVersion, operation, err := normalizeMonitorUpdate(monitor, expectedVersion, actorID, recordedAt)
	if err != nil {
		return nil, err
	}
	event, err := monitorUpdatedEvent(normalized, targetVersion, operation, actorID, recordedAt)
	if err != nil {
		return nil, err
	}
	if err := s.appendLog.Append(ctx, event); err != nil {
		return nil, fmt.Errorf("append compliance monitor update: %w", err)
	}
	projected, projectErr := s.store.ProjectComplianceMonitor(ctx, normalized, expectedVersion)
	if projectErr == nil {
		return projected, nil
	}
	// A projection may commit and still return an error to the caller. Read back
	// the target version before reporting failure so a retry cannot turn an
	// already-projected append into a false conflict.
	existing, readErr := s.store.GetComplianceMonitor(ctx, normalized.TenantID, normalized.ID)
	if readErr == nil && sameMonitorProjection(existing, normalized) {
		return existing, nil
	}
	return nil, fmt.Errorf("project compliance monitor update: %w", projectErr)
}

func (s *Service) GetMonitor(ctx context.Context, tenantID, monitorID string) (*ports.ComplianceMonitor, error) {
	if s == nil || s.store == nil {
		return nil, ErrServiceUnavailable
	}
	return s.store.GetComplianceMonitor(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(monitorID))
}

func (s *Service) ListMonitors(ctx context.Context, filter ports.ComplianceMonitorFilter) ([]*ports.ComplianceMonitor, error) {
	if s == nil || s.store == nil {
		return nil, ErrServiceUnavailable
	}
	return s.store.ListComplianceMonitors(ctx, filter)
}

// RecordChangeSignal projects an already-durable, bounded change notification
// into the debounce window. The signal carries identifiers and a digest only.
func (s *Service) RecordChangeSignal(ctx context.Context, signal ports.ComplianceChangeSignal) (bool, error) {
	if s == nil || s.store == nil {
		return false, ErrServiceUnavailable
	}
	store, ok := s.store.(ports.ComplianceChangeMonitorStore)
	if !ok {
		return false, ErrServiceUnavailable
	}
	return store.RecordComplianceChangeSignal(ctx, signal)
}

type monitorDefinitionEvent struct {
	MonitorID                string `json:"monitor_id"`
	ProgramID                string `json:"program_id"`
	PlanRevisionID           string `json:"plan_revision_id"`
	TriggerKind              string `json:"trigger_kind"`
	IntervalSeconds          int64  `json:"interval_seconds"`
	ExpectedCoverage         string `json:"expected_coverage,omitempty"`
	MaximumEvidenceAgeSecond int64  `json:"maximum_evidence_age_seconds"`
	GracePeriodSeconds       int64  `json:"grace_period_seconds"`
	DebounceSeconds          int64  `json:"debounce_seconds"`
	EscalationOwner          string `json:"escalation_owner,omitempty"`
	Enabled                  bool   `json:"enabled"`
	NextRunAt                string `json:"next_run_at,omitempty"`
}

type monitorTriggerEvent struct {
	MonitorID      string `json:"monitor_id"`
	ProgramID      string `json:"program_id"`
	PlanRevisionID string `json:"plan_revision_id"`
	TriggerKind    string `json:"trigger_kind"`
	OccurrenceKey  string `json:"occurrence_key"`
	JobID          string `json:"job_id"`
	ScheduledFor   string `json:"scheduled_for,omitempty"`
	WindowVersion  uint64 `json:"window_version,omitempty"`
	WindowOpenedAt string `json:"window_opened_at,omitempty"`
	WindowReadyAt  string `json:"window_ready_at,omitempty"`
	SignalCount    uint64 `json:"signal_count,omitempty"`
	ScopeDigest    string `json:"scope_digest,omitempty"`
}

func normalizeMonitorUpdate(monitor *ports.ComplianceMonitor, expectedVersion uint64, actorID string, recordedAt time.Time) (*ports.ComplianceMonitor, uint64, string, error) {
	if monitor == nil {
		return nil, 0, "", fmt.Errorf("%w: monitor is required", ErrInvalidMonitor)
	}
	if expectedVersion >= math.MaxInt64 {
		return nil, 0, "", fmt.Errorf("%w: expected version exceeds its limit", ErrInvalidMonitor)
	}
	if recordedAt.IsZero() {
		return nil, 0, "", fmt.Errorf("%w: recorded time is required", ErrInvalidMonitor)
	}
	if !bounded(actorID, 512, true) {
		return nil, 0, "", fmt.Errorf("%w: actor exceeds its limit", ErrInvalidMonitor)
	}
	result := *monitor
	result.ID = strings.TrimSpace(result.ID)
	result.TenantID = strings.TrimSpace(result.TenantID)
	result.ProgramID = strings.TrimSpace(result.ProgramID)
	result.PlanRevisionID = strings.TrimSpace(result.PlanRevisionID)
	result.TriggerKind = strings.ToLower(strings.TrimSpace(result.TriggerKind))
	result.ExpectedCoverage = strings.TrimSpace(result.ExpectedCoverage)
	result.EscalationOwner = strings.TrimSpace(result.EscalationOwner)
	result.NextRunAt = canonicalTime(result.NextRunAt)
	if !bounded(result.ID, 512, false) || !bounded(result.TenantID, 255, false) || !bounded(result.ProgramID, 512, false) || !bounded(result.PlanRevisionID, 512, false) {
		return nil, 0, "", fmt.Errorf("%w: id, tenant, program, and plan revision are required and must be bounded", ErrInvalidMonitor)
	}
	if !bounded(result.ExpectedCoverage, 256, true) || !bounded(result.EscalationOwner, 512, true) {
		return nil, 0, "", fmt.Errorf("%w: coverage or escalation owner exceeds its limit", ErrInvalidMonitor)
	}
	if result.TriggerKind != ports.ComplianceTriggerTime && result.TriggerKind != ports.ComplianceTriggerChange {
		return nil, 0, "", fmt.Errorf("%w: trigger kind is invalid", ErrInvalidMonitor)
	}
	if result.MaximumEvidenceAge < 0 || result.GracePeriod < 0 || result.DebounceWindow < 0 ||
		result.MaximumEvidenceAge%time.Second != 0 || result.GracePeriod%time.Second != 0 || result.DebounceWindow%time.Second != 0 {
		return nil, 0, "", fmt.Errorf("%w: durations must be non-negative whole seconds", ErrInvalidMonitor)
	}
	if result.TriggerKind == ports.ComplianceTriggerTime && (result.IntervalSeconds <= 0 || result.NextRunAt.IsZero()) {
		return nil, 0, "", fmt.Errorf("%w: time-triggered interval and next run time are required", ErrInvalidMonitor)
	}
	if result.TriggerKind == ports.ComplianceTriggerChange && result.DebounceWindow <= 0 {
		return nil, 0, "", fmt.Errorf("%w: change-triggered debounce window must be positive", ErrInvalidMonitor)
	}
	targetVersion := expectedVersion + 1
	if result.Version != 0 && result.Version != targetVersion {
		return nil, 0, "", fmt.Errorf("%w: version %d does not match target version %d", ErrInvalidMonitor, result.Version, targetVersion)
	}
	result.Version = targetVersion
	operation := operationUpdated
	if expectedVersion == 0 {
		operation = operationCreated
	}
	return &result, targetVersion, operation, nil
}

func monitorUpdatedEvent(monitor *ports.ComplianceMonitor, version uint64, operation, actorID string, recordedAt time.Time) (*cerebrov1.EventEnvelope, error) {
	if version == 0 || version > math.MaxInt64 {
		return nil, errors.New("compliance monitor event version exceeds its limit")
	}
	aggregateVersion := int64(version) // #nosec G115 -- bounded by MaxInt64 above.
	payload := definitionPayload(monitor)
	encoded, digest, err := encodedDigest(payload)
	if err != nil {
		return nil, err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceMonitorUpdated, TenantID: monitor.TenantID,
		AggregateType: monitorAggregateType, AggregateID: monitor.ID,
		RevisionID: fmt.Sprintf("%s:v%d", monitor.ID, version), AggregateVersion: aggregateVersion,
		Operation: operation, ContentDigest: digest, PayloadJSON: string(encoded),
		ActorID: strings.TrimSpace(actorID), RecordedAt: canonicalTime(recordedAt).Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, err
	}
	return event, nil
}

func monitorTimeTriggeredEvent(monitor *ports.ComplianceMonitor, occurrence, jobID string) (*cerebrov1.EventEnvelope, error) {
	payload := monitorTriggerEvent{
		MonitorID: monitor.ID, ProgramID: monitor.ProgramID, PlanRevisionID: monitor.PlanRevisionID,
		TriggerKind: ports.ComplianceTriggerTime, OccurrenceKey: occurrence, JobID: strings.TrimSpace(jobID),
		ScheduledFor: canonicalTime(monitor.NextRunAt).Format(time.RFC3339Nano),
	}
	return monitorTriggeredEvent(monitor.TenantID, occurrence, jobID, operationTimeTrigger, monitor.NextRunAt, payload)
}

func monitorChangeTriggeredEvent(window *ports.ComplianceChangeWindow, occurrence, jobID string) (*cerebrov1.EventEnvelope, error) {
	payload := monitorTriggerEvent{
		MonitorID: window.MonitorID, ProgramID: window.ProgramID, PlanRevisionID: window.PlanRevisionID,
		TriggerKind: ports.ComplianceTriggerChange, OccurrenceKey: occurrence, JobID: strings.TrimSpace(jobID),
		WindowVersion: window.Version, WindowOpenedAt: canonicalTime(window.OpenedAt).Format(time.RFC3339Nano),
		WindowReadyAt: canonicalTime(window.ReadyAt).Format(time.RFC3339Nano), SignalCount: window.SignalCount,
		ScopeDigest: strings.TrimSpace(window.ScopeDigest),
	}
	return monitorTriggeredEvent(window.TenantID, occurrence, jobID, operationChange, window.ReadyAt, payload)
}

func monitorTriggeredEvent(tenantID, occurrence, jobID, operation string, recordedAt time.Time, payload monitorTriggerEvent) (*cerebrov1.EventEnvelope, error) {
	if !bounded(tenantID, 255, false) || !bounded(occurrence, 1024, false) || !bounded(jobID, 512, false) || recordedAt.IsZero() {
		return nil, errors.New("compliance monitor trigger tenant, occurrence, job, and time are required")
	}
	if !bounded(payload.MonitorID, 512, false) || !bounded(payload.ProgramID, 512, false) || !bounded(payload.PlanRevisionID, 512, false) ||
		payload.OccurrenceKey != strings.TrimSpace(occurrence) || payload.JobID != strings.TrimSpace(jobID) {
		return nil, errors.New("compliance monitor trigger identifiers are invalid")
	}
	switch payload.TriggerKind {
	case ports.ComplianceTriggerTime:
		if operation != operationTimeTrigger || strings.TrimSpace(payload.ScheduledFor) == "" {
			return nil, errors.New("time-triggered compliance monitor occurrence is invalid")
		}
	case ports.ComplianceTriggerChange:
		if operation != operationChange || payload.WindowVersion == 0 || payload.SignalCount == 0 ||
			strings.TrimSpace(payload.WindowOpenedAt) == "" || strings.TrimSpace(payload.WindowReadyAt) == "" || !bounded(payload.ScopeDigest, 256, false) {
			return nil, errors.New("change-triggered compliance monitor window is invalid")
		}
	default:
		return nil, errors.New("compliance monitor trigger kind is invalid")
	}
	encoded, digest, err := encodedDigest(payload)
	if err != nil {
		return nil, err
	}
	return workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceMonitorTriggered, TenantID: strings.TrimSpace(tenantID),
		AggregateType: triggerAggregateType, AggregateID: strings.TrimSpace(occurrence),
		RevisionID: strings.TrimSpace(jobID), AggregateVersion: 1, Operation: operation,
		ContentDigest: digest, PayloadJSON: string(encoded), RecordedAt: canonicalTime(recordedAt).Format(time.RFC3339Nano),
	})
}

func definitionPayload(monitor *ports.ComplianceMonitor) monitorDefinitionEvent {
	result := monitorDefinitionEvent{
		MonitorID: monitor.ID, ProgramID: monitor.ProgramID, PlanRevisionID: monitor.PlanRevisionID,
		TriggerKind: monitor.TriggerKind, IntervalSeconds: monitor.IntervalSeconds,
		ExpectedCoverage: monitor.ExpectedCoverage, MaximumEvidenceAgeSecond: int64(monitor.MaximumEvidenceAge / time.Second),
		GracePeriodSeconds: int64(monitor.GracePeriod / time.Second), DebounceSeconds: int64(monitor.DebounceWindow / time.Second),
		EscalationOwner: monitor.EscalationOwner, Enabled: monitor.Enabled,
	}
	if !monitor.NextRunAt.IsZero() {
		result.NextRunAt = canonicalTime(monitor.NextRunAt).Format(time.RFC3339Nano)
	}
	return result
}

func encodedDigest(payload any) ([]byte, string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("encode compliance monitor event: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return encoded, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sameMonitorProjection(actual, expected *ports.ComplianceMonitor) bool {
	if actual == nil || expected == nil || actual.Version != expected.Version {
		return false
	}
	return definitionPayload(actual) == definitionPayload(expected)
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Millisecond)
}

func bounded(value string, maximum int, optional bool) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return optional
	}
	return len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}
