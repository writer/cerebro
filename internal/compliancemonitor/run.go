package compliancemonitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

const (
	claimBatch   = uint32(50)
	claimTTL     = 2 * time.Minute
	planLeaseTTL = 6 * time.Hour
	subjectType  = "compliance_monitor"
)

// RunDue claims due monitor occurrences, obtains one durable lease per tenant
// and plan revision, creates the assessment job, and advances the monitor only
// after the job exists.
func (s *Service) RunDue(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.store == nil || s.assessments == nil || s.appendLog == nil {
		return 0, ErrServiceUnavailable
	}
	now = now.UTC()
	owner := newOwner()
	due, err := s.store.ClaimDueComplianceMonitors(ctx, now, owner, claimTTL, claimBatch)
	if err != nil {
		return 0, err
	}
	enqueued := 0
	var errs []error
	for _, monitor := range due {
		if monitor == nil {
			continue
		}
		occurrence := occurrenceKey(monitor)
		leaseOwner := occurrenceLeaseOwner(monitor.TenantID, monitor.PlanRevisionID, occurrence)
		if err := s.store.AcquireCompliancePlanLease(ctx, monitor.TenantID, monitor.PlanRevisionID, leaseOwner, occurrence, now, planLeaseTTL); err != nil {
			_ = s.store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			if !errors.Is(err, ports.ErrComplianceMonitorOverlap) {
				errs = append(errs, fmt.Errorf("compliance monitor %q plan lease: %w", monitor.ID, err))
			}
			continue
		}
		assessment, createErr := s.assessments.RequestScheduledAssessment(ctx, ScheduledAssessmentRequest{
			TenantID: monitor.TenantID, PlanRevisionID: monitor.PlanRevisionID,
			PeriodStart: monitor.NextRunAt.Add(-time.Duration(monitor.IntervalSeconds) * time.Second), PeriodEnd: monitor.NextRunAt,
			IdempotencyKey: occurrence, RequestedBy: subjectType + ":" + monitor.ID,
			MonitorRun: ports.ComplianceMonitorRun{TenantID: monitor.TenantID, MonitorID: monitor.ID, PlanRevisionID: monitor.PlanRevisionID, OccurrenceKey: occurrence, LeaseOwner: leaseOwner},
		})
		if createErr != nil {
			_ = s.store.ReleaseCompliancePlanLease(context.WithoutCancel(ctx), monitor.TenantID, monitor.PlanRevisionID, leaseOwner)
			_ = s.store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			errs = append(errs, fmt.Errorf("compliance monitor %q enqueue: %w", monitor.ID, createErr))
			continue
		}
		triggerEvent, eventErr := monitorTimeTriggeredEvent(monitor, occurrence, assessment.JobID)
		if eventErr != nil {
			_ = s.store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			errs = append(errs, fmt.Errorf("compliance monitor %q trigger event: %w", monitor.ID, eventErr))
			continue
		}
		if appendErr := s.appendLog.Append(ctx, triggerEvent); appendErr != nil {
			_ = s.store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			errs = append(errs, fmt.Errorf("compliance monitor %q trigger append: %w", monitor.ID, appendErr))
			continue
		}
		if err := s.store.CompleteComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner, monitor.NextRunAt, now); err != nil {
			_ = s.store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			errs = append(errs, fmt.Errorf("compliance monitor %q completion: %w", monitor.ID, err))
			continue
		}
		if err := s.assessments.StartScheduledAssessment(ctx, assessment); err != nil {
			errs = append(errs, fmt.Errorf("compliance monitor %q start assessment: %w", monitor.ID, err))
			continue
		}
		enqueued++
	}
	return enqueued, errors.Join(errs...)
}

// RunDueChanges claims coalesced change windows, obtains the same per-plan
// overlap lease used by time monitors, creates one assessment job, and only
// then acknowledges the exact claimed window version.
func (s *Service) RunDueChanges(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.store == nil || s.assessments == nil || s.appendLog == nil {
		return 0, ErrServiceUnavailable
	}
	store, ok := s.store.(ports.ComplianceChangeMonitorStore)
	if !ok {
		return 0, ErrServiceUnavailable
	}
	now = now.UTC()
	owner := newOwner()
	windows, err := store.ClaimDueComplianceChangeWindows(ctx, now, owner, claimTTL, claimBatch)
	if err != nil {
		return 0, err
	}
	enqueued := 0
	var errs []error
	for _, window := range windows {
		if window == nil {
			continue
		}
		occurrence := changeOccurrenceKey(window)
		leaseOwner := occurrenceLeaseOwner(window.TenantID, window.PlanRevisionID, occurrence)
		if err := store.AcquireCompliancePlanLease(ctx, window.TenantID, window.PlanRevisionID, leaseOwner, occurrence, now, planLeaseTTL); err != nil {
			_ = store.ReleaseComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner)
			if !errors.Is(err, ports.ErrComplianceMonitorOverlap) {
				errs = append(errs, fmt.Errorf("compliance change monitor %q plan lease: %w", window.MonitorID, err))
			}
			continue
		}
		assessment, createErr := s.assessments.RequestScheduledAssessment(ctx, ScheduledAssessmentRequest{
			TenantID: window.TenantID, PlanRevisionID: window.PlanRevisionID,
			PeriodStart: window.OpenedAt, PeriodEnd: window.ReadyAt,
			IdempotencyKey: occurrence, RequestedBy: subjectType + ":" + window.MonitorID,
			MonitorRun: ports.ComplianceMonitorRun{TenantID: window.TenantID, MonitorID: window.MonitorID, PlanRevisionID: window.PlanRevisionID, OccurrenceKey: occurrence, LeaseOwner: leaseOwner},
		})
		if createErr != nil {
			_ = store.ReleaseCompliancePlanLease(context.WithoutCancel(ctx), window.TenantID, window.PlanRevisionID, leaseOwner)
			_ = store.ReleaseComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner)
			errs = append(errs, fmt.Errorf("compliance change monitor %q enqueue: %w", window.MonitorID, createErr))
			continue
		}
		triggerEvent, eventErr := monitorChangeTriggeredEvent(window, occurrence, assessment.JobID)
		if eventErr != nil {
			_ = store.ReleaseComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner)
			errs = append(errs, fmt.Errorf("compliance change monitor %q trigger event: %w", window.MonitorID, eventErr))
			continue
		}
		if appendErr := s.appendLog.Append(ctx, triggerEvent); appendErr != nil {
			_ = store.ReleaseComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner)
			errs = append(errs, fmt.Errorf("compliance change monitor %q trigger append: %w", window.MonitorID, appendErr))
			continue
		}
		if err := store.CompleteComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner, window.Version); err != nil {
			_ = store.ReleaseComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner)
			errs = append(errs, fmt.Errorf("compliance change monitor %q completion: %w", window.MonitorID, err))
			continue
		}
		if err := s.assessments.StartScheduledAssessment(ctx, assessment); err != nil {
			errs = append(errs, fmt.Errorf("compliance change monitor %q start assessment: %w", window.MonitorID, err))
			continue
		}
		enqueued++
	}
	return enqueued, errors.Join(errs...)
}

func occurrenceKey(monitor *ports.ComplianceMonitor) string {
	if monitor == nil {
		return ""
	}
	return "compliance-monitor:" + strings.TrimSpace(monitor.ID) + ":" + monitor.NextRunAt.UTC().Format(time.RFC3339Nano)
}

func changeOccurrenceKey(window *ports.ComplianceChangeWindow) string {
	if window == nil {
		return ""
	}
	return fmt.Sprintf("compliance-change:%s:%d:%s", strings.TrimSpace(window.MonitorID), window.Version, window.OpenedAt.UTC().Format(time.RFC3339Nano))
}

func newOwner() string {
	return "compliance-scheduler-" + strings.TrimPrefix(platformjobs.NewID(), "job-")
}

func occurrenceLeaseOwner(tenantID, planRevisionID, occurrence string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(planRevisionID) + "\x00" + strings.TrimSpace(occurrence)))
	return "compliance-occurrence-" + hex.EncodeToString(sum[:])
}

// ReleasePlanLease releases the overlap guard after the assessment runner has
// reached a terminal state. The runner should call it from a deferred cleanup.
func ReleasePlanLease(ctx context.Context, store ports.ComplianceMonitorStore, job *ports.Job) error {
	if store == nil || job == nil {
		return nil
	}
	planRevisionID, _ := job.Payload["plan_revision_id"].(string)
	owner, _ := job.Payload["plan_lease_owner"].(string)
	if strings.TrimSpace(job.TenantID) == "" || strings.TrimSpace(planRevisionID) == "" || strings.TrimSpace(owner) == "" {
		return nil
	}
	return store.ReleaseCompliancePlanLease(ctx, job.TenantID, planRevisionID, owner)
}

// CompleteRun records the bounded monitor outcome and releases the plan overlap
// lease. The assessment runner calls this once after its own terminal event is
// durable.
func CompleteRun(ctx context.Context, store ports.ComplianceMonitorStore, job *ports.Job, succeeded bool, at time.Time) error {
	if store == nil || job == nil {
		return nil
	}
	monitorID, _ := job.Payload["monitor_id"].(string)
	var errs []error
	if strings.TrimSpace(monitorID) != "" {
		if err := store.RecordComplianceMonitorOutcome(ctx, job.TenantID, monitorID, succeeded, at.UTC()); err != nil {
			errs = append(errs, err)
		}
	}
	if err := ReleasePlanLease(ctx, store, job); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// CompleteAssessmentRun records one terminal monitor occurrence and releases
// its exact plan lease. The completion store makes retries idempotent.
func (s *Service) CompleteAssessmentRun(ctx context.Context, run ports.ComplianceMonitorRun, succeeded bool, at time.Time) error {
	if s == nil || s.store == nil {
		return ErrServiceUnavailable
	}
	store, ok := s.store.(ports.ComplianceMonitorCompletionStore)
	if !ok {
		return ErrServiceUnavailable
	}
	return store.CompleteComplianceMonitorRun(ctx, ports.ComplianceMonitorRunCompletion{Run: run, Succeeded: succeeded, At: at})
}
