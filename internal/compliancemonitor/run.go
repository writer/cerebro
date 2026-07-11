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
	if s == nil || s.store == nil || s.jobs == nil || s.appendLog == nil {
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
		job, _, createErr := s.jobs.Create(ctx, ports.CreateJobRequest{
			Kind:           platformjobs.KindComplianceAssessment,
			TenantID:       monitor.TenantID,
			SubjectType:    subjectType,
			SubjectID:      monitor.ID,
			IdempotencyKey: occurrence,
			Payload: map[string]any{
				"program_id":            monitor.ProgramID,
				"plan_revision_id":      monitor.PlanRevisionID,
				"monitor_id":            monitor.ID,
				"scheduled_for":         monitor.NextRunAt.UTC().Format(time.RFC3339Nano),
				"plan_lease_owner":      leaseOwner,
				"plan_lease_occurrence": occurrence,
			},
		})
		if createErr != nil {
			_ = s.store.ReleaseCompliancePlanLease(context.WithoutCancel(ctx), monitor.TenantID, monitor.PlanRevisionID, leaseOwner)
			_ = s.store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			errs = append(errs, fmt.Errorf("compliance monitor %q enqueue: %w", monitor.ID, createErr))
			continue
		}
		triggerEvent, eventErr := monitorTimeTriggeredEvent(monitor, occurrence, job)
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
		s.jobs.StartAsync(ctx, job)
		enqueued++
	}
	return enqueued, errors.Join(errs...)
}

// RunDueChanges claims coalesced change windows, obtains the same per-plan
// overlap lease used by time monitors, creates one assessment job, and only
// then acknowledges the exact claimed window version.
func (s *Service) RunDueChanges(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.store == nil || s.jobs == nil || s.appendLog == nil {
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
		job, _, createErr := s.jobs.Create(ctx, ports.CreateJobRequest{
			Kind:           platformjobs.KindComplianceAssessment,
			TenantID:       window.TenantID,
			SubjectType:    subjectType,
			SubjectID:      window.MonitorID,
			IdempotencyKey: occurrence,
			Payload: map[string]any{
				"program_id":              window.ProgramID,
				"plan_revision_id":        window.PlanRevisionID,
				"monitor_id":              window.MonitorID,
				"change_window_version":   window.Version,
				"change_window_opened_at": window.OpenedAt.UTC().Format(time.RFC3339Nano),
				"change_signal_count":     window.SignalCount,
				"change_scope_digest":     window.ScopeDigest,
				"plan_lease_owner":        leaseOwner,
				"plan_lease_occurrence":   occurrence,
			},
		})
		if createErr != nil {
			_ = store.ReleaseCompliancePlanLease(context.WithoutCancel(ctx), window.TenantID, window.PlanRevisionID, leaseOwner)
			_ = store.ReleaseComplianceChangeWindow(context.WithoutCancel(ctx), window.TenantID, window.MonitorID, owner)
			errs = append(errs, fmt.Errorf("compliance change monitor %q enqueue: %w", window.MonitorID, createErr))
			continue
		}
		triggerEvent, eventErr := monitorChangeTriggeredEvent(window, occurrence, job)
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
		s.jobs.StartAsync(ctx, job)
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
