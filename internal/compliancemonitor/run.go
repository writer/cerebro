package compliancemonitor

import (
	"context"
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
func RunDue(ctx context.Context, store ports.ComplianceMonitorStore, jobs *platformjobs.Service, now time.Time) (int, error) {
	if store == nil || jobs == nil {
		return 0, nil
	}
	now = now.UTC()
	owner := newOwner()
	due, err := store.ClaimDueComplianceMonitors(ctx, now, owner, claimTTL, claimBatch)
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
		if err := store.AcquireCompliancePlanLease(ctx, monitor.TenantID, monitor.PlanRevisionID, owner, occurrence, now, planLeaseTTL); err != nil {
			_ = store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			if !errors.Is(err, ports.ErrComplianceMonitorOverlap) {
				errs = append(errs, fmt.Errorf("compliance monitor %q plan lease: %w", monitor.ID, err))
			}
			continue
		}
		job, created, createErr := jobs.Create(ctx, ports.CreateJobRequest{
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
				"plan_lease_owner":      owner,
				"plan_lease_occurrence": occurrence,
			},
		})
		if createErr != nil {
			_ = store.ReleaseCompliancePlanLease(context.WithoutCancel(ctx), monitor.TenantID, monitor.PlanRevisionID, owner)
			_ = store.ReleaseComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner)
			errs = append(errs, fmt.Errorf("compliance monitor %q enqueue: %w", monitor.ID, createErr))
			continue
		}
		if err := store.CompleteComplianceMonitorClaim(context.WithoutCancel(ctx), monitor.TenantID, monitor.ID, owner, monitor.NextRunAt, now); err != nil {
			errs = append(errs, fmt.Errorf("compliance monitor %q completion: %w", monitor.ID, err))
			continue
		}
		if created {
			jobs.StartAsync(ctx, job)
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

func newOwner() string {
	return "compliance-scheduler-" + strings.TrimPrefix(platformjobs.NewID(), "job-")
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
