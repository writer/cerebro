package reportschedule

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
	claimBatch  = uint32(50)
	claimTTL    = 2 * time.Minute
	subjectType = "report_schedule"
)

// RunDue claims due occurrences, creates their idempotent jobs, and advances a
// schedule only after job creation succeeds.
func RunDue(ctx context.Context, store ports.ReportScheduleStore, jobs *platformjobs.Service, now time.Time) (int, error) {
	if store == nil || jobs == nil {
		return 0, nil
	}
	now = now.UTC()
	owner := newClaimOwner()
	due, err := store.ClaimDueReportSchedules(ctx, now, owner, claimTTL, claimBatch)
	if err != nil {
		return 0, err
	}
	enqueued := 0
	var errs []error
	for _, schedule := range due {
		if err := enqueue(ctx, jobs, schedule); err != nil {
			_ = store.ReleaseReportScheduleClaim(context.WithoutCancel(ctx), schedule.ID, owner)
			errs = append(errs, fmt.Errorf("report schedule %q: %w", schedule.ID, err))
			continue
		}
		if err := store.CompleteReportScheduleClaim(context.WithoutCancel(ctx), schedule.ID, owner, schedule.NextRunAt, now); err != nil {
			errs = append(errs, fmt.Errorf("report schedule %q completion: %w", schedule.ID, err))
			continue
		}
		enqueued++
	}
	return enqueued, errors.Join(errs...)
}

func enqueue(ctx context.Context, jobs *platformjobs.Service, schedule *ports.ReportSchedule) error {
	if schedule == nil {
		return nil
	}
	parameters := make(map[string]any, len(schedule.Parameters)+1)
	for key, value := range schedule.Parameters {
		parameters[key] = value
	}
	if tenantID := strings.TrimSpace(schedule.TenantID); tenantID != "" {
		if _, ok := parameters["tenant_id"]; !ok {
			parameters["tenant_id"] = tenantID
		}
	}
	job, created, err := jobs.Create(ctx, ports.CreateJobRequest{
		Kind:           platformjobs.KindReportRun,
		TenantID:       schedule.TenantID,
		SubjectType:    subjectType,
		SubjectID:      schedule.ID,
		IdempotencyKey: occurrenceKey(schedule),
		Payload: map[string]any{
			"report_id":     schedule.ReportID,
			"parameters":    parameters,
			"scheduled_for": schedule.NextRunAt.UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return err
	}
	if created {
		jobs.StartAsync(ctx, job)
	}
	return nil
}

func occurrenceKey(schedule *ports.ReportSchedule) string {
	if schedule == nil {
		return ""
	}
	return "report-schedule:" + strings.TrimSpace(schedule.ID) + ":" + schedule.NextRunAt.UTC().Format(time.RFC3339Nano)
}

func newClaimOwner() string {
	return "scheduler-" + strings.TrimPrefix(platformjobs.NewID(), "job-")
}
