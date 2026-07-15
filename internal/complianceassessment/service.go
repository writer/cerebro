package complianceassessment

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

	"github.com/writer/cerebro/internal/compliance"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const JobKindComplianceAssessment = "compliance_assessment"

type Service struct {
	store     Store
	log       ports.AppendLog
	replayer  ports.EventReplayPager
	jobs      *platformjobs.Service
	collector Collector
	now       func() time.Time
}

func NewAssessmentService(store Store, log ports.AppendLog, jobs *platformjobs.Service, collector Collector) *Service {
	return &Service{store: store, log: log, jobs: jobs, collector: collector, now: func() time.Time { return time.Now().UTC() }}
}

// WithEventReplayPager enables append-first projection recovery. The pager is
// optional so focused domain callers can keep using the service without a
// production append-log runtime.
func (s *Service) WithEventReplayPager(replayer ports.EventReplayPager) *Service {
	if s != nil {
		s.replayer = replayer
	}
	return s
}

func (s *Service) RecordPlan(ctx context.Context, plan AssessmentPlanRevision, actorID string, expectedVersion uint64) (AssessmentPlanRevision, error) {
	if s == nil || s.store == nil || s.log == nil {
		return AssessmentPlanRevision{}, ErrPlanNotFound
	}
	now := CanonicalTime(s.now())
	actorID = strings.TrimSpace(actorID)
	plan = normalizePlan(plan)
	if plan.ID == "" {
		id, err := compliance.NewIdentifier(compliance.IdentifierPlan)
		if err != nil {
			return AssessmentPlanRevision{}, err
		}
		plan.ID = id
	}
	if plan.RevisionID == "" {
		id, err := compliance.NewRevisionIdentifier(compliance.IdentifierPlan)
		if err != nil {
			return AssessmentPlanRevision{}, err
		}
		plan.RevisionID = id
	}
	if plan.Version == 0 {
		plan.Version = expectedVersion + 1
	}
	if plan.Status == "" {
		plan.Status = PlanDraft
	}
	if plan.CreatedAt.IsZero() {
		plan.CreatedAt = now
	}
	if plan.CreatedBy == "" {
		plan.CreatedBy = actorID
	}
	plan.ContentDigest = ""
	digest, err := semanticHash(plan)
	if err != nil {
		return AssessmentPlanRevision{}, err
	}
	plan.ContentDigest = digest
	if err := validatePlan(plan); err != nil {
		return AssessmentPlanRevision{}, err
	}
	return plan, s.appendPlan(ctx, workflowevents.EventKindCompliancePlanRevisionRecorded, "plan_revision_recorded", plan, expectedVersion, actorID)
}

func (s *Service) PublishPlan(ctx context.Context, tenantID, planID, actorID string, expectedVersion uint64) (AssessmentPlanRevision, error) {
	plan, err := s.store.GetPlan(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(planID))
	if err != nil {
		return AssessmentPlanRevision{}, err
	}
	if plan.Version != expectedVersion || plan.Status != PlanDraft {
		return AssessmentPlanRevision{}, ErrAssessmentConflict
	}
	plan.Status = PlanPublished
	plan.PublishedAt = CanonicalTime(s.now())
	plan.PublishedBy = strings.TrimSpace(actorID)
	plan.Version++
	if err := validatePlan(plan); err != nil {
		return AssessmentPlanRevision{}, err
	}
	return plan, s.appendPlan(ctx, workflowevents.EventKindCompliancePlanPublished, "plan_published", plan, expectedVersion, actorID)
}

func (s *Service) appendPlan(ctx context.Context, kind, operation string, plan AssessmentPlanRevision, expectedVersion uint64, actorID string) error {
	payload, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	version, err := aggregateVersion(plan.Version)
	if err != nil {
		return err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: kind, TenantID: plan.TenantID, AggregateType: "assessment_plan", AggregateID: plan.ID,
		RevisionID: plan.RevisionID, AggregateVersion: version, Operation: operation,
		ContentDigest: plan.ContentDigest, PayloadJSON: string(payload), ActorID: actorID,
		RecordedAt: CanonicalTime(s.now()).Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return fmt.Errorf("append assessment plan: %w", err)
	}
	if err := s.store.ApplyPlan(ctx, event.GetId(), plan, expectedVersion); err != nil {
		return fmt.Errorf("project assessment plan: %w", err)
	}
	return nil
}

func (s *Service) RequestRun(ctx context.Context, request RunRequest) (AssessmentRun, bool, error) {
	if s == nil || s.store == nil || s.log == nil || s.jobs == nil {
		return AssessmentRun{}, false, ErrRunNotFound
	}
	request = normalizeRunRequest(request)
	requestHash, err := semanticHash(request)
	if err != nil {
		return AssessmentRun{}, false, err
	}
	if existing, findErr := s.store.FindRunByIdempotency(ctx, request.TenantID, request.IdempotencyKey); findErr == nil {
		if existing.RequestHash != requestHash {
			return AssessmentRun{}, false, ports.ErrJobIdempotencyConflict
		}
		return existing, false, nil
	} else if !errors.Is(findErr, ErrRunNotFound) {
		return AssessmentRun{}, false, findErr
	}
	plan, err := s.store.GetPlan(ctx, request.TenantID, request.PlanRevisionID)
	if err != nil {
		return AssessmentRun{}, false, err
	}
	if plan.Status != PlanPublished || plan.RevisionID != request.PlanRevisionID {
		return AssessmentRun{}, false, ErrAssessmentConflict
	}
	if request.PeriodStart.IsZero() || request.PeriodEnd.IsZero() || request.PeriodEnd.Before(request.PeriodStart) || request.IdempotencyKey == "" || request.RequestedBy == "" {
		return AssessmentRun{}, false, fmt.Errorf("%w: run request is incomplete", ErrInvalidResult)
	}
	runID, err := compliance.NewIdentifier(compliance.IdentifierRun)
	if err != nil {
		return AssessmentRun{}, false, err
	}
	run := AssessmentRun{
		ID: runID, TenantID: request.TenantID, ProgramID: plan.Scope.ProgramID,
		ScopeRevisionID: plan.Scope.ScopeRevisionID, PlanRevisionID: plan.RevisionID,
		State: RunQueued, Version: 1, PeriodStart: request.PeriodStart, PeriodEnd: request.PeriodEnd,
		RequestedAt: CanonicalTime(s.now()), RequestedBy: request.RequestedBy,
		RequestHash: requestHash, IdempotencyKey: request.IdempotencyKey, BaselineRunID: request.BaselineRunID,
	}
	if err := s.appendRun(ctx, workflowevents.EventKindComplianceAssessmentRequested, "assessment_requested", run, 0); err != nil {
		return AssessmentRun{}, false, err
	}
	return s.bindRunJob(ctx, run)
}

func (s *Service) bindRunJob(ctx context.Context, run AssessmentRun) (AssessmentRun, bool, error) {
	job, _, err := s.jobs.Create(ctx, ports.CreateJobRequest{
		Kind: JobKindComplianceAssessment, TenantID: run.TenantID, SubjectType: "assessment_run", SubjectID: run.ID,
		IdempotencyKey: "assessment-run:" + run.ID,
		Payload:        map[string]any{"run_id": run.ID, "tenant_id": run.TenantID},
	})
	if err != nil {
		return run, false, err
	}
	expectedVersion := run.Version
	run.JobID = job.ID
	run.Version++
	if err := s.appendRun(ctx, workflowevents.EventKindComplianceAssessmentJobBound, "assessment_job_bound", run, expectedVersion); err != nil {
		return run, false, err
	}
	s.jobs.StartAsync(ctx, job)
	return run, true, nil
}

func (s *Service) ReconcileUnboundRuns(ctx context.Context, limit uint32) (int, error) {
	runs, err := s.store.ListUnboundRuns(ctx, limit)
	if err != nil {
		return 0, err
	}
	bound := 0
	var errs []error
	for _, run := range runs {
		if _, _, bindErr := s.bindRunJob(ctx, run); bindErr != nil {
			errs = append(errs, fmt.Errorf("bind assessment run %q: %w", run.ID, bindErr))
			continue
		}
		bound++
	}
	return bound, errors.Join(errs...)
}

// ReconcileInterruptedRuns aligns nonterminal assessments with their durable
// jobs after projection recovery. Retryable attempts are requeued explicitly;
// cancelled, exhausted, and permanently failed jobs become terminal runs.
func (s *Service) ReconcileInterruptedRuns(ctx context.Context, limit uint32) (int, error) {
	store, ok := s.store.(NonterminalRunStore)
	if !ok || s.jobs == nil {
		return 0, nil
	}
	runs, err := store.ListNonterminalRuns(ctx, limit)
	if err != nil {
		return 0, err
	}
	reconciled := 0
	var errs []error
	for _, run := range runs {
		if strings.TrimSpace(run.JobID) == "" {
			continue
		}
		job, getErr := s.jobs.Get(ctx, run.JobID)
		if getErr != nil {
			errs = append(errs, fmt.Errorf("read assessment job %q: %w", run.JobID, getErr))
			continue
		}
		switch job.Status {
		case ports.JobStatusQueued, ports.JobStatusRunning:
			continue
		case ports.JobStatusFailed:
			if queued, requeued, retryErr := s.jobs.RequeueRetryable(ctx, job.ID, maxAssessmentJobAttempts); retryErr != nil {
				errs = append(errs, fmt.Errorf("requeue assessment job %q: %w", job.ID, retryErr))
				continue
			} else if requeued {
				s.jobs.StartAsync(ctx, queued)
				reconciled++
				continue
			}
			code := "execution_failed"
			if job.FailureClass == platformjobs.JobFailureRetryable && job.Attempt >= maxAssessmentJobAttempts {
				code = "execution_retry_exhausted"
			}
			if terminalErr := s.recordFailedRun(ctx, run, code); terminalErr != nil {
				errs = append(errs, fmt.Errorf("fail assessment run %q: %w", run.ID, terminalErr))
				continue
			}
			reconciled++
		case ports.JobStatusCancelled:
			if terminalErr := s.recordCancelledRun(ctx, run); terminalErr != nil {
				errs = append(errs, fmt.Errorf("cancel assessment run %q: %w", run.ID, terminalErr))
				continue
			}
			reconciled++
		case ports.JobStatusCompleted:
			if terminalErr := s.recordFailedRun(ctx, run, "execution_state_mismatch"); terminalErr != nil {
				errs = append(errs, fmt.Errorf("reconcile completed assessment job %q: %w", job.ID, terminalErr))
				continue
			}
			reconciled++
		}
	}
	return reconciled, errors.Join(errs...)
}

func (s *Service) appendRun(ctx context.Context, kind, operation string, run AssessmentRun, expectedVersion uint64) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	digest, err := semanticHash(run)
	if err != nil {
		return err
	}
	version, err := aggregateVersion(run.Version)
	if err != nil {
		return err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: kind, TenantID: run.TenantID, AggregateType: "assessment_run", AggregateID: run.ID,
		RevisionID: fmt.Sprintf("%s-v%d", run.ID, run.Version), AggregateVersion: version,
		Operation: operation, ContentDigest: digest, PayloadJSON: string(payload), ActorID: run.RequestedBy,
		RecordedAt: CanonicalTime(s.now()).Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return fmt.Errorf("append assessment run: %w", err)
	}
	if err := s.store.ApplyRun(ctx, event.GetId(), run, expectedVersion); err != nil {
		return fmt.Errorf("project assessment run: %w", err)
	}
	return nil
}

func normalizeRunRequest(request RunRequest) RunRequest {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.PlanRevisionID = strings.TrimSpace(request.PlanRevisionID)
	request.BaselineRunID = strings.TrimSpace(request.BaselineRunID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.RequestedBy = strings.TrimSpace(request.RequestedBy)
	request.PeriodStart = CanonicalTime(request.PeriodStart)
	request.PeriodEnd = CanonicalTime(request.PeriodEnd)
	return request
}

func semanticHash(value any) (string, error) {
	payload, err := canonicalBytes(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func aggregateVersion(value uint64) (int64, error) {
	if value == 0 || value > math.MaxInt64 {
		return 0, ErrAssessmentConflict
	}
	return int64(value), nil
}
