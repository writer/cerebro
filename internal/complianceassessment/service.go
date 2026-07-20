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

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const JobKindComplianceAssessment = "compliance_assessment"

const defaultInterruptedRunRecoveryInterval = 15 * time.Second

type Service struct {
	store         Store
	log           ports.AppendLog
	replayer      ports.EventReplayPager
	jobs          *platformjobs.Service
	collector     Collector
	now           func() time.Time
	terminalHook  func(context.Context, ports.ComplianceMonitorRun, bool, time.Time) error
	planEventSink PlanEventSink
}

type PlanEventSink interface {
	ProcessAssessmentPlanEvent(context.Context, *cerebrov1.EventEnvelope) error
}

type PlanLineageResolver interface {
	ResolveAssessmentPlanLineage(context.Context, string, string, string, []string) (compliance.RevisionRef, []compliance.RevisionRef, error)
}

func (s *Service) WithPlanEventSink(sink PlanEventSink) *Service {
	if s != nil {
		s.planEventSink = sink
	}
	return s
}

func (s *Service) WithRunTerminalHook(hook func(context.Context, ports.ComplianceMonitorRun, bool, time.Time) error) *Service {
	if s != nil {
		s.terminalHook = hook
	}
	return s
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
	if expectedVersion > 0 {
		previous, previousErr := s.store.GetPlan(ctx, plan.TenantID, plan.ID)
		if previousErr != nil {
			return AssessmentPlanRevision{}, previousErr
		}
		if previous.Version != expectedVersion {
			return AssessmentPlanRevision{}, ErrAssessmentConflict
		}
		predecessor, refErr := assessmentPlanRevisionRef(previous)
		if refErr != nil {
			return AssessmentPlanRevision{}, refErr
		}
		plan.PredecessorID = previous.RevisionID
		plan.PredecessorRevision = &predecessor
	}
	plan.RevisionModifiedAt = now
	if resolver, ok := s.store.(PlanLineageResolver); ok {
		scopeRevision, implementationRevisions, resolveErr := resolver.ResolveAssessmentPlanLineage(ctx, plan.TenantID, plan.Scope.ProgramID, plan.Scope.ScopeRevisionID, plan.Scope.ImplementationRevisions)
		if resolveErr != nil {
			return AssessmentPlanRevision{}, fmt.Errorf("resolve assessment plan lineage: %w", resolveErr)
		}
		plan.Scope.ExactScopeRevision = &scopeRevision
		plan.Scope.ExactImplementationRevisions = implementationRevisions
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
	predecessorID := plan.RevisionID
	predecessor, err := assessmentPlanRevisionRef(plan)
	if err != nil {
		return AssessmentPlanRevision{}, err
	}
	revisionID, err := compliance.NewRevisionIdentifier(compliance.IdentifierPlan)
	if err != nil {
		return AssessmentPlanRevision{}, err
	}
	plan.PredecessorID = predecessorID
	plan.PredecessorRevision = &predecessor
	plan.RevisionID = revisionID
	plan.Status = PlanPublished
	plan.PublishedAt = CanonicalTime(s.now())
	plan.PublishedBy = strings.TrimSpace(actorID)
	plan.Version++
	plan.RevisionModifiedAt = plan.PublishedAt
	plan.ContentDigest = ""
	digest, err := semanticHash(plan)
	if err != nil {
		return AssessmentPlanRevision{}, err
	}
	plan.ContentDigest = digest
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
	if s.planEventSink != nil {
		if err := s.planEventSink.ProcessAssessmentPlanEvent(ctx, event); err != nil {
			return fmt.Errorf("process assessment plan impact: %w", err)
		}
	}
	if err := s.store.ApplyPlan(ctx, event.GetId(), plan, expectedVersion); err != nil {
		return fmt.Errorf("project assessment plan: %w", err)
	}
	return nil
}

func assessmentPlanRevisionRef(plan AssessmentPlanRevision) (compliance.RevisionRef, error) {
	modifiedAt := CanonicalTime(plan.RevisionModifiedAt)
	if modifiedAt.IsZero() {
		modifiedAt = CanonicalTime(plan.PublishedAt)
	}
	if modifiedAt.IsZero() {
		modifiedAt = CanonicalTime(plan.CreatedAt)
	}
	ref := compliance.NormalizeRevisionRef(compliance.RevisionRef{
		ID: plan.ID, RevisionID: plan.RevisionID, Version: plan.Version,
		ContentDigest: compliance.ContentDigest(plan.ContentDigest), LastModified: modifiedAt,
	})
	if err := ref.Validate(); err != nil {
		return compliance.RevisionRef{}, fmt.Errorf("assessment plan exact revision: %w", err)
	}
	return ref, nil
}

func (s *Service) RequestRun(ctx context.Context, request RunRequest) (AssessmentRun, bool, error) {
	return s.requestRun(ctx, request, true)
}

// RequestRunDeferred records and binds a canonical run without starting its
// job. Monitor scheduling uses it so the trigger event and claim acknowledgement
// are durable before execution begins.
func (s *Service) RequestRunDeferred(ctx context.Context, request RunRequest) (AssessmentRun, bool, error) {
	return s.requestRun(ctx, request, false)
}

func (s *Service) StartRunJob(ctx context.Context, tenantID, runID, jobID string) error {
	if s == nil || s.jobs == nil {
		return ErrRunNotFound
	}
	job, err := s.jobs.Get(ctx, strings.TrimSpace(jobID))
	if err != nil {
		return err
	}
	payloadRunID, _ := job.Payload["run_id"].(string)
	if job.Kind != JobKindComplianceAssessment || job.TenantID != strings.TrimSpace(tenantID) || payloadRunID != strings.TrimSpace(runID) {
		return fmt.Errorf("%w: assessment job binding is invalid", ErrAssessmentConflict)
	}
	s.jobs.StartAsync(ctx, job)
	return nil
}

func (s *Service) requestRun(ctx context.Context, request RunRequest, start bool) (AssessmentRun, bool, error) {
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
		if existing.State == RunQueued && strings.TrimSpace(existing.JobID) == "" {
			bound, _, bindErr := s.bindRunJob(ctx, existing, start)
			return bound, false, bindErr
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
	if err := validateMonitorRun(request.MonitorRun, request.TenantID, request.PlanRevisionID); err != nil {
		return AssessmentRun{}, false, err
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
		MonitorRun: cloneMonitorRun(request.MonitorRun),
	}
	if err := s.appendRun(ctx, workflowevents.EventKindComplianceAssessmentRequested, "assessment_requested", run, 0); err != nil {
		return AssessmentRun{}, false, err
	}
	return s.bindRunJob(ctx, run, start)
}

func (s *Service) bindRunJob(ctx context.Context, run AssessmentRun, start bool) (AssessmentRun, bool, error) {
	job, _, err := s.jobs.Create(ctx, ports.CreateJobRequest{
		Kind: JobKindComplianceAssessment, TenantID: run.TenantID, SubjectType: "assessment_run", SubjectID: run.ID,
		IdempotencyKey: "assessment-run:" + run.ID,
		Payload:        assessmentJobPayload(run),
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
	if start {
		s.jobs.StartAsync(ctx, job)
	}
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
		if _, _, bindErr := s.bindRunJob(ctx, run, true); bindErr != nil {
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
	drain := limit == 0
	if limit == 0 || limit > 500 {
		limit = 100
	}
	total := 0
	var errs []error
	for {
		runs, err := store.ListNonterminalRuns(ctx, limit)
		if err != nil {
			errs = append(errs, err)
			break
		}
		reconciled := 0
		for _, run := range runs {
			changed, reconcileErr := s.reconcileInterruptedRun(ctx, run)
			if reconcileErr != nil {
				errs = append(errs, reconcileErr)
				continue
			}
			if changed {
				reconciled++
				total++
			}
		}
		if !drain || len(runs) < int(limit) || reconciled == 0 {
			break
		}
	}
	return total, errors.Join(errs...)
}

func (s *Service) reconcileInterruptedRun(ctx context.Context, run AssessmentRun) (bool, error) {
	if strings.TrimSpace(run.JobID) == "" {
		return false, nil
	}
	job, err := s.jobs.Get(ctx, run.JobID)
	if err != nil {
		return false, fmt.Errorf("read assessment job %q: %w", run.JobID, err)
	}
	switch job.Status {
	case ports.JobStatusQueued, ports.JobStatusRunning:
		return false, nil
	case ports.JobStatusFailed:
		queued, requeued, retryErr := s.jobs.RequeueRetryable(ctx, job.ID, maxAssessmentJobAttempts)
		if retryErr != nil {
			return false, fmt.Errorf("requeue assessment job %q: %w", job.ID, retryErr)
		}
		if requeued {
			s.jobs.StartAsync(ctx, queued)
			return true, nil
		}
		code := "execution_failed"
		if job.FailureClass == platformjobs.JobFailureRetryable && job.Attempt >= maxAssessmentJobAttempts {
			code = "execution_retry_exhausted"
		}
		if err := s.recordFailedRun(ctx, run, code); err != nil {
			return false, fmt.Errorf("fail assessment run %q: %w", run.ID, err)
		}
		return true, nil
	case ports.JobStatusCancelled:
		if err := s.recordCancelledRun(ctx, run); err != nil {
			return false, fmt.Errorf("cancel assessment run %q: %w", run.ID, err)
		}
		return true, nil
	case ports.JobStatusCompleted:
		if err := s.recordFailedRun(ctx, run, "execution_state_mismatch"); err != nil {
			return false, fmt.Errorf("reconcile completed assessment job %q: %w", job.ID, err)
		}
		return true, nil
	default:
		return false, nil
	}
}

// StartInterruptedRunRecovery continuously reconciles nonterminal assessments
// with failed or cancelled jobs. The first pass runs immediately so callers do
// not wait one interval after a dependency recovers.
func (s *Service) StartInterruptedRunRecovery(ctx context.Context, interval time.Duration, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	if s == nil {
		close(done)
		return done
	}
	if interval <= 0 {
		interval = defaultInterruptedRunRecoveryInterval
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := s.ReconcileInterruptedRuns(ctx, 0); err != nil && ctx.Err() == nil && logf != nil {
				logf("reconcile interrupted assessment runs: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
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
	request.MonitorRun = normalizeMonitorRun(request.MonitorRun)
	return request
}

func normalizeMonitorRun(value *ports.ComplianceMonitorRun) *ports.ComplianceMonitorRun {
	if value == nil {
		return nil
	}
	result := *value
	result.TenantID = strings.TrimSpace(result.TenantID)
	result.MonitorID = strings.TrimSpace(result.MonitorID)
	result.PlanRevisionID = strings.TrimSpace(result.PlanRevisionID)
	result.OccurrenceKey = strings.TrimSpace(result.OccurrenceKey)
	result.LeaseOwner = strings.TrimSpace(result.LeaseOwner)
	return &result
}

func cloneMonitorRun(value *ports.ComplianceMonitorRun) *ports.ComplianceMonitorRun {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func validateMonitorRun(value *ports.ComplianceMonitorRun, tenantID, planRevisionID string) error {
	if value == nil {
		return nil
	}
	if value.TenantID != tenantID || value.PlanRevisionID != planRevisionID || value.MonitorID == "" || value.OccurrenceKey == "" || value.LeaseOwner == "" ||
		len(value.MonitorID) > 512 || len(value.OccurrenceKey) > 1024 || len(value.LeaseOwner) > 512 {
		return fmt.Errorf("%w: monitor run binding is invalid", ErrInvalidResult)
	}
	return nil
}

func (s *Service) completeMonitorRun(ctx context.Context, run AssessmentRun, succeeded bool) error {
	if s == nil || s.terminalHook == nil || run.MonitorRun == nil {
		return nil
	}
	at := run.CompletedAt
	if at.IsZero() {
		at = CanonicalTime(s.now())
	}
	if err := s.terminalHook(context.WithoutCancel(ctx), *run.MonitorRun, succeeded, at); err != nil {
		return platformjobs.Retryable(fmt.Errorf("complete compliance monitor run: %w", err))
	}
	return nil
}

func assessmentJobPayload(run AssessmentRun) map[string]any {
	payload := map[string]any{"run_id": run.ID, "tenant_id": run.TenantID}
	if run.MonitorRun != nil {
		payload["monitor_id"] = run.MonitorRun.MonitorID
		payload["plan_lease_owner"] = run.MonitorRun.LeaseOwner
		payload["plan_lease_occurrence"] = run.MonitorRun.OccurrenceKey
	}
	return payload
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
