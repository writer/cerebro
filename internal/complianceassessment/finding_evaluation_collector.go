package complianceassessment

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const findingEvaluationCollectorRevision = "finding-evaluation-collector/v1"

// AssessmentPlanReader loads the immutable plan revision pinned by a run.
type AssessmentPlanReader interface {
	GetPlan(context.Context, string, string) (AssessmentPlanRevision, error)
}

// SourceRuntimeLister resolves runtime ownership through a tenant-filtered read.
type SourceRuntimeLister interface {
	ListSourceRuntimes(context.Context, ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error)
}

// FindingEvaluationRunLister loads durable rule-evaluation envelopes.
type FindingEvaluationRunLister interface {
	ListFindingEvaluationRuns(context.Context, ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error)
}

// FindingEvaluationCollector converts bounded, durable finding-evaluation runs
// into point-in-time objective results and reproducible collection receipts.
type FindingEvaluationCollector struct {
	plans       AssessmentPlanReader
	runtimes    SourceRuntimeLister
	evaluations FindingEvaluationRunLister
	now         func() time.Time
}

func NewFindingEvaluationCollector(plans AssessmentPlanReader, runtimes SourceRuntimeLister, evaluations FindingEvaluationRunLister) *FindingEvaluationCollector {
	if plans == nil || runtimes == nil || evaluations == nil {
		return nil
	}
	return &FindingEvaluationCollector{
		plans:       plans,
		runtimes:    runtimes,
		evaluations: evaluations,
		now:         func() time.Time { return time.Now().UTC() },
	}
}

func (c *FindingEvaluationCollector) Collect(ctx context.Context, run AssessmentRun) (InputManifest, []ObjectiveResult, error) {
	if c == nil || c.plans == nil || c.runtimes == nil || c.evaluations == nil || c.now == nil {
		return InputManifest{}, nil, fmt.Errorf("%w: finding evaluation collector is not configured", ErrIncompleteInput)
	}
	plan, err := c.plans.GetPlan(ctx, strings.TrimSpace(run.TenantID), strings.TrimSpace(run.PlanRevisionID))
	if err != nil {
		return InputManifest{}, nil, fmt.Errorf("load assessment plan: %w", err)
	}
	plan = normalizePlan(plan)
	if err := validatePlan(plan); err != nil {
		return InputManifest{}, nil, err
	}
	if plan.Status != PlanPublished || plan.TenantID != strings.TrimSpace(run.TenantID) || plan.RevisionID != strings.TrimSpace(run.PlanRevisionID) ||
		plan.Scope.ProgramID != strings.TrimSpace(run.ProgramID) || plan.Scope.ScopeRevisionID != strings.TrimSpace(run.ScopeRevisionID) {
		return InputManifest{}, nil, fmt.Errorf("%w: assessment run and plan binding do not match", ErrIncompleteInput)
	}

	cutoff := CanonicalTime(c.now())
	if run.InputManifest != nil && !run.InputManifest.CollectionCutoff.IsZero() {
		cutoff = CanonicalTime(run.InputManifest.CollectionCutoff)
	}
	periodStart := CanonicalTime(run.PeriodStart)
	periodEnd := CanonicalTime(run.PeriodEnd)
	if periodStart.IsZero() || periodEnd.IsZero() || periodEnd.Before(periodStart) || periodEnd.After(cutoff) {
		return InputManifest{}, nil, fmt.Errorf("%w: assessment period is outside the collection cutoff", ErrIncompleteInput)
	}

	orderedTasks, err := orderedFindingEvaluationTasks(plan.Execution)
	if err != nil {
		return InputManifest{}, nil, err
	}
	runtimeIDs := make([]string, 0, MaxFindingEvaluationBindings)
	for _, task := range orderedTasks {
		runtimeIDs = append(runtimeIDs, task.RuntimeIDs...)
	}
	runtimeIDs = normalizedStrings(runtimeIDs)
	resolvedRuntimes, err := c.runtimes.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{
		TenantID:   run.TenantID,
		RuntimeIDs: runtimeIDs,
		Limit:      uint32(len(runtimeIDs)),
	})
	if err != nil {
		return InputManifest{}, nil, fmt.Errorf("list assessment source runtimes: %w", err)
	}
	if err := validateResolvedRuntimes(run.TenantID, runtimeIDs, resolvedRuntimes); err != nil {
		return InputManifest{}, nil, err
	}

	scopeDigest, err := semanticHash(plan.Scope)
	if err != nil {
		return InputManifest{}, nil, err
	}
	objectiveDigest, err := semanticHash(plan.Scope.ObjectiveIDs)
	if err != nil {
		return InputManifest{}, nil, err
	}
	mappingDigest, err := semanticHash(orderedTasks)
	if err != nil {
		return InputManifest{}, nil, err
	}
	manifest := InputManifest{
		ProgramID:                  run.ProgramID,
		ScopeRevisionID:            run.ScopeRevisionID,
		PlanRevisionID:             run.PlanRevisionID,
		PeriodStart:                periodStart,
		PeriodEnd:                  periodEnd,
		CollectionCutoff:           cutoff,
		RequestedScopeDigest:       scopeDigest,
		ResolvedObjectiveSetDigest: objectiveDigest,
		MappingSetDigest:           mappingDigest,
		Revisions: []ManifestRevision{{
			Kind: "plan", ID: plan.ID, RevisionID: plan.RevisionID,
			Version: plan.Version, Digest: plan.ContentDigest,
		}},
	}
	results := make([]ObjectiveResult, 0, len(orderedTasks))
	for _, task := range orderedTasks {
		result, receipts, evaluationRunIDs, collectErr := c.collectTask(ctx, plan, run, task, cutoff)
		if collectErr != nil {
			return InputManifest{}, nil, collectErr
		}
		manifest.Receipts = append(manifest.Receipts, receipts...)
		manifest.EvaluationRunIDs = append(manifest.EvaluationRunIDs, evaluationRunIDs...)
		results = append(results, result)
	}
	manifest = NormalizeManifest(manifest)
	if err := ValidateInputManifest(manifest); err != nil {
		return InputManifest{}, nil, err
	}
	for index := range results {
		results[index] = NormalizeResult(results[index])
		if err := ValidateObjectiveResult(results[index]); err != nil {
			return InputManifest{}, nil, fmt.Errorf("objective result %q: %w", results[index].ObjectiveID, err)
		}
	}
	return manifest, results, nil
}

func orderedFindingEvaluationTasks(execution PlanExecution) ([]PlanTask, error) {
	byID := make(map[string]PlanTask, len(execution.Tasks))
	for _, task := range execution.Tasks {
		if task.Kind != PlanTaskKindFindingEvaluation {
			return nil, fmt.Errorf("%w: task %q requires unsupported collector %q", ErrIncompleteInput, task.ID, task.Kind)
		}
		byID[task.ID] = task
	}
	ordered := make([]PlanTask, 0, len(execution.OrderedTaskIDs))
	for _, taskID := range execution.OrderedTaskIDs {
		task, ok := byID[taskID]
		if !ok {
			return nil, fmt.Errorf("%w: ordered task %q is not defined", ErrIncompleteInput, taskID)
		}
		ordered = append(ordered, task)
	}
	return ordered, nil
}

func validateResolvedRuntimes(tenantID string, expectedIDs []string, values []*cerebrov1.SourceRuntime) error {
	expected := make(map[string]struct{}, len(expectedIDs))
	for _, runtimeID := range expectedIDs {
		expected[runtimeID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(values))
	for _, runtime := range values {
		if runtime == nil || strings.TrimSpace(runtime.GetTenantId()) != strings.TrimSpace(tenantID) {
			return fmt.Errorf("%w: source runtime ownership could not be verified", ErrIncompleteInput)
		}
		runtimeID := strings.TrimSpace(runtime.GetId())
		if _, ok := expected[runtimeID]; !ok {
			return fmt.Errorf("%w: source runtime response exceeded the requested scope", ErrIncompleteInput)
		}
		if _, ok := seen[runtimeID]; ok {
			return fmt.Errorf("%w: source runtime %q was returned more than once", ErrIncompleteInput, runtimeID)
		}
		seen[runtimeID] = struct{}{}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: one or more source runtimes are unavailable in the assessment tenant", ErrIncompleteInput)
	}
	return nil
}

type taskCollectionState struct {
	evaluationRunIDs []string
	findingIDs       []string
	reasons          []ReasonCode
	actions          []NextAction
	evidenceState    EvidenceState
	incomplete       bool
}

func (c *FindingEvaluationCollector) collectTask(ctx context.Context, plan AssessmentPlanRevision, assessmentRun AssessmentRun, task PlanTask, cutoff time.Time) (ObjectiveResult, []CollectionReceipt, []string, error) {
	maxAge, err := time.ParseDuration(task.MaxAge)
	if err != nil || maxAge <= 0 {
		return ObjectiveResult{}, nil, nil, fmt.Errorf("%w: task %q has invalid max_age", ErrIncompleteInput, task.ID)
	}
	state := taskCollectionState{evidenceState: EvidenceSufficient}
	receipts := make([]CollectionReceipt, 0, len(task.RuntimeIDs))
	for _, runtimeID := range task.RuntimeIDs {
		query := findingEvaluationQuery{
			TaskID: task.ID, RuntimeID: runtimeID, RuleID: task.RuleID,
			PeriodStart: assessmentRun.PeriodStart, PeriodEnd: assessmentRun.PeriodEnd,
			Cutoff: cutoff, MaxAge: task.MaxAge,
		}
		queryDigest, hashErr := semanticHash(query)
		if hashErr != nil {
			return ObjectiveResult{}, nil, nil, hashErr
		}
		runs, listErr := c.evaluations.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{
			RuntimeID: runtimeID,
			RuleID:    task.RuleID,
			Status:    "completed",
			Limit:     1,
		})
		if listErr != nil {
			return ObjectiveResult{}, nil, nil, fmt.Errorf("list finding evaluations for task %q runtime %q: %w", task.ID, runtimeID, listErr)
		}
		receipt, collected, receiptErr := evaluationReceipt(task, runtimeID, queryDigest, runs, assessmentRun.PeriodStart, cutoff, maxAge)
		if receiptErr != nil {
			return ObjectiveResult{}, nil, nil, receiptErr
		}
		receipts = append(receipts, receipt)
		state.evaluationRunIDs = append(state.evaluationRunIDs, collected.evaluationRunIDs...)
		state.findingIDs = append(state.findingIDs, collected.findingIDs...)
		if collected.incomplete {
			state.incomplete = true
			state.reasons = append(state.reasons, collected.reasons...)
			state.actions = append(state.actions, collected.actions...)
			state.evidenceState = strongerEvidenceFailure(state.evidenceState, collected.evidenceState)
		}
	}
	state.evaluationRunIDs = normalizedStrings(state.evaluationRunIDs)
	state.findingIDs = normalizedStrings(state.findingIDs)
	state.reasons = normalizedEnums(state.reasons)
	state.actions = normalizedEnums(state.actions)
	result, err := taskObjectiveResult(plan, task, cutoff, state)
	if err != nil {
		return ObjectiveResult{}, nil, nil, err
	}
	return result, receipts, state.evaluationRunIDs, nil
}

type findingEvaluationQuery struct {
	TaskID      string    `json:"task_id"`
	RuntimeID   string    `json:"runtime_id"`
	RuleID      string    `json:"rule_id"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Cutoff      time.Time `json:"cutoff"`
	MaxAge      string    `json:"max_age"`
}

type findingEvaluationPage struct {
	ID               string    `json:"id"`
	RuntimeID        string    `json:"runtime_id"`
	RuleID           string    `json:"rule_id"`
	Status           string    `json:"status"`
	EventLimit       uint32    `json:"event_limit"`
	EventsEvaluated  uint32    `json:"events_evaluated"`
	EventsProcessed  uint32    `json:"events_processed"`
	FindingsUpserted uint32    `json:"findings_upserted"`
	FindingsEmitted  uint32    `json:"findings_emitted"`
	FindingIDs       []string  `json:"finding_ids"`
	FinishedAt       time.Time `json:"finished_at"`
	GraphRule        bool      `json:"graph_rule"`
	GraphRowsRead    uint32    `json:"graph_rows_read"`
}

func evaluationReceipt(task PlanTask, runtimeID, queryDigest string, runs []*cerebrov1.FindingEvaluationRun, periodStart, cutoff time.Time, maxAge time.Duration) (CollectionReceipt, taskCollectionState, error) {
	kind := PlanTaskKindFindingEvaluation + ":" + task.ID
	zero := uint64(0)
	missingDigest, err := semanticHash(struct {
		QueryDigest string `json:"query_digest"`
		State       string `json:"state"`
	}{QueryDigest: queryDigest, State: "missing"})
	if err != nil {
		return CollectionReceipt{}, taskCollectionState{}, err
	}
	if len(runs) == 0 {
		return CollectionReceipt{
				Kind: kind, RuntimeID: runtimeID, QueryDigest: queryDigest, PageIndex: 0,
				ExpectedTotal: &zero, Cutoff: cutoff, Completeness: CollectionUnknown, PageDigest: missingDigest,
			}, taskCollectionState{
				incomplete: true, evidenceState: EvidenceMissing,
				reasons: []ReasonCode{ReasonEvidenceMissing}, actions: []NextAction{ActionCollectEvidence},
			}, nil
	}
	if len(runs) != 1 || runs[0] == nil {
		return CollectionReceipt{}, taskCollectionState{}, fmt.Errorf("%w: finding evaluation query for task %q returned an invalid page", ErrIncompleteInput, task.ID)
	}
	run := runs[0]
	if strings.TrimSpace(run.GetId()) == "" || strings.TrimSpace(run.GetRuntimeId()) != runtimeID || strings.TrimSpace(run.GetRuleId()) != task.RuleID || strings.TrimSpace(run.GetStatus()) != "completed" || run.GetFinishedAt() == nil || run.GetFinishedAt().CheckValid() != nil {
		return CollectionReceipt{}, taskCollectionState{}, fmt.Errorf("%w: finding evaluation run for task %q is invalid", ErrIncompleteInput, task.ID)
	}
	finishedAt := CanonicalTime(run.GetFinishedAt().AsTime())
	findingIDs := normalizedStrings(run.GetFindingIds())
	if len(findingIDs) != len(run.GetFindingIds()) || uint64(len(findingIDs)) != uint64(run.GetFindingsUpserted()) || run.GetFindingsEmitted() != run.GetFindingsUpserted() {
		return CollectionReceipt{}, taskCollectionState{}, fmt.Errorf("%w: finding evaluation run %q has inconsistent finding counts", ErrIncompleteInput, run.GetId())
	}
	population, truncated, err := evaluationPopulation(run)
	if err != nil {
		return CollectionReceipt{}, taskCollectionState{}, err
	}
	pageDigest, err := semanticHash(findingEvaluationPage{
		ID: run.GetId(), RuntimeID: run.GetRuntimeId(), RuleID: run.GetRuleId(), Status: run.GetStatus(),
		EventLimit: run.GetEventLimit(), EventsEvaluated: run.GetEventsEvaluated(), EventsProcessed: run.GetEventsProcessed(),
		FindingsUpserted: run.GetFindingsUpserted(), FindingsEmitted: run.GetFindingsEmitted(), FindingIDs: findingIDs,
		FinishedAt: finishedAt, GraphRule: run.GetGraphRule(), GraphRowsRead: run.GetGraphRowsRead(),
	})
	if err != nil {
		return CollectionReceipt{}, taskCollectionState{}, err
	}
	expected := population
	receipt := CollectionReceipt{
		Kind: kind, RuntimeID: runtimeID, QueryDigest: queryDigest, PageIndex: 0,
		RawCount: population, Deduplicated: population, Included: population, ExpectedTotal: &expected,
		Watermark: finishedAt, Cutoff: cutoff, Completeness: CollectionComplete, PageDigest: pageDigest,
	}
	collected := taskCollectionState{
		evaluationRunIDs: []string{run.GetId()},
		findingIDs:       findingIDs,
		evidenceState:    EvidenceSufficient,
	}
	if finishedAt.Before(CanonicalTime(periodStart)) || cutoff.Sub(finishedAt) > maxAge {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceStale
		collected.reasons = []ReasonCode{ReasonEvidenceStale}
		collected.actions = []NextAction{ActionRefreshEvidence}
	} else if finishedAt.After(cutoff) {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceUntrusted
		collected.reasons = []ReasonCode{ReasonEvidenceInvalid}
		collected.actions = []NextAction{ActionReview}
	} else if truncated {
		receipt.Completeness = CollectionTruncated
		collected.incomplete = true
		collected.evidenceState = EvidenceIncomplete
		collected.reasons = []ReasonCode{ReasonCoverageIncomplete}
		collected.actions = []NextAction{ActionCollectEvidence}
	}
	return receipt, collected, nil
}

func evaluationPopulation(run *cerebrov1.FindingEvaluationRun) (uint64, bool, error) {
	if run.GraphRule == nil {
		return 0, false, fmt.Errorf("%w: finding evaluation run %q does not identify its rule type", ErrIncompleteInput, run.GetId())
	}
	if run.GetGraphRule() {
		if run.GraphRowsRead == nil || run.GetEventLimit() != 0 || run.GetEventsEvaluated() != 0 || run.GetEventsProcessed() != 0 {
			return 0, false, fmt.Errorf("%w: graph evaluation run %q has inconsistent population metadata", ErrIncompleteInput, run.GetId())
		}
		population := uint64(run.GetGraphRowsRead())
		return population, population >= uint64(ports.MaxCypherQueryRows), nil
	}
	if run.GetEventLimit() == 0 || run.GetEventsEvaluated() != run.GetEventsProcessed() {
		return 0, false, fmt.Errorf("%w: event evaluation run %q has inconsistent population metadata", ErrIncompleteInput, run.GetId())
	}
	population := uint64(run.GetEventsProcessed())
	return population, population >= uint64(run.GetEventLimit()), nil
}

func taskObjectiveResult(plan AssessmentPlanRevision, task PlanTask, cutoff time.Time, state taskCollectionState) (ObjectiveResult, error) {
	identityDigest, err := semanticHash(struct {
		PlanRevisionID  string    `json:"plan_revision_id"`
		TaskID          string    `json:"task_id"`
		ObjectiveID     string    `json:"objective_id"`
		EvaluationRunID []string  `json:"evaluation_run_ids"`
		Cutoff          time.Time `json:"cutoff"`
	}{
		PlanRevisionID: plan.RevisionID, TaskID: task.ID, ObjectiveID: task.ObjectiveID,
		EvaluationRunID: state.evaluationRunIDs, Cutoff: cutoff,
	})
	if err != nil {
		return ObjectiveResult{}, err
	}
	result := ObjectiveResult{
		ID:         "assessment-result-" + strings.TrimPrefix(identityDigest, "sha256:")[:24],
		ControlRef: task.ControlRef, ObjectiveID: task.ObjectiveID, ScopeState: ScopeInScope,
		DesignState: DesignUnknown, OperatingEffectivenessState: OperatingNotTested,
		DispositionState: DispositionNone, AuditorState: AuditorNotReviewed,
		EvidenceIDs: state.evaluationRunIDs, FindingIDs: state.findingIDs, SourceRuntimeIDs: task.RuntimeIDs,
		EvaluatorRevision: findingEvaluationCollectorRevision, EvaluatedAt: cutoff,
	}
	if state.incomplete {
		result.AutomatedOutcome = OutcomeIndeterminate
		result.EvidenceState = state.evidenceState
		result.Assurance = AssuranceNone
		result.ReasonCodes = state.reasons
		result.NextActions = state.actions
	} else if len(state.findingIDs) != 0 {
		result.AutomatedOutcome = OutcomeNotSatisfied
		result.EvidenceState = EvidenceSufficient
		result.Assurance = AssuranceMedium
		result.ReasonCodes = []ReasonCode{ReasonActiveFinding}
		result.NextActions = []NextAction{ActionRemediate}
	} else {
		result.AutomatedOutcome = OutcomeSatisfied
		result.EvidenceState = EvidenceSufficient
		result.Assurance = AssuranceMedium
		result.ReasonCodes = []ReasonCode{ReasonSatisfied}
		result.NextActions = []NextAction{ActionNone}
	}
	return NormalizeResult(result), nil
}

func strongerEvidenceFailure(current, candidate EvidenceState) EvidenceState {
	rank := map[EvidenceState]int{
		EvidenceSufficient: 0,
		EvidenceStale:      1,
		EvidenceMissing:    2,
		EvidenceIncomplete: 3,
		EvidenceUntrusted:  4,
	}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}
