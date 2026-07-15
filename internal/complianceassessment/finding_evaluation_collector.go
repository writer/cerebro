package complianceassessment

import (
	"context"
	"fmt"
	"sort"
	"strconv"
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
		Limit:      MaxFindingEvaluationBindings,
	})
	if err != nil {
		return InputManifest{}, nil, fmt.Errorf("list assessment source runtimes: %w", err)
	}
	if err := validateResolvedRuntimes(run.TenantID, runtimeIDs, resolvedRuntimes); err != nil {
		return InputManifest{}, nil, err
	}
	resolvedRuntimeByID := make(map[string]*cerebrov1.SourceRuntime, len(resolvedRuntimes))
	for _, runtime := range resolvedRuntimes {
		resolvedRuntimeByID[strings.TrimSpace(runtime.GetId())] = runtime
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
		result, receipts, evaluationRunIDs, collectErr := c.collectTask(ctx, plan, run, task, cutoff, resolvedRuntimeByID)
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

type findingEvaluationTaskQuery struct {
	runtimeID   string
	queryDigest string
	runs        []*cerebrov1.FindingEvaluationRun
}

func (c *FindingEvaluationCollector) collectTask(ctx context.Context, plan AssessmentPlanRevision, assessmentRun AssessmentRun, task PlanTask, cutoff time.Time, resolvedRuntimeByID map[string]*cerebrov1.SourceRuntime) (ObjectiveResult, []CollectionReceipt, []string, error) {
	maxAge, err := time.ParseDuration(task.MaxAge)
	if err != nil || maxAge <= 0 {
		return ObjectiveResult{}, nil, nil, fmt.Errorf("%w: task %q has invalid max_age", ErrIncompleteInput, task.ID)
	}
	queries := make([]findingEvaluationTaskQuery, 0, len(task.RuntimeIDs))
	for _, runtimeID := range task.RuntimeIDs {
		query := findingEvaluationQuery{
			TaskID: task.ID, RuntimeID: runtimeID, RuntimeIDs: task.RuntimeIDs, RuleID: task.RuleID,
			PeriodStart: assessmentRun.PeriodStart, PeriodEnd: assessmentRun.PeriodEnd,
			Cutoff: cutoff, MaxAge: task.MaxAge,
		}
		queryDigest, hashErr := semanticHash(query)
		if hashErr != nil {
			return ObjectiveResult{}, nil, nil, hashErr
		}
		runs, listErr := c.evaluations.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{
			RuntimeID:          runtimeID,
			RuleID:             task.RuleID,
			Status:             "completed",
			FinishedAtOrBefore: CanonicalTime(assessmentRun.PeriodEnd),
			Limit:              1,
		})
		if listErr != nil {
			return ObjectiveResult{}, nil, nil, fmt.Errorf("list finding evaluations for task %q runtime %q: %w", task.ID, runtimeID, listErr)
		}
		queries = append(queries, findingEvaluationTaskQuery{runtimeID: runtimeID, queryDigest: queryDigest, runs: runs})
	}

	// Tenant-scoped graph rules run once per orchestration cycle and bind every
	// source dependency in that run's source snapshots. Consume the newest such
	// run once instead of requiring one duplicate graph run per dependency.
	if graphQueryIndex := newestGraphEvaluationQueryIndex(queries); graphQueryIndex >= 0 {
		queries = queries[graphQueryIndex : graphQueryIndex+1]
	}

	state := taskCollectionState{evidenceState: EvidenceSufficient}
	receipts := make([]CollectionReceipt, 0, len(queries))
	for _, query := range queries {
		receipt, collected, receiptErr := evaluationReceipt(task, query.runtimeID, query.queryDigest, query.runs, assessmentRun.PeriodStart, assessmentRun.PeriodEnd, cutoff, maxAge, resolvedRuntimeByID)
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

func newestGraphEvaluationQueryIndex(queries []findingEvaluationTaskQuery) int {
	newestIndex := -1
	for index, query := range queries {
		if len(query.runs) != 1 || query.runs[0] == nil || query.runs[0].GraphRule == nil || !query.runs[0].GetGraphRule() {
			continue
		}
		if newestIndex < 0 || findingEvaluationRunNewer(query.runs[0], queries[newestIndex].runs[0]) {
			newestIndex = index
		}
	}
	return newestIndex
}

func findingEvaluationRunNewer(candidate, current *cerebrov1.FindingEvaluationRun) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	candidateFinishedAt := candidate.GetFinishedAt()
	currentFinishedAt := current.GetFinishedAt()
	if candidateFinishedAt != nil && candidateFinishedAt.CheckValid() == nil && currentFinishedAt != nil && currentFinishedAt.CheckValid() == nil {
		candidateTime := CanonicalTime(candidateFinishedAt.AsTime())
		currentTime := CanonicalTime(currentFinishedAt.AsTime())
		if !candidateTime.Equal(currentTime) {
			return candidateTime.After(currentTime)
		}
	} else if candidateFinishedAt != nil && candidateFinishedAt.CheckValid() == nil {
		return true
	} else if currentFinishedAt != nil && currentFinishedAt.CheckValid() == nil {
		return false
	}
	return strings.TrimSpace(candidate.GetId()) > strings.TrimSpace(current.GetId())
}

type findingEvaluationQuery struct {
	TaskID      string    `json:"task_id"`
	RuntimeID   string    `json:"runtime_id"`
	RuntimeIDs  []string  `json:"runtime_ids"`
	RuleID      string    `json:"rule_id"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Cutoff      time.Time `json:"cutoff"`
	MaxAge      string    `json:"max_age"`
}

type findingEvaluationPage struct {
	ID                       string                        `json:"id"`
	RuntimeID                string                        `json:"runtime_id"`
	RuleID                   string                        `json:"rule_id"`
	Status                   string                        `json:"status"`
	EventLimit               uint32                        `json:"event_limit"`
	EventsEvaluated          uint32                        `json:"events_evaluated"`
	EventsProcessed          uint32                        `json:"events_processed"`
	FindingsUpserted         uint32                        `json:"findings_upserted"`
	FindingsEmitted          uint32                        `json:"findings_emitted"`
	FindingIDs               []string                      `json:"finding_ids"`
	StartedAt                time.Time                     `json:"started_at"`
	FinishedAt               time.Time                     `json:"finished_at"`
	GraphRule                bool                          `json:"graph_rule"`
	GraphRowsRead            uint32                        `json:"graph_rows_read"`
	GraphTruncated           bool                          `json:"graph_truncated"`
	GraphRowLimit            uint32                        `json:"graph_row_limit"`
	SourceDependencyComplete bool                          `json:"source_dependency_complete"`
	RuleApplicable           bool                          `json:"rule_applicable"`
	SourceSnapshots          []findingEvaluationSourcePage `json:"source_snapshots"`
}

type findingEvaluationSourcePage struct {
	RuntimeID             string    `json:"runtime_id"`
	SourceID              string    `json:"source_id"`
	Family                string    `json:"family"`
	LastSyncedAt          time.Time `json:"last_synced_at"`
	CheckpointWatermark   time.Time `json:"checkpoint_watermark"`
	Complete              bool      `json:"complete"`
	RecordsScanned        uint32    `json:"records_scanned"`
	RecordsAccepted       uint32    `json:"records_accepted"`
	RecordsRejected       uint32    `json:"records_rejected"`
	SyncStatus            string    `json:"sync_status"`
	ContractProbeState    string    `json:"contract_probe_state"`
	ProgressConfigHash    string    `json:"progress_config_hash"`
	GraphIngestRunID      string    `json:"graph_ingest_run_id,omitempty"`
	GraphIngestStatus     string    `json:"graph_ingest_status,omitempty"`
	GraphCheckpointID     string    `json:"graph_checkpoint_id,omitempty"`
	GraphIngestedAt       time.Time `json:"graph_ingested_at,omitempty"`
	GraphSnapshotComplete bool      `json:"graph_snapshot_complete,omitempty"`
}

func evaluationReceipt(task PlanTask, runtimeID, queryDigest string, runs []*cerebrov1.FindingEvaluationRun, periodStart, periodEnd, cutoff time.Time, maxAge time.Duration, resolvedRuntimeByID map[string]*cerebrov1.SourceRuntime) (CollectionReceipt, taskCollectionState, error) {
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
	if strings.TrimSpace(run.GetId()) == "" || strings.TrimSpace(run.GetRuntimeId()) != runtimeID || strings.TrimSpace(run.GetRuleId()) != task.RuleID || strings.TrimSpace(run.GetStatus()) != "completed" ||
		run.GetStartedAt() == nil || run.GetStartedAt().CheckValid() != nil || run.GetFinishedAt() == nil || run.GetFinishedAt().CheckValid() != nil {
		return CollectionReceipt{}, taskCollectionState{}, fmt.Errorf("%w: finding evaluation run for task %q is invalid", ErrIncompleteInput, task.ID)
	}
	startedAt := CanonicalTime(run.GetStartedAt().AsTime())
	finishedAt := CanonicalTime(run.GetFinishedAt().AsTime())
	if finishedAt.Before(startedAt) {
		return CollectionReceipt{}, taskCollectionState{}, fmt.Errorf("%w: finding evaluation run %q has an invalid time range", ErrIncompleteInput, run.GetId())
	}
	findingIDs := normalizedStrings(run.GetFindingIds())
	if len(findingIDs) != len(run.GetFindingIds()) || uint64(len(findingIDs)) != uint64(run.GetFindingsUpserted()) || run.GetFindingsEmitted() != run.GetFindingsUpserted() {
		return CollectionReceipt{}, taskCollectionState{}, fmt.Errorf("%w: finding evaluation run %q has inconsistent finding counts", ErrIncompleteInput, run.GetId())
	}
	population, truncated, err := evaluationPopulation(run)
	if err != nil {
		return CollectionReceipt{}, taskCollectionState{}, err
	}
	sourcePages := findingEvaluationSourcePages(run.GetSourceSnapshots())
	pageDigest, err := semanticHash(findingEvaluationPage{
		ID: run.GetId(), RuntimeID: run.GetRuntimeId(), RuleID: run.GetRuleId(), Status: run.GetStatus(),
		EventLimit: run.GetEventLimit(), EventsEvaluated: run.GetEventsEvaluated(), EventsProcessed: run.GetEventsProcessed(),
		FindingsUpserted: run.GetFindingsUpserted(), FindingsEmitted: run.GetFindingsEmitted(), FindingIDs: findingIDs,
		StartedAt: startedAt, FinishedAt: finishedAt, GraphRule: run.GetGraphRule(), GraphRowsRead: run.GetGraphRowsRead(),
		GraphTruncated: run.GetGraphTruncated(), GraphRowLimit: run.GetGraphRowLimit(),
		SourceDependencyComplete: run.GetSourceDependencyComplete(), RuleApplicable: run.GetRuleApplicable(), SourceSnapshots: sourcePages,
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
	periodStart = CanonicalTime(periodStart)
	periodEnd = CanonicalTime(periodEnd)
	// Graph evaluation envelopes do not carry a tenant-wide graph generation.
	// Source runtime snapshots therefore cannot prove that the shared graph was
	// stable while the rule ran. Keep legacy and new graph runs inspectable, but
	// do not admit them as assessment evidence until that fence is persisted and
	// verified here at the consumer boundary.
	if run.GetGraphRule() {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceUntrusted
		collected.reasons = []ReasonCode{ReasonSourceUntrusted}
		collected.actions = []NextAction{ActionRestoreSource}
	} else if finishedAt.Before(periodStart) || periodEnd.Sub(finishedAt) > maxAge {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceStale
		collected.reasons = []ReasonCode{ReasonEvidenceStale}
		collected.actions = []NextAction{ActionRefreshEvidence}
	} else if finishedAt.After(periodEnd) || finishedAt.After(cutoff) {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceUntrusted
		collected.reasons = []ReasonCode{ReasonEvidenceInvalid}
		collected.actions = []NextAction{ActionReview}
	} else if run.RuleApplicable == nil || !run.GetRuleApplicable() {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceUntrusted
		collected.reasons = []ReasonCode{ReasonSourceUnsupported}
		collected.actions = []NextAction{ActionReview}
	} else if sourceSnapshotErr := validateEvaluationSourceSnapshots(run, task.RuntimeIDs, startedAt, periodEnd, maxAge, resolvedRuntimeByID); sourceSnapshotErr != nil {
		receipt.Completeness = CollectionUnknown
		collected.incomplete = true
		collected.evidenceState = EvidenceUntrusted
		collected.reasons = []ReasonCode{ReasonSourceUntrusted}
		collected.actions = []NextAction{ActionRestoreSource}
	} else if truncated {
		receipt.Completeness = CollectionTruncated
		collected.incomplete = true
		collected.evidenceState = EvidenceIncomplete
		collected.reasons = []ReasonCode{ReasonCoverageIncomplete}
		collected.actions = []NextAction{ActionCollectEvidence}
	}
	return receipt, collected, nil
}

func findingEvaluationSourcePages(snapshots []*cerebrov1.FindingEvaluationSourceSnapshot) []findingEvaluationSourcePage {
	pages := make([]findingEvaluationSourcePage, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot == nil {
			continue
		}
		page := findingEvaluationSourcePage{
			RuntimeID: snapshot.GetRuntimeId(), SourceID: snapshot.GetSourceId(), Family: snapshot.GetFamily(), Complete: snapshot.GetComplete(),
			RecordsScanned: snapshot.GetRecordsScanned(), RecordsAccepted: snapshot.GetRecordsAccepted(), RecordsRejected: snapshot.GetRecordsRejected(),
			SyncStatus: snapshot.GetSyncStatus(), ContractProbeState: snapshot.GetContractProbeState(), ProgressConfigHash: snapshot.GetProgressConfigHash(),
			GraphIngestRunID: snapshot.GetGraphIngestRunId(), GraphIngestStatus: snapshot.GetGraphIngestStatus(), GraphCheckpointID: snapshot.GetGraphCheckpointId(),
			GraphSnapshotComplete: snapshot.GetGraphSnapshotComplete(),
		}
		if value := snapshot.GetLastSyncedAt(); value != nil && value.CheckValid() == nil {
			page.LastSyncedAt = CanonicalTime(value.AsTime())
		}
		if value := snapshot.GetCheckpointWatermark(); value != nil && value.CheckValid() == nil {
			page.CheckpointWatermark = CanonicalTime(value.AsTime())
		}
		if value := snapshot.GetGraphIngestedAt(); value != nil && value.CheckValid() == nil {
			page.GraphIngestedAt = CanonicalTime(value.AsTime())
		}
		pages = append(pages, page)
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].RuntimeID < pages[j].RuntimeID })
	return pages
}

func validateEvaluationSourceSnapshots(run *cerebrov1.FindingEvaluationRun, taskRuntimeIDs []string, evaluationStartedAt, periodEnd time.Time, maxAge time.Duration, resolvedRuntimeByID map[string]*cerebrov1.SourceRuntime) error {
	if run.SourceDependencyComplete == nil || !run.GetSourceDependencyComplete() || len(run.GetSourceSnapshots()) == 0 {
		return fmt.Errorf("%w: finding evaluation run %q has incomplete source dependencies", ErrIncompleteInput, run.GetId())
	}
	allowedRuntimeIDs := make(map[string]struct{}, len(taskRuntimeIDs))
	for _, runtimeID := range taskRuntimeIDs {
		allowedRuntimeIDs[strings.TrimSpace(runtimeID)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(run.GetSourceSnapshots()))
	for _, snapshot := range run.GetSourceSnapshots() {
		if snapshot == nil || snapshot.Complete == nil || !snapshot.GetComplete() || snapshot.GetLastSyncedAt() == nil || snapshot.GetLastSyncedAt().CheckValid() != nil ||
			snapshot.GetCheckpointWatermark() == nil || snapshot.GetCheckpointWatermark().CheckValid() != nil || snapshot.GetSyncStatus() != "completed" ||
			(snapshot.GetContractProbeState() != "passing" && snapshot.GetContractProbeState() != "not_configured") || snapshot.GetRecordsRejected() != 0 ||
			snapshot.GetRecordsAccepted() > snapshot.GetRecordsScanned() || strings.TrimSpace(snapshot.GetProgressConfigHash()) == "" {
			return fmt.Errorf("%w: finding evaluation run %q has an incomplete source snapshot", ErrIncompleteInput, run.GetId())
		}
		runtimeID := strings.TrimSpace(snapshot.GetRuntimeId())
		if runtimeID == "" {
			return fmt.Errorf("%w: finding evaluation run %q has an unnamed source snapshot", ErrIncompleteInput, run.GetId())
		}
		if _, ok := allowedRuntimeIDs[runtimeID]; !ok {
			return fmt.Errorf("%w: finding evaluation run %q reads runtime %q outside the plan", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		if _, ok := seen[runtimeID]; ok {
			return fmt.Errorf("%w: finding evaluation run %q duplicates runtime %q", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		seen[runtimeID] = struct{}{}
		current := resolvedRuntimeByID[runtimeID]
		if current == nil {
			return fmt.Errorf("%w: finding evaluation run %q runtime %q is unavailable", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		currentConfig := current.GetConfig()
		if strings.TrimSpace(current.GetSourceId()) != strings.TrimSpace(snapshot.GetSourceId()) ||
			strings.TrimSpace(current.GetConfig()["family"]) != strings.TrimSpace(snapshot.GetFamily()) ||
			strings.TrimSpace(currentConfig["__cerebro_resolved_progress_config_hash"]) != strings.TrimSpace(snapshot.GetProgressConfigHash()) {
			return fmt.Errorf("%w: finding evaluation run %q source scope changed for runtime %q", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		lastSyncedAt := CanonicalTime(snapshot.GetLastSyncedAt().AsTime())
		checkpointWatermark := CanonicalTime(snapshot.GetCheckpointWatermark().AsTime())
		if current.GetLastSyncedAt() == nil || current.GetLastSyncedAt().CheckValid() != nil || current.GetCheckpoint().GetWatermark() == nil || current.GetCheckpoint().GetWatermark().CheckValid() != nil {
			return fmt.Errorf("%w: finding evaluation run %q no longer matches runtime %q progress", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		currentLastSyncedAt := CanonicalTime(current.GetLastSyncedAt().AsTime())
		currentCheckpointWatermark := CanonicalTime(current.GetCheckpoint().GetWatermark().AsTime())
		if !currentLastSyncedAt.Equal(lastSyncedAt) || !currentCheckpointWatermark.Equal(checkpointWatermark) {
			return fmt.Errorf("%w: finding evaluation run %q no longer matches runtime %q progress", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		if !currentRuntimeMatchesSnapshot(current, snapshot) {
			return fmt.Errorf("%w: finding evaluation run %q no longer matches runtime %q state", ErrIncompleteInput, run.GetId(), runtimeID)
		}
		if lastSyncedAt.After(evaluationStartedAt) || lastSyncedAt.After(periodEnd) || checkpointWatermark.After(periodEnd) ||
			periodEnd.Sub(lastSyncedAt) > maxAge || periodEnd.Sub(checkpointWatermark) > maxAge {
			return fmt.Errorf("%w: finding evaluation run %q source snapshot is outside the assessment period", ErrIncompleteInput, run.GetId())
		}
		if run.GetGraphRule() {
			if snapshot.GraphSnapshotComplete == nil || !snapshot.GetGraphSnapshotComplete() || snapshot.GetGraphIngestedAt() == nil || snapshot.GetGraphIngestedAt().CheckValid() != nil ||
				snapshot.GetGraphIngestStatus() != "completed" || strings.TrimSpace(snapshot.GetGraphIngestRunId()) == "" || strings.TrimSpace(snapshot.GetGraphCheckpointId()) == "" {
				return fmt.Errorf("%w: graph evaluation run %q has no complete graph snapshot for runtime %q", ErrIncompleteInput, run.GetId(), runtimeID)
			}
			graphIngestedAt := CanonicalTime(snapshot.GetGraphIngestedAt().AsTime())
			if graphIngestedAt.Before(lastSyncedAt) || graphIngestedAt.After(evaluationStartedAt) || graphIngestedAt.After(periodEnd) || periodEnd.Sub(graphIngestedAt) > maxAge {
				return fmt.Errorf("%w: graph evaluation run %q graph snapshot is outside the assessment period", ErrIncompleteInput, run.GetId())
			}
		}
	}
	if run.GetGraphRule() && len(seen) != len(allowedRuntimeIDs) {
		return fmt.Errorf("%w: graph evaluation run %q does not cover every planned runtime", ErrIncompleteInput, run.GetId())
	}
	return nil
}

func parseRuntimeCounter(value string) (uint32, bool) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	return uint32(parsed), err == nil
}

func currentRuntimeMatchesSnapshot(current *cerebrov1.SourceRuntime, snapshot *cerebrov1.FindingEvaluationSourceSnapshot) bool {
	if current == nil || snapshot == nil {
		return false
	}
	config := current.GetConfig()
	contractState := strings.TrimSpace(config["__cerebro_runtime_contract_probe_state"])
	scanned, scannedOK := parseRuntimeCounter(config["__cerebro_runtime_records_scanned"])
	accepted, acceptedOK := parseRuntimeCounter(config["__cerebro_runtime_records_accepted"])
	rejected, rejectedOK := parseRuntimeCounter(config["__cerebro_runtime_records_rejected"])
	return strings.TrimSpace(config["__cerebro_runtime_status"]) == "completed" && strings.TrimSpace(config["__cerebro_runtime_last_failure_category"]) == "" &&
		scannedOK && acceptedOK && rejectedOK && scanned == snapshot.GetRecordsScanned() && accepted == snapshot.GetRecordsAccepted() &&
		rejected == snapshot.GetRecordsRejected() && rejected == 0 && contractState == snapshot.GetContractProbeState() &&
		(contractState == "passing" || contractState == "not_configured") &&
		strings.TrimSpace(current.GetNextCursor().GetOpaque()) == ""
}

func evaluationPopulation(run *cerebrov1.FindingEvaluationRun) (uint64, bool, error) {
	if run.GraphRule == nil {
		return 0, false, fmt.Errorf("%w: finding evaluation run %q does not identify its rule type", ErrIncompleteInput, run.GetId())
	}
	if run.GetGraphRule() {
		if run.GraphRowsRead == nil || run.GraphTruncated == nil || run.GraphRowLimit == nil || run.GetGraphRowLimit() == 0 ||
			run.GetEventLimit() != 0 || run.GetEventsEvaluated() != 0 || run.GetEventsProcessed() != 0 || run.GetGraphRowsRead() > run.GetGraphRowLimit() ||
			(run.GetGraphRowsRead() >= run.GetGraphRowLimit() && !run.GetGraphTruncated()) {
			return 0, false, fmt.Errorf("%w: graph evaluation run %q has inconsistent population metadata", ErrIncompleteInput, run.GetId())
		}
		population := uint64(run.GetGraphRowsRead())
		return population, run.GetGraphTruncated(), nil
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
