package complianceassessment

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const DefaultAgentResultBound = 2000

type AgentRunRequest struct {
	TenantID       string
	PlanRevisionID string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	BaselineRunID  string
	IdempotencyKey string
	ActorID        string
}

type VerifiedResultPage struct {
	Run          AssessmentRun          `json:"run"`
	Page         ResultChunkPage        `json:"page"`
	Verification ResultPageVerification `json:"verification"`
}

type VerifiedResultSet struct {
	Results      []ObjectiveResult      `json:"results"`
	Verification ResultPageVerification `json:"verification"`
}

type AgentResultChange struct {
	ObjectiveID string          `json:"objective_id"`
	Before      ObjectiveResult `json:"before"`
	After       ObjectiveResult `json:"after"`
}

type AgentResultDiff struct {
	Added          []ObjectiveResult   `json:"added"`
	Removed        []ObjectiveResult   `json:"removed"`
	Changed        []AgentResultChange `json:"changed"`
	UnchangedCount int                 `json:"unchanged_count"`
}

type AgentRunDiff struct {
	Run                  AssessmentRun          `json:"run"`
	Baseline             AssessmentRun          `json:"baseline"`
	CurrentVerification  ResultPageVerification `json:"current_verification"`
	BaselineVerification ResultPageVerification `json:"baseline_verification"`
	Diff                 AgentResultDiff        `json:"diff"`
}

type AgentRemediationWorkRequest struct {
	TenantID            string          `json:"tenant_id"`
	ProgramID           string          `json:"program_id"`
	ScopeRevisionID     string          `json:"scope_revision_id"`
	SubjectID           string          `json:"subject_id"`
	SourceID            string          `json:"source_id,omitempty"`
	OwnerID             string          `json:"owner_id"`
	DueAt               string          `json:"due_at"`
	Priority            string          `json:"priority"`
	AssessmentRunID     string          `json:"assessment_run_id"`
	AutomatedResultHash string          `json:"automated_result_hash"`
	Result              ObjectiveResult `json:"result"`
}

type AgentRemediationProposal struct {
	Ready         bool                        `json:"ready"`
	MissingFields []string                    `json:"missing_fields"`
	Request       AgentRemediationWorkRequest `json:"request"`
	Verification  ResultPageVerification      `json:"verification"`
}

func (s *Service) CreatePlanForAgent(ctx context.Context, tenantID, actorID string, plan AssessmentPlanRevision) (AssessmentPlanRevision, error) {
	plan.ID = ""
	plan.TenantID = strings.TrimSpace(tenantID)
	plan.RevisionID = ""
	plan.Version = 0
	plan.PredecessorID = ""
	plan.Status = PlanDraft
	plan.ContentDigest = ""
	plan.CreatedAt = time.Time{}
	plan.CreatedBy = ""
	plan.PublishedAt = time.Time{}
	plan.PublishedBy = ""
	if err := validateAgentExecutablePlan(plan); err != nil {
		return AssessmentPlanRevision{}, err
	}
	return s.RecordPlan(ctx, plan, actorID, 0)
}

func (s *Service) PublishPlanForAgent(ctx context.Context, tenantID, planID, actorID string, expectedVersion uint64) (AssessmentPlanRevision, error) {
	draft, err := s.GetPlan(ctx, tenantID, planID)
	if err != nil {
		return AssessmentPlanRevision{}, err
	}
	if err := validateAgentExecutablePlan(draft); err != nil {
		return AssessmentPlanRevision{}, err
	}
	return s.PublishPlan(ctx, tenantID, planID, actorID, expectedVersion)
}

func (s *Service) RequestRunForAgent(ctx context.Context, request AgentRunRequest) (AssessmentRun, bool, error) {
	plan, err := s.GetPlan(ctx, request.TenantID, request.PlanRevisionID)
	if err != nil {
		return AssessmentRun{}, false, err
	}
	if err := validateAgentExecutablePlan(plan); err != nil {
		return AssessmentRun{}, false, err
	}
	return s.RequestRun(ctx, RunRequest{
		TenantID: request.TenantID, PlanRevisionID: request.PlanRevisionID,
		PeriodStart: request.PeriodStart, PeriodEnd: request.PeriodEnd,
		BaselineRunID: request.BaselineRunID, IdempotencyKey: request.IdempotencyKey,
		RequestedBy: request.ActorID,
	})
}

func (s *Service) GetCompletedRun(ctx context.Context, tenantID, runID string) (AssessmentRun, error) {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return AssessmentRun{}, err
	}
	if run.State != RunComplete {
		return AssessmentRun{}, fmt.Errorf("%w: assessment results are available only when the run is complete", ErrAssessmentConflict)
	}
	return run, nil
}

func (s *Service) VerifiedResultsPage(ctx context.Context, tenantID, runID string, afterSequence, limit uint32, expectedPreviousDigest string) (VerifiedResultPage, error) {
	run, err := s.GetCompletedRun(ctx, tenantID, runID)
	if err != nil {
		return VerifiedResultPage{}, err
	}
	page, err := s.ListResultChunksPage(ctx, tenantID, runID, afterSequence, limit)
	if err != nil {
		return VerifiedResultPage{}, err
	}
	verification, err := VerifyResultChunkPage(runID, afterSequence, expectedPreviousDigest, page)
	if err != nil {
		return VerifiedResultPage{}, err
	}
	return VerifiedResultPage{Run: run, Page: page, Verification: verification}, nil
}

func (s *Service) CollectVerifiedResults(ctx context.Context, tenantID, runID string, maxResults int) (VerifiedResultSet, error) {
	if maxResults < 1 {
		maxResults = DefaultAgentResultBound
	}
	run, err := s.GetCompletedRun(ctx, tenantID, runID)
	if err != nil {
		return VerifiedResultSet{}, err
	}
	results := []ObjectiveResult{}
	afterSequence := uint32(0)
	previousDigest := ""
	combined := ResultPageVerification{Verified: true}
	for {
		verified, err := s.VerifiedResultsPage(ctx, tenantID, runID, afterSequence, 100, previousDigest)
		if err != nil {
			return VerifiedResultSet{}, err
		}
		if combined.ChunkCount == 0 {
			combined.FirstSequence = verified.Verification.FirstSequence
		}
		combined.LastSequence = verified.Verification.LastSequence
		combined.ChunkCount += verified.Verification.ChunkCount
		combined.ResultCount += verified.Verification.ResultCount
		combined.NextPreviousDigest = verified.Verification.NextPreviousDigest
		for _, chunk := range verified.Page.Chunks {
			results = append(results, chunk.Results...)
			if len(results) > maxResults {
				return VerifiedResultSet{}, fmt.Errorf("%w: assessment has more than %d results; page results instead", ErrInvalidResult, maxResults)
			}
		}
		if !verified.Page.HasMore {
			break
		}
		afterSequence = verified.Page.NextSequence
		previousDigest = verified.Verification.NextPreviousDigest
	}
	if uint64(len(results)) != run.ResultCount {
		return VerifiedResultSet{}, fmt.Errorf("%w: verified result count does not match the completed run", ErrInvalidResult)
	}
	return VerifiedResultSet{Results: results, Verification: combined}, nil
}

func (s *Service) FindVerifiedResult(ctx context.Context, tenantID, runID, resultID string, maxResults int) (AssessmentRun, ObjectiveResult, ResultPageVerification, error) {
	resultID = strings.TrimSpace(resultID)
	if resultID == "" {
		return AssessmentRun{}, ObjectiveResult{}, ResultPageVerification{}, fmt.Errorf("%w: result_id is required", ErrInvalidResult)
	}
	run, err := s.GetCompletedRun(ctx, tenantID, runID)
	if err != nil {
		return AssessmentRun{}, ObjectiveResult{}, ResultPageVerification{}, err
	}
	set, err := s.CollectVerifiedResults(ctx, tenantID, runID, maxResults)
	if err != nil {
		return AssessmentRun{}, ObjectiveResult{}, set.Verification, err
	}
	for _, result := range set.Results {
		if result.ID == resultID {
			return run, result, set.Verification, nil
		}
	}
	return AssessmentRun{}, ObjectiveResult{}, set.Verification, fmt.Errorf("%w: assessment result %q was not found", ErrInvalidResult, resultID)
}

func (s *Service) DiffRunsForAgent(ctx context.Context, tenantID, runID, baselineRunID string, maxResults int) (AgentRunDiff, error) {
	run, err := s.GetCompletedRun(ctx, tenantID, runID)
	if err != nil {
		return AgentRunDiff{}, err
	}
	baselineRunID = strings.TrimSpace(baselineRunID)
	if baselineRunID == "" {
		baselineRunID = strings.TrimSpace(run.BaselineRunID)
	}
	if baselineRunID == "" || baselineRunID == run.ID {
		return AgentRunDiff{}, fmt.Errorf("%w: a different baseline_run_id is required", ErrInvalidResult)
	}
	baseline, err := s.GetCompletedRun(ctx, tenantID, baselineRunID)
	if err != nil {
		return AgentRunDiff{}, err
	}
	currentSet, err := s.CollectVerifiedResults(ctx, tenantID, run.ID, maxResults)
	if err != nil {
		return AgentRunDiff{}, err
	}
	baselineSet, err := s.CollectVerifiedResults(ctx, tenantID, baseline.ID, maxResults)
	if err != nil {
		return AgentRunDiff{}, err
	}
	diff, err := diffAgentResults(baselineSet.Results, currentSet.Results)
	if err != nil {
		return AgentRunDiff{}, err
	}
	return AgentRunDiff{Run: run, Baseline: baseline, CurrentVerification: currentSet.Verification, BaselineVerification: baselineSet.Verification, Diff: diff}, nil
}

func (s *Service) ProposeRemediationForAgent(ctx context.Context, tenantID, runID, resultID, subjectID, sourceID, ownerID, dueAt, priority string, maxResults int) (AgentRemediationProposal, error) {
	run, result, verification, err := s.FindVerifiedResult(ctx, tenantID, runID, resultID, maxResults)
	if err != nil {
		return AgentRemediationProposal{}, err
	}
	if result.AutomatedOutcome == OutcomeSatisfied || result.AutomatedOutcome == OutcomeNotAssessed {
		return AgentRemediationProposal{}, fmt.Errorf("%w: the assessment result does not support remediation work", ErrInvalidResult)
	}
	request := AgentRemediationWorkRequest{
		TenantID: tenantID, ProgramID: run.ProgramID, ScopeRevisionID: run.ScopeRevisionID,
		SubjectID: strings.TrimSpace(subjectID), SourceID: strings.TrimSpace(sourceID),
		OwnerID: strings.TrimSpace(ownerID), DueAt: strings.TrimSpace(dueAt), Priority: strings.TrimSpace(priority),
		AssessmentRunID: run.ID, AutomatedResultHash: run.AutomatedResultHash, Result: result,
	}
	missing := []string{}
	for name, value := range map[string]string{"subject_id": request.SubjectID, "owner_id": request.OwnerID, "due_at": request.DueAt, "priority": request.Priority} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if request.SourceID == "" && len(result.SourceRuntimeIDs) == 0 {
		missing = append(missing, "source_id")
	}
	if request.DueAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, request.DueAt); err != nil {
			return AgentRemediationProposal{}, fmt.Errorf("%w: due_at must be an RFC3339 timestamp", ErrInvalidResult)
		}
	}
	sort.Strings(missing)
	return AgentRemediationProposal{Ready: len(missing) == 0, MissingFields: missing, Request: request, Verification: verification}, nil
}

func AgentRunTerminal(state string) bool {
	switch state {
	case RunComplete, RunFailed, RunCancelled, RunSuperseded:
		return true
	default:
		return false
	}
}

func validateAgentExecutablePlan(plan AssessmentPlanRevision) error {
	for _, task := range plan.Execution.Tasks {
		if task.Kind != PlanTaskKindFindingEvaluation {
			return fmt.Errorf("%w: assessment task %q uses unsupported kind %q", ErrInvalidResult, task.ID, task.Kind)
		}
	}
	return nil
}

func diffAgentResults(baseline, current []ObjectiveResult) (AgentResultDiff, error) {
	baselineByObjective := make(map[string]ObjectiveResult, len(baseline))
	currentByObjective := make(map[string]ObjectiveResult, len(current))
	for _, result := range baseline {
		if _, exists := baselineByObjective[result.ObjectiveID]; exists {
			return AgentResultDiff{}, fmt.Errorf("%w: baseline contains duplicate objective %q", ErrInvalidResult, result.ObjectiveID)
		}
		baselineByObjective[result.ObjectiveID] = result
	}
	for _, result := range current {
		if _, exists := currentByObjective[result.ObjectiveID]; exists {
			return AgentResultDiff{}, fmt.Errorf("%w: current run contains duplicate objective %q", ErrInvalidResult, result.ObjectiveID)
		}
		currentByObjective[result.ObjectiveID] = result
	}
	keys := make([]string, 0, len(baselineByObjective)+len(currentByObjective))
	seen := map[string]struct{}{}
	for key := range baselineByObjective {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range currentByObjective {
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	diff := AgentResultDiff{Added: []ObjectiveResult{}, Removed: []ObjectiveResult{}, Changed: []AgentResultChange{}}
	for _, key := range keys {
		before, hadBefore := baselineByObjective[key]
		after, hasAfter := currentByObjective[key]
		switch {
		case !hadBefore:
			diff.Added = append(diff.Added, after)
		case !hasAfter:
			diff.Removed = append(diff.Removed, before)
		default:
			beforeDigest, err := CanonicalResultDigest(before)
			if err != nil {
				return AgentResultDiff{}, err
			}
			afterDigest, err := CanonicalResultDigest(after)
			if err != nil {
				return AgentResultDiff{}, err
			}
			if beforeDigest == afterDigest {
				diff.UnchangedCount++
			} else {
				diff.Changed = append(diff.Changed, AgentResultChange{ObjectiveID: key, Before: before, After: after})
			}
		}
	}
	return diff, nil
}
