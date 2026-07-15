package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrPlanNotFound       = errors.New("assessment plan not found")
	ErrRunNotFound        = errors.New("assessment run not found")
	ErrAssessmentConflict = errors.New("assessment version conflict")
	ErrIncompleteInput    = errors.New("assessment input is incomplete")
)

const (
	PlanDraft     = "draft"
	PlanPublished = "published"
	PlanRetired   = "retired"

	RunQueued         = "queued"
	RunCollecting     = "collecting"
	RunEvaluating     = "evaluating"
	RunReviewRequired = "review_required"
	RunComplete       = "complete"
	RunFailed         = "failed"
	RunCancelled      = "cancelled"
	RunSuperseded     = "superseded"
)

type PlanScope struct {
	ProgramID               string   `json:"program_id"`
	ScopeRevisionID         string   `json:"scope_revision_id"`
	ImplementationRevisions []string `json:"implementation_revision_ids"`
	ObjectiveIDs            []string `json:"objective_ids"`
	IncludedSubjectIDs      []string `json:"included_subject_ids,omitempty"`
	ExcludedSubjectIDs      []string `json:"excluded_subject_ids,omitempty"`
}

type PlanExecution struct {
	Methods          []string `json:"methods"`
	Depth            string   `json:"depth"`
	CoverageTarget   string   `json:"coverage_target"`
	AssuranceTarget  string   `json:"assurance_target"`
	SamplingRule     string   `json:"sampling_rule,omitempty"`
	OrderedTaskIDs   []string `json:"ordered_task_ids"`
	ToolRevisionIDs  []string `json:"tool_revision_ids,omitempty"`
	CancellationRule string   `json:"cancellation_rule"`
}

type PlanGovernance struct {
	OwnerID           string   `json:"owner_id"`
	AssessorIDs       []string `json:"assessor_ids"`
	ApproverIDs       []string `json:"approver_ids"`
	IndependenceRule  string   `json:"independence_rule"`
	RulesOfEngagement string   `json:"rules_of_engagement"`
	Limitations       []string `json:"limitations,omitempty"`
}

type AssessmentPlanRevision struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	RevisionID    string         `json:"revision_id"`
	Version       uint64         `json:"version"`
	PredecessorID string         `json:"predecessor_id,omitempty"`
	Status        string         `json:"status"`
	Name          string         `json:"name"`
	Scope         PlanScope      `json:"scope"`
	Execution     PlanExecution  `json:"execution"`
	Governance    PlanGovernance `json:"governance"`
	ContentDigest string         `json:"content_digest"`
	CreatedAt     time.Time      `json:"created_at"`
	CreatedBy     string         `json:"created_by"`
	PublishedAt   time.Time      `json:"published_at,omitempty"`
	PublishedBy   string         `json:"published_by,omitempty"`
}

func normalizePlan(plan AssessmentPlanRevision) AssessmentPlanRevision {
	plan.ID = strings.TrimSpace(plan.ID)
	plan.TenantID = strings.TrimSpace(plan.TenantID)
	plan.RevisionID = strings.TrimSpace(plan.RevisionID)
	plan.PredecessorID = strings.TrimSpace(plan.PredecessorID)
	plan.Status = strings.TrimSpace(plan.Status)
	plan.Name = strings.TrimSpace(plan.Name)
	plan.CreatedBy = strings.TrimSpace(plan.CreatedBy)
	plan.PublishedBy = strings.TrimSpace(plan.PublishedBy)
	plan.Scope.ProgramID = strings.TrimSpace(plan.Scope.ProgramID)
	plan.Scope.ScopeRevisionID = strings.TrimSpace(plan.Scope.ScopeRevisionID)
	plan.Scope.ImplementationRevisions = normalizedStrings(plan.Scope.ImplementationRevisions)
	plan.Scope.ObjectiveIDs = normalizedStrings(plan.Scope.ObjectiveIDs)
	plan.Scope.IncludedSubjectIDs = normalizedStrings(plan.Scope.IncludedSubjectIDs)
	plan.Scope.ExcludedSubjectIDs = normalizedStrings(plan.Scope.ExcludedSubjectIDs)
	plan.Execution.Methods = normalizedStrings(plan.Execution.Methods)
	plan.Execution.OrderedTaskIDs = orderedUniqueStrings(plan.Execution.OrderedTaskIDs)
	plan.Execution.ToolRevisionIDs = normalizedStrings(plan.Execution.ToolRevisionIDs)
	plan.Governance.AssessorIDs = normalizedStrings(plan.Governance.AssessorIDs)
	plan.Governance.ApproverIDs = normalizedStrings(plan.Governance.ApproverIDs)
	plan.Governance.Limitations = normalizedStrings(plan.Governance.Limitations)
	plan.CreatedAt = CanonicalTime(plan.CreatedAt)
	plan.PublishedAt = CanonicalTime(plan.PublishedAt)
	return plan
}

func validatePlan(plan AssessmentPlanRevision) error {
	if plan.ID == "" || plan.TenantID == "" || plan.RevisionID == "" || plan.Version == 0 || plan.Name == "" || plan.CreatedBy == "" || plan.CreatedAt.IsZero() {
		return fmt.Errorf("%w: plan identity and revision metadata are required", ErrInvalidResult)
	}
	if plan.Scope.ProgramID == "" || plan.Scope.ScopeRevisionID == "" || len(plan.Scope.ImplementationRevisions) == 0 || len(plan.Scope.ObjectiveIDs) == 0 {
		return fmt.Errorf("%w: plan scope is incomplete", ErrInvalidResult)
	}
	if len(plan.Execution.Methods) == 0 || len(plan.Execution.OrderedTaskIDs) == 0 || plan.Execution.CoverageTarget == "" || plan.Execution.AssuranceTarget == "" {
		return fmt.Errorf("%w: plan execution contract is incomplete", ErrInvalidResult)
	}
	if plan.Governance.OwnerID == "" || len(plan.Governance.ApproverIDs) == 0 || plan.Governance.RulesOfEngagement == "" {
		return fmt.Errorf("%w: plan governance is incomplete", ErrInvalidResult)
	}
	switch plan.Status {
	case PlanDraft, PlanPublished, PlanRetired:
	default:
		return fmt.Errorf("%w: plan status %q", ErrInvalidResult, plan.Status)
	}
	return nil
}

func orderedUniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
