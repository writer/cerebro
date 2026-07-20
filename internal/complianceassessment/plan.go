package complianceassessment

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
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

	PlanTaskKindProcedure         = "procedure"
	PlanTaskKindFindingEvaluation = "finding_evaluation"
	EvaluationModePointInTime     = "point_in_time"

	MaxFindingEvaluationTasks        = 25
	MaxFindingEvaluationTaskRuntimes = 20
	MaxFindingEvaluationBindings     = 100
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
	Methods          []string   `json:"methods"`
	Depth            string     `json:"depth"`
	CoverageTarget   string     `json:"coverage_target"`
	AssuranceTarget  string     `json:"assurance_target"`
	SamplingRule     string     `json:"sampling_rule,omitempty"`
	Tasks            []PlanTask `json:"tasks"`
	OrderedTaskIDs   []string   `json:"ordered_task_ids"`
	ToolRevisionIDs  []string   `json:"tool_revision_ids,omitempty"`
	CancellationRule string     `json:"cancellation_rule"`
}

// PlanTask binds one assessment objective to one bounded procedure. Finding
// evaluation tasks read only the latest durable evaluation run for each named
// source runtime; they do not execute rules or issue graph queries.
type PlanTask struct {
	ID             string                `json:"id"`
	ObjectiveID    string                `json:"objective_id"`
	ControlRef     compliance.ControlRef `json:"control_ref"`
	Kind           string                `json:"kind"`
	RuleID         string                `json:"rule_id,omitempty"`
	RuntimeIDs     []string              `json:"runtime_ids,omitempty"`
	MaxAge         string                `json:"max_age,omitempty"`
	EvaluationMode string                `json:"evaluation_mode,omitempty"`
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
	plan.Execution.Depth = strings.TrimSpace(plan.Execution.Depth)
	plan.Execution.CoverageTarget = strings.TrimSpace(plan.Execution.CoverageTarget)
	plan.Execution.AssuranceTarget = strings.TrimSpace(plan.Execution.AssuranceTarget)
	plan.Execution.SamplingRule = strings.TrimSpace(plan.Execution.SamplingRule)
	plan.Execution.CancellationRule = strings.TrimSpace(plan.Execution.CancellationRule)
	plan.Execution.Tasks = append([]PlanTask(nil), plan.Execution.Tasks...)
	for index := range plan.Execution.Tasks {
		task := &plan.Execution.Tasks[index]
		task.ID = strings.TrimSpace(task.ID)
		task.ObjectiveID = strings.TrimSpace(task.ObjectiveID)
		task.ControlRef = compliance.NormalizeControlRef(task.ControlRef)
		task.Kind = strings.TrimSpace(task.Kind)
		task.RuleID = strings.TrimSpace(task.RuleID)
		task.RuntimeIDs = normalizedStrings(task.RuntimeIDs)
		task.MaxAge = strings.TrimSpace(task.MaxAge)
		task.EvaluationMode = strings.TrimSpace(task.EvaluationMode)
	}
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
	if len(plan.Execution.Methods) == 0 || len(plan.Execution.Tasks) == 0 || len(plan.Execution.OrderedTaskIDs) == 0 || plan.Execution.CoverageTarget == "" || plan.Execution.AssuranceTarget == "" {
		return fmt.Errorf("%w: plan execution contract is incomplete", ErrInvalidResult)
	}
	if err := validatePlanTasks(plan.Scope.ObjectiveIDs, plan.Execution); err != nil {
		return err
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

func validatePlanTasks(objectiveIDs []string, execution PlanExecution) error {
	objectives := make(map[string]struct{}, len(objectiveIDs))
	for _, objectiveID := range objectiveIDs {
		objectives[objectiveID] = struct{}{}
	}
	tasks := make(map[string]PlanTask, len(execution.Tasks))
	taskObjectives := make(map[string]struct{}, len(execution.Tasks))
	findingTasks := 0
	findingBindings := 0
	for index, task := range execution.Tasks {
		if task.ID == "" || task.ObjectiveID == "" || task.Kind == "" || strings.TrimSpace(task.ControlRef.ControlID) == "" ||
			(strings.TrimSpace(task.ControlRef.FrameworkID) == "" && strings.TrimSpace(task.ControlRef.FrameworkName) == "" && strings.TrimSpace(task.ControlRef.Framework) == "") {
			return fmt.Errorf("%w: plan task %d is incomplete", ErrInvalidResult, index)
		}
		if _, ok := objectives[task.ObjectiveID]; !ok {
			return fmt.Errorf("%w: plan task %q references objective %q outside scope", ErrInvalidResult, task.ID, task.ObjectiveID)
		}
		if _, ok := tasks[task.ID]; ok {
			return fmt.Errorf("%w: duplicate plan task %q", ErrInvalidResult, task.ID)
		}
		if _, ok := taskObjectives[task.ObjectiveID]; ok {
			return fmt.Errorf("%w: objective %q has more than one plan task", ErrInvalidResult, task.ObjectiveID)
		}
		tasks[task.ID] = task
		taskObjectives[task.ObjectiveID] = struct{}{}
		switch task.Kind {
		case PlanTaskKindProcedure:
		case PlanTaskKindFindingEvaluation:
			findingTasks++
			findingBindings += len(task.RuntimeIDs)
			if task.RuleID == "" || len(task.RuntimeIDs) == 0 || task.MaxAge == "" || task.EvaluationMode != EvaluationModePointInTime {
				return fmt.Errorf("%w: finding evaluation task %q is incomplete", ErrInvalidResult, task.ID)
			}
			if len(task.RuntimeIDs) > MaxFindingEvaluationTaskRuntimes {
				return fmt.Errorf("%w: finding evaluation task %q has too many runtimes", ErrInvalidResult, task.ID)
			}
			maxAge, err := time.ParseDuration(task.MaxAge)
			if err != nil || maxAge <= 0 {
				return fmt.Errorf("%w: finding evaluation task %q has invalid max_age", ErrInvalidResult, task.ID)
			}
		default:
			return fmt.Errorf("%w: plan task %q has unsupported kind %q", ErrInvalidResult, task.ID, task.Kind)
		}
	}
	if len(taskObjectives) != len(objectives) {
		return fmt.Errorf("%w: plan tasks do not cover every scoped objective", ErrInvalidResult)
	}
	if findingTasks > MaxFindingEvaluationTasks || findingBindings > MaxFindingEvaluationBindings {
		return fmt.Errorf("%w: finding evaluation task bounds exceeded", ErrInvalidResult)
	}
	if len(execution.OrderedTaskIDs) != len(tasks) {
		return fmt.Errorf("%w: ordered task ids do not cover every plan task", ErrInvalidResult)
	}
	seenOrdered := make(map[string]struct{}, len(execution.OrderedTaskIDs))
	for _, taskID := range execution.OrderedTaskIDs {
		if _, ok := tasks[taskID]; !ok {
			return fmt.Errorf("%w: ordered task %q is not defined", ErrInvalidResult, taskID)
		}
		if _, ok := seenOrdered[taskID]; ok {
			return fmt.Errorf("%w: ordered task %q is duplicated", ErrInvalidResult, taskID)
		}
		seenOrdered[taskID] = struct{}{}
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
