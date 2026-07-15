package complianceassessment

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

func TestValidatePlanEnforcesFindingEvaluationBoundsAndCoverage(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	valid := planForValidation(now, []PlanTask{findingTaskForValidation(1, 1)})
	if err := validatePlan(normalizePlan(valid)); err != nil {
		t.Fatalf("validatePlan(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*AssessmentPlanRevision)
	}{
		{
			name: "objective without task",
			mutate: func(plan *AssessmentPlanRevision) {
				plan.Scope.ObjectiveIDs = append(plan.Scope.ObjectiveIDs, "objective-2")
			},
		},
		{
			name: "duplicate objective task",
			mutate: func(plan *AssessmentPlanRevision) {
				duplicate := findingTaskForValidation(2, 1)
				duplicate.ObjectiveID = "objective-1"
				plan.Execution.Tasks = append(plan.Execution.Tasks, duplicate)
				plan.Execution.OrderedTaskIDs = append(plan.Execution.OrderedTaskIDs, duplicate.ID)
			},
		},
		{
			name: "unknown ordered task",
			mutate: func(plan *AssessmentPlanRevision) {
				plan.Execution.OrderedTaskIDs[0] = "task-unknown"
			},
		},
		{
			name: "invalid max age",
			mutate: func(plan *AssessmentPlanRevision) {
				plan.Execution.Tasks[0].MaxAge = "later"
			},
		},
		{
			name: "too many runtimes for task",
			mutate: func(plan *AssessmentPlanRevision) {
				plan.Execution.Tasks[0] = findingTaskForValidation(1, MaxFindingEvaluationTaskRuntimes+1)
			},
		},
		{
			name: "too many finding tasks",
			mutate: func(plan *AssessmentPlanRevision) {
				plan.Scope.ObjectiveIDs = nil
				plan.Execution.Tasks = nil
				plan.Execution.OrderedTaskIDs = nil
				for index := 1; index <= MaxFindingEvaluationTasks+1; index++ {
					task := findingTaskForValidation(index, 1)
					plan.Scope.ObjectiveIDs = append(plan.Scope.ObjectiveIDs, task.ObjectiveID)
					plan.Execution.Tasks = append(plan.Execution.Tasks, task)
					plan.Execution.OrderedTaskIDs = append(plan.Execution.OrderedTaskIDs, task.ID)
				}
			},
		},
		{
			name: "too many runtime bindings",
			mutate: func(plan *AssessmentPlanRevision) {
				plan.Scope.ObjectiveIDs = nil
				plan.Execution.Tasks = nil
				plan.Execution.OrderedTaskIDs = nil
				for index := 1; index <= 6; index++ {
					task := findingTaskForValidation(index, MaxFindingEvaluationTaskRuntimes)
					plan.Scope.ObjectiveIDs = append(plan.Scope.ObjectiveIDs, task.ObjectiveID)
					plan.Execution.Tasks = append(plan.Execution.Tasks, task)
					plan.Execution.OrderedTaskIDs = append(plan.Execution.OrderedTaskIDs, task.ID)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := valid
			plan.Scope.ObjectiveIDs = append([]string(nil), valid.Scope.ObjectiveIDs...)
			plan.Execution.Tasks = append([]PlanTask(nil), valid.Execution.Tasks...)
			plan.Execution.OrderedTaskIDs = append([]string(nil), valid.Execution.OrderedTaskIDs...)
			test.mutate(&plan)
			if err := validatePlan(normalizePlan(plan)); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("validatePlan() error = %v, want ErrInvalidResult", err)
			}
		})
	}
}

func planForValidation(now time.Time, tasks []PlanTask) AssessmentPlanRevision {
	objectives := make([]string, 0, len(tasks))
	ordered := make([]string, 0, len(tasks))
	for _, task := range tasks {
		objectives = append(objectives, task.ObjectiveID)
		ordered = append(ordered, task.ID)
	}
	return AssessmentPlanRevision{
		ID: "plan-1", TenantID: "tenant-1", RevisionID: "plan-revision-1", Version: 1,
		Status: PlanDraft, Name: "Access assessment",
		Scope: PlanScope{
			ProgramID: "program-1", ScopeRevisionID: "scope-revision-1",
			ImplementationRevisions: []string{"implementation-revision-1"}, ObjectiveIDs: objectives,
		},
		Execution: PlanExecution{
			Methods: []string{"test"}, Depth: "moderate", CoverageTarget: "complete", AssuranceTarget: "medium",
			Tasks: tasks, OrderedTaskIDs: ordered, CancellationRule: "stop_after_checkpoint",
		},
		Governance: PlanGovernance{
			OwnerID: "owner-1", AssessorIDs: []string{"assessor-1"}, ApproverIDs: []string{"approver-1"},
			IndependenceRule: "approver_not_assessor", RulesOfEngagement: "Read-only source access.",
		},
		CreatedAt: now, CreatedBy: "owner-1",
	}
}

func findingTaskForValidation(index, runtimeCount int) PlanTask {
	runtimeIDs := make([]string, 0, runtimeCount)
	for runtimeIndex := 1; runtimeIndex <= runtimeCount; runtimeIndex++ {
		runtimeIDs = append(runtimeIDs, fmt.Sprintf("runtime-%d-%d", index, runtimeIndex))
	}
	return PlanTask{
		ID: fmt.Sprintf("task-%d", index), ObjectiveID: fmt.Sprintf("objective-%d", index),
		ControlRef: compliance.ControlRef{FrameworkID: "framework-1", ControlID: fmt.Sprintf("control-%d", index)},
		Kind:       PlanTaskKindFindingEvaluation, RuleID: fmt.Sprintf("rule-%d", index), RuntimeIDs: runtimeIDs,
		MaxAge: "24h", EvaluationMode: EvaluationModePointInTime,
	}
}
