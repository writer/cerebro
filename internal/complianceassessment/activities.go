package complianceassessment

import "time"

type ActivityMethod string

const (
	ActivityExamine   ActivityMethod = "examine"
	ActivityInterview ActivityMethod = "interview"
	ActivityTest      ActivityMethod = "test"
)

type ActivityExecutionState string

const (
	ActivityQueued    ActivityExecutionState = "queued"
	ActivityRunning   ActivityExecutionState = "running"
	ActivityCompleted ActivityExecutionState = "completed"
	ActivityFailed    ActivityExecutionState = "failed"
	ActivityError     ActivityExecutionState = "error"
	ActivitySkipped   ActivityExecutionState = "skipped"
	ActivityCancelled ActivityExecutionState = "cancelled"
)

// AssessmentActivity records what was performed. ExecutionState is operational
// state and must not be interpreted as a control outcome.
type AssessmentActivity struct {
	ID               string                 `json:"id"`
	RunID            string                 `json:"run_id"`
	ObjectiveID      string                 `json:"objective_id"`
	PlanTaskID       string                 `json:"plan_task_id"`
	Method           ActivityMethod         `json:"method"`
	Procedure        string                 `json:"procedure"`
	ExpectedResult   string                 `json:"expected_result"`
	OperatorRef      string                 `json:"operator_ref,omitempty"`
	ToolRef          string                 `json:"tool_ref,omitempty"`
	ExecutionState   ActivityExecutionState `json:"execution_state"`
	FailureCode      string                 `json:"failure_code,omitempty"`
	SubjectCount     uint64                 `json:"subject_count"`
	OutputReferences []string               `json:"output_references,omitempty"`
	StartedAt        time.Time              `json:"started_at,omitempty"`
	FinishedAt       time.Time              `json:"finished_at,omitempty"`
}
