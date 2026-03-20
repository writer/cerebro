package autonomous

import "time"

type WorkflowID string

const (
	WorkflowCredentialExposureResponse WorkflowID = "credential_exposure_response"
)

type RunStatus string

const (
	RunStatusPending          RunStatus = "pending"
	RunStatusAwaitingApproval RunStatus = "awaiting_approval"
	RunStatusRunning          RunStatus = "running"
	RunStatusCompleted        RunStatus = "completed"
	RunStatusFailed           RunStatus = "failed"
	RunStatusCanceled         RunStatus = "canceled"
)

type RunStage string

const (
	RunStageAnalyze          RunStage = "analyze"
	RunStageAwaitingApproval RunStage = "approval"
	RunStageExecute          RunStage = "execute"
	RunStageValidate         RunStage = "validate"
	RunStageClosed           RunStage = "closed"
)

type RunRecord struct {
	ID                 string         `json:"id"`
	WorkflowID         WorkflowID     `json:"workflow_id"`
	WorkflowName       string         `json:"workflow_name"`
	Status             RunStatus      `json:"status"`
	Stage              RunStage       `json:"stage"`
	RequestedBy        string         `json:"requested_by,omitempty"`
	SubmittedAt        time.Time      `json:"submitted_at"`
	StartedAt          *time.Time     `json:"started_at,omitempty"`
	CompletedAt        *time.Time     `json:"completed_at,omitempty"`
	UpdatedAt          time.Time      `json:"updated_at"`
	Error              string         `json:"error,omitempty"`
	Summary            string         `json:"summary,omitempty"`
	SecretNodeID       string         `json:"secret_node_id,omitempty"`
	WorkloadID         string         `json:"workload_id,omitempty"`
	PrincipalID        string         `json:"principal_id,omitempty"`
	Provider           string         `json:"provider,omitempty"`
	ImpactedTargetIDs  []string       `json:"impacted_target_ids,omitempty"`
	ObservationID      string         `json:"observation_id,omitempty"`
	DetectionClaimID   string         `json:"detection_claim_id,omitempty"`
	RemediationClaimID string         `json:"remediation_claim_id,omitempty"`
	DecisionID         string         `json:"decision_id,omitempty"`
	OutcomeID          string         `json:"outcome_id,omitempty"`
	ActionExecutionID  string         `json:"action_execution_id,omitempty"`
	RequireApproval    bool           `json:"require_approval"`
	Inputs             map[string]any `json:"inputs,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type RunEvent struct {
	Sequence   int64          `json:"sequence"`
	RecordedAt time.Time      `json:"recorded_at"`
	Status     RunStatus      `json:"status"`
	Stage      RunStage       `json:"stage"`
	Message    string         `json:"message"`
	Data       map[string]any `json:"data,omitempty"`
}

type RunListOptions struct {
	Statuses           []RunStatus
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}
