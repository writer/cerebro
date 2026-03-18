package actionengine

import "time"

type SeverityMatchMode string

const (
	SeverityMatchExact   SeverityMatchMode = "exact"
	SeverityMatchMinimum SeverityMatchMode = "minimum"
)

type FailurePolicy string

const (
	FailurePolicyAbort    FailurePolicy = "abort"
	FailurePolicyContinue FailurePolicy = "continue"
)

type Status string

const (
	StatusPending          Status = "pending"
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusRunning          Status = "running"
	StatusCompleted        Status = "completed"
	StatusFailed           Status = "failed"
	StatusCanceled         Status = "canceled"
)

type Signal struct {
	ID           string            `json:"id"`
	Kind         string            `json:"kind"`
	Severity     string            `json:"severity,omitempty"`
	PolicyID     string            `json:"policy_id,omitempty"`
	Category     string            `json:"category,omitempty"`
	RuleID       string            `json:"rule_id,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	ResourceType string            `json:"resource_type,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Data         map[string]any    `json:"data,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type Trigger struct {
	Kind              string            `json:"kind"`
	Severity          string            `json:"severity,omitempty"`
	SeverityMatchMode SeverityMatchMode `json:"severity_match_mode,omitempty"`
	PolicyID          string            `json:"policy_id,omitempty"`
	Category          string            `json:"category,omitempty"`
	RuleID            string            `json:"rule_id,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	Conditions        map[string]string `json:"conditions,omitempty"`
}

type Step struct {
	ID               string            `json:"id"`
	Type             string            `json:"type"`
	Parameters       map[string]string `json:"parameters,omitempty"`
	RequiresApproval bool              `json:"requires_approval,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
	OnFailure        FailurePolicy     `json:"on_failure,omitempty"`
}

type Playbook struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Enabled         bool      `json:"enabled"`
	Priority        int       `json:"priority,omitempty"`
	Triggers        []Trigger `json:"triggers"`
	Steps           []Step    `json:"steps"`
	RequireApproval bool      `json:"require_approval,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type ActionResult struct {
	StepID      string     `json:"step_id,omitempty"`
	Type        string     `json:"type"`
	Status      Status     `json:"status"`
	Output      string     `json:"output,omitempty"`
	Error       string     `json:"error,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Duration    string     `json:"duration,omitempty"`
}

type Execution struct {
	ID           string         `json:"id"`
	PlaybookID   string         `json:"playbook_id"`
	PlaybookName string         `json:"playbook_name"`
	SignalID     string         `json:"signal_id,omitempty"`
	Status       Status         `json:"status"`
	ResourceID   string         `json:"resource_id,omitempty"`
	ResourceType string         `json:"resource_type,omitempty"`
	TriggerData  map[string]any `json:"trigger_data,omitempty"`
	Results      []ActionResult `json:"results"`
	ApprovedBy   string         `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time     `json:"approved_at,omitempty"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	Error        string         `json:"error,omitempty"`
}

type Event struct {
	Type        string         `json:"type"`
	ExecutionID string         `json:"execution_id"`
	RecordedAt  time.Time      `json:"recorded_at"`
	Data        map[string]any `json:"data,omitempty"`
	Sequence    int64          `json:"sequence"`
}
