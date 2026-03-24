package forensics

import (
	"time"

	"github.com/writer/cerebro/internal/workloadscan"
)

type CaptureStatus string

const (
	CaptureStatusPending  CaptureStatus = "pending"
	CaptureStatusCaptured CaptureStatus = "captured"
	CaptureStatusPartial  CaptureStatus = "partial"
	CaptureStatusFailed   CaptureStatus = "failed"
)

type EvidenceStatus string

const (
	EvidenceStatusRecorded EvidenceStatus = "recorded"
	EvidenceStatusVerified EvidenceStatus = "verified"
)

type CustodyEvent struct {
	Step       string         `json:"step"`
	Actor      string         `json:"actor,omitempty"`
	Location   string         `json:"location,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	RecordedAt time.Time      `json:"recorded_at"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type CaptureRecord struct {
	ID             string                          `json:"id"`
	IncidentID     string                          `json:"incident_id,omitempty"`
	WorkloadID     string                          `json:"workload_id,omitempty"`
	Status         CaptureStatus                   `json:"status"`
	Target         workloadscan.VMTarget           `json:"target"`
	RequestedBy    string                          `json:"requested_by,omitempty"`
	Reason         string                          `json:"reason,omitempty"`
	RetentionDays  int                             `json:"retention_days,omitempty"`
	SubmittedAt    time.Time                       `json:"submitted_at"`
	CompletedAt    *time.Time                      `json:"completed_at,omitempty"`
	RetainUntil    *time.Time                      `json:"retain_until,omitempty"`
	Snapshots      []workloadscan.SnapshotArtifact `json:"snapshots,omitempty"`
	ChainOfCustody []CustodyEvent                  `json:"chain_of_custody,omitempty"`
	Error          string                          `json:"error,omitempty"`
	Metadata       map[string]any                  `json:"metadata,omitempty"`
}

type CaptureListOptions struct {
	Statuses   []CaptureStatus
	IncidentID string
	WorkloadID string
	Limit      int
	Offset     int
}

type RemediationEvidenceRecord struct {
	ID                     string         `json:"id"`
	IncidentID             string         `json:"incident_id,omitempty"`
	WorkloadID             string         `json:"workload_id,omitempty"`
	BeforeCaptureID        string         `json:"before_capture_id,omitempty"`
	AfterCaptureID         string         `json:"after_capture_id,omitempty"`
	RemediationExecutionID string         `json:"remediation_execution_id,omitempty"`
	ActionSummary          string         `json:"action_summary,omitempty"`
	Actor                  string         `json:"actor,omitempty"`
	Status                 EvidenceStatus `json:"status"`
	CreatedAt              time.Time      `json:"created_at"`
	Notes                  string         `json:"notes,omitempty"`
	Metadata               map[string]any `json:"metadata,omitempty"`
	ChainOfCustody         []CustodyEvent `json:"chain_of_custody,omitempty"`
}

type EvidenceListOptions struct {
	IncidentID string
	WorkloadID string
	Limit      int
	Offset     int
}

type RemediationExecutionSummary struct {
	ID          string     `json:"id"`
	RuleID      string     `json:"rule_id,omitempty"`
	RuleName    string     `json:"rule_name,omitempty"`
	Status      string     `json:"status,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

type EvidencePackage struct {
	ID                   string                       `json:"id"`
	GeneratedAt          time.Time                    `json:"generated_at"`
	IncidentID           string                       `json:"incident_id,omitempty"`
	WorkloadID           string                       `json:"workload_id,omitempty"`
	RemediationEvidence  *RemediationEvidenceRecord   `json:"remediation_evidence,omitempty"`
	RemediationExecution *RemediationExecutionSummary `json:"remediation_execution,omitempty"`
	Captures             []CaptureRecord              `json:"captures,omitempty"`
	ChainOfCustody       []CustodyEvent               `json:"chain_of_custody,omitempty"`
}
