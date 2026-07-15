// Package verifiedaccessaction defines a provider-free contract for access
// revocation proposals, approval, receipt ingestion, and independent closure.
package verifiedaccessaction

import (
	"errors"
	"time"

	"github.com/writer/cerebro/internal/graphactions"
)

const (
	SchemaVersion           = "verified-access-action.v1"
	TransitionSchemaVersion = "verified-access-action-transition.v1"

	StatusProposed    = "proposed"
	StatusPreflighted = "preflighted"
	StatusApproved    = "approved"
	StatusExecuted    = "execution_receipt_ingested"
	StatusClosed      = "verified_closed"
	StatusReopened    = "reopened"

	ResultProposed                = "proposal_recorded"
	ResultPreflightPassed         = "preflight_passed"
	ResultApproved                = "human_approval_recorded"
	ResultReceiptIngested         = "execution_receipt_ingested"
	ResultVerifiedClosed          = "independently_verified_closed"
	ResultReopenedMismatch        = "reopened_verification_mismatch"
	ResultReopenedSourceUnhealthy = "reopened_source_unhealthy"
)

var (
	ErrInvalid              = errors.New("invalid verified access action")
	ErrState                = errors.New("verified access action state conflict")
	ErrStale                = errors.New("stale verified access action input")
	ErrSeparationOfDuty     = errors.New("verified access action separation of duty failed")
	ErrSourceUnhealthy      = errors.New("verified access action source is unhealthy")
	ErrVerificationMismatch = errors.New("verified access action verification mismatch")
)

type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ActionDefinition struct {
	Metadata graphactions.ActionMetadata `json:"metadata"`
	Version  string                      `json:"version"`
}

type TargetBinding struct {
	TargetID         string `json:"target_id"`
	SubjectURN       string `json:"subject_urn"`
	SubjectRevision  string `json:"subject_revision"`
	ResourceURN      string `json:"resource_urn"`
	ResourceRevision string `json:"resource_revision"`
	SourceRuntimeID  string `json:"source_runtime_id"`
	SourceRevision   string `json:"source_revision"`
}

type RollbackPlan struct {
	ActionID          string            `json:"action_id"`
	DefinitionVersion string            `json:"definition_version"`
	Parameters        map[string]string `json:"parameters"`
	Steps             []string          `json:"steps"`
}

type ProposalInput struct {
	TenantID       string            `json:"tenant_id"`
	Definition     ActionDefinition  `json:"definition"`
	Binding        TargetBinding     `json:"binding"`
	Parameters     map[string]string `json:"parameters"`
	Proposer       Actor             `json:"proposer"`
	IdempotencyKey string            `json:"idempotency_key"`
	Rollback       RollbackPlan      `json:"rollback"`
	Reason         string            `json:"reason"`
	ProposedAt     time.Time         `json:"proposed_at"`
}

type Record struct {
	SchemaVersion        string               `json:"schema_version"`
	ID                   string               `json:"id"`
	Digest               string               `json:"digest"`
	TenantID             string               `json:"tenant_id"`
	Status               string               `json:"status"`
	Definition           ActionDefinition     `json:"definition"`
	Binding              TargetBinding        `json:"binding"`
	Parameters           map[string]string    `json:"parameters"`
	Proposer             Actor                `json:"proposer"`
	IdempotencyKey       string               `json:"idempotency_key"`
	Rollback             RollbackPlan         `json:"rollback"`
	Reason               string               `json:"reason"`
	ProposedAt           time.Time            `json:"proposed_at"`
	Preflight            *PreflightReceipt    `json:"preflight,omitempty"`
	Approval             *ApprovalReceipt     `json:"approval,omitempty"`
	Execution            *ExecutionReceipt    `json:"execution,omitempty"`
	Verification         *VerificationReceipt `json:"verification,omitempty"`
	LastTransitionDigest string               `json:"last_transition_digest"`
}

type PreflightInput struct {
	ProposalDigest   string        `json:"proposal_digest"`
	Binding          TargetBinding `json:"binding"`
	ParametersDigest string        `json:"parameters_digest"`
	RollbackDigest   string        `json:"rollback_digest"`
	Actor            Actor         `json:"actor"`
	ExpectedEffect   string        `json:"expected_effect"`
	TargetExists     bool          `json:"target_exists"`
	WouldChange      bool          `json:"would_change"`
	SourceHealthy    bool          `json:"source_healthy"`
	ProviderMutation bool          `json:"provider_mutation"`
	SimulatedAt      time.Time     `json:"simulated_at"`
	ValidUntil       time.Time     `json:"valid_until"`
}

type PreflightReceipt struct {
	PreflightInput
	Digest string `json:"digest"`
}

type ApprovalInput struct {
	ProposalDigest  string    `json:"proposal_digest"`
	PreflightDigest string    `json:"preflight_digest"`
	Actor           Actor     `json:"actor"`
	Reason          string    `json:"reason"`
	ApprovedAt      time.Time `json:"approved_at"`
}

type ApprovalReceipt struct {
	ApprovalInput
	Digest string `json:"digest"`
}

type ExecutionInput struct {
	GraphAction           graphactions.GraphAction `json:"graph_action"`
	DefinitionVersion     string                   `json:"definition_version"`
	ProposalDigest        string                   `json:"proposal_digest"`
	PreflightDigest       string                   `json:"preflight_digest"`
	ApprovalDigest        string                   `json:"approval_digest"`
	ParametersDigest      string                   `json:"parameters_digest"`
	Binding               TargetBinding            `json:"binding"`
	ExecutedBy            Actor                    `json:"executed_by"`
	IngestedBy            Actor                    `json:"ingested_by"`
	ProviderReceiptDigest string                   `json:"provider_receipt_digest"`
	OccurredAt            time.Time                `json:"occurred_at"`
}

type ExecutionReceipt struct {
	ExecutionInput
	Digest string `json:"digest"`
}

type EvidenceReference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type VerificationInput struct {
	ExecutionDigest        string              `json:"execution_digest"`
	PreviousSourceRevision string              `json:"previous_source_revision"`
	Binding                TargetBinding       `json:"binding"`
	ExpectedEffect         string              `json:"expected_effect"`
	Effective              bool                `json:"effective"`
	SourceHealthy          bool                `json:"source_healthy"`
	Evidence               []EvidenceReference `json:"evidence"`
	Actor                  Actor               `json:"actor"`
	VerifiedAt             time.Time           `json:"verified_at"`
}

type VerificationReceipt struct {
	VerificationInput
	Digest string `json:"digest"`
}

type TransitionReceipt struct {
	SchemaVersion            string    `json:"schema_version"`
	ID                       string    `json:"id"`
	Digest                   string    `json:"digest"`
	TenantID                 string    `json:"tenant_id"`
	ActionID                 string    `json:"action_id"`
	FromStatus               string    `json:"from_status"`
	ToStatus                 string    `json:"to_status"`
	PreviousTransitionDigest string    `json:"previous_transition_digest,omitempty"`
	RecordDigest             string    `json:"record_digest"`
	ResultCode               string    `json:"result_code"`
	Actor                    Actor     `json:"actor"`
	OccurredAt               time.Time `json:"occurred_at"`
}

type Metrics struct {
	Status             string `json:"status"`
	ResultCode         string `json:"result_code"`
	PreflightPassed    bool   `json:"preflight_passed"`
	Approved           bool   `json:"approved"`
	ReceiptAccepted    bool   `json:"receipt_accepted"`
	VerificationClosed bool   `json:"verification_closed"`
	Reopened           bool   `json:"reopened"`
}

type Outcome struct {
	Record     Record            `json:"record"`
	Transition TransitionReceipt `json:"transition"`
	Metrics    Metrics           `json:"metrics"`
}
