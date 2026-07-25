package verifiedaccessaction

import "time"

const (
	BlockerPreflightRequired       = "preflight_required"
	BlockerHumanApprovalRequired   = "human_approval_required"
	BlockerExecutionClaimRequired  = "execution_claim_required"
	BlockerProviderResultPending   = "provider_result_pending"
	BlockerProviderReconcile       = "provider_reconciliation_required"
	BlockerFreshVerification       = "fresh_verification_required"
	BlockerFreshVerificationFailed = "fresh_verification_failed"
)

// Summary is the bounded read model exposed to operators. It omits action
// parameters, rollback instructions, actor identifiers, and receipt bodies.
type Summary struct {
	ActionID             string     `json:"action_id"`
	FindingID            string     `json:"finding_id"`
	Action               string     `json:"action"`
	Provider             string     `json:"provider"`
	Status               string     `json:"status"`
	BlockerCode          string     `json:"blocker_code,omitempty"`
	RecordDigest         string     `json:"record_digest"`
	TransitionDigest     string     `json:"transition_digest"`
	ProviderExternalID   string     `json:"provider_external_id,omitempty"`
	ProviderStatus       string     `json:"provider_status,omitempty"`
	ProviderSucceeded    bool       `json:"provider_succeeded"`
	VerifiedClosed       bool       `json:"verified_closed"`
	AttentionRequired    bool       `json:"attention_required"`
	ProposedAt           time.Time  `json:"proposed_at"`
	ApprovedAt           *time.Time `json:"approved_at,omitempty"`
	ExecutionClaimedAt   *time.Time `json:"execution_claimed_at,omitempty"`
	SubmissionObservedAt *time.Time `json:"submission_observed_at,omitempty"`
	NextReconcileAt      *time.Time `json:"next_reconcile_at,omitempty"`
	ExecutedAt           *time.Time `json:"executed_at,omitempty"`
	VerifiedAt           *time.Time `json:"verified_at,omitempty"`
}

// Summarize verifies the canonical record before producing its operator read
// model. Provider success remains distinct from independent verification.
func Summarize(record Record) (Summary, error) {
	if err := VerifyRecord(record); err != nil {
		return Summary{}, err
	}
	result := Summary{
		ActionID:         record.ID,
		FindingID:        record.FindingID,
		Action:           record.Definition.Metadata.ID,
		Provider:         record.Definition.Metadata.Provider,
		Status:           record.Status,
		BlockerCode:      blockerCode(record.Status),
		RecordDigest:     record.Digest,
		TransitionDigest: record.LastTransitionDigest,
		ProposedAt:       record.ProposedAt,
		AttentionRequired: record.Status == StatusUnknown ||
			record.Status == StatusReopened,
	}
	if record.Approval != nil {
		result.ApprovedAt = timePointer(record.Approval.ApprovedAt)
	}
	if record.ExecutionClaim != nil {
		result.ExecutionClaimedAt = timePointer(record.ExecutionClaim.ClaimedAt)
	}
	if record.SubmissionUnknown != nil {
		result.SubmissionObservedAt = timePointer(record.SubmissionUnknown.ObservedAt)
		result.NextReconcileAt = timePointer(record.SubmissionUnknown.NextReconcileAt)
	}
	if record.Execution != nil {
		action := record.Execution.GraphAction
		result.ProviderExternalID = action.ExternalID
		result.ProviderStatus = first(action.ExternalStatus, action.Status)
		result.ProviderSucceeded = true
		result.ExecutedAt = timePointer(record.Execution.OccurredAt)
	}
	if record.Verification != nil {
		result.VerifiedAt = timePointer(record.Verification.VerifiedAt)
	}
	result.VerifiedClosed = record.Status == StatusClosed
	return result, nil
}

func blockerCode(status string) string {
	switch status {
	case StatusProposed:
		return BlockerPreflightRequired
	case StatusPreflighted:
		return BlockerHumanApprovalRequired
	case StatusApproved:
		return BlockerExecutionClaimRequired
	case StatusClaimed:
		return BlockerProviderResultPending
	case StatusUnknown:
		return BlockerProviderReconcile
	case StatusExecuted:
		return BlockerFreshVerification
	case StatusReopened:
		return BlockerFreshVerificationFailed
	default:
		return ""
	}
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}
