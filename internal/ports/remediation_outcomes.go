package ports

import (
	"context"
	"time"
)

// RemediationOutcomeRecord is one immutable, derived observation of a
// remediation attempt. It points at canonical records; it is not an execution
// or verification authority.
type RemediationOutcomeRecord struct {
	ID string
	RemediationOutcomeBinding
	VerificationState  string
	CensoredReason     string
	SourceHealth       string
	ProviderSucceeded  bool
	VerifiedResolution bool
	RemediationOutcomeTiming
	Digest    string
	CreatedAt time.Time
}

// RemediationOutcomeBinding identifies the exact finding, rule, action, and
// verification versions used for one derived result.
type RemediationOutcomeBinding struct {
	TenantID                  string
	EpisodeID                 string
	FindingID                 string
	FindingFingerprint        string
	FindingRevision           string
	RuleID                    string
	RuleVersion               string
	DecisionID                string
	ProposalID                string
	ActionID                  string
	ActionType                string
	ActionVersion             string
	ExecutionID               string
	ProviderCapabilityVersion string
	VerificationID            string
	EvaluationRunID           string
	SourceRuntimeID           string
}

// RemediationOutcomeTiming preserves the action-to-verification interval.
type RemediationOutcomeTiming struct {
	ActionCompletedAt   time.Time
	VerifiedAt          time.Time
	ObservedAt          time.Time
	VerificationLatency time.Duration
}

// ResolutionEpisodeRecord is the latest derived state for one open-to-close
// finding interval. It is rebuildable from finding and verification history.
type ResolutionEpisodeRecord struct {
	EpisodeID          string
	TenantID           string
	FindingID          string
	FindingFingerprint string
	FindingRevision    string
	RuleID             string
	RuleVersion        string
	ResolutionType     string
	VerificationID     string
	OutcomeID          string
	SourceHealth       string
	SourceRuntimeID    string
	DurabilityState    string
	OpenedAt           time.Time
	ResolvedAt         time.Time
	ReopenedAt         time.Time
	AsOf               time.Time
	TimeToResolution   time.Duration
	TimeToRecurrence   time.Duration
	RevisionDigest     string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type ListRemediationOutcomesRequest struct {
	TenantID          string
	FindingID         string
	RuleID            string
	ActionType        string
	VerificationState string
	Limit             uint32
}

type ListResolutionEpisodesRequest struct {
	TenantID        string
	FindingID       string
	RuleID          string
	DurabilityState string
	Limit           uint32
}

// RemediationOutcomeStore persists the rebuildable remediation analytics read
// model in the existing Postgres current-state boundary.
type RemediationOutcomeStore interface {
	StateStore
	RecordRemediationOutcome(context.Context, *RemediationOutcomeRecord) (*RemediationOutcomeRecord, error)
	UpsertResolutionEpisode(context.Context, *ResolutionEpisodeRecord) (*ResolutionEpisodeRecord, error)
	ListRemediationOutcomes(context.Context, ListRemediationOutcomesRequest) ([]*RemediationOutcomeRecord, error)
	ListResolutionEpisodes(context.Context, ListResolutionEpisodesRequest) ([]*ResolutionEpisodeRecord, error)
}
