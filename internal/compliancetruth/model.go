package compliancetruth

import (
	"time"

	"github.com/writer/cerebro/internal/trustclaims"
)

const (
	RevisionSchemaVersion     = "compliance-truth-revision.v1"
	SupersessionSchemaVersion = "compliance-truth-supersession.v1"
	ResolutionSchemaVersion   = "compliance-conflict-resolution.v1"

	PositionSupports = "supports"
	PositionRefutes  = "refutes"

	EvaluationUnknown    = "unknown"
	EvaluationQualified  = "qualified"
	EvaluationConflicted = "conflicted"

	ConflictValueDisagreement = "value_disagreement"
	ConflictClaimMissing      = "claim_missing"
	ConflictClaimState        = "claim_state"
	ConflictCitationState     = "citation_state"

	ResolutionAcceptRevision = "accept_revision"
)

type Interval struct {
	From time.Time  `json:"from"`
	To   *time.Time `json:"to,omitempty"`
}

// TruthRevision is one immutable assertion revision. ValidTime describes when
// the assertion applies; RecordedTime describes when Cerebro learned it.
type TruthRevision struct {
	SchemaVersion  string                  `json:"schema_version"`
	TenantID       string                  `json:"tenant_id"`
	AssertionID    string                  `json:"assertion_id"`
	RevisionID     string                  `json:"revision_id"`
	Version        int                     `json:"version"`
	Subject        trustclaims.ResourceRef `json:"subject"`
	Predicate      string                  `json:"predicate"`
	Value          string                  `json:"value"`
	ValidTime      Interval                `json:"valid_time"`
	RecordedTime   Interval                `json:"recorded_time"`
	ClaimBindings  []ClaimBinding          `json:"claim_bindings"`
	PreviousDigest string                  `json:"previous_digest,omitempty"`
	Digest         string                  `json:"digest"`
}

type ClaimBinding struct {
	ReceiptID     string `json:"receipt_id"`
	ReceiptDigest string `json:"receipt_digest"`
	Position      string `json:"position"`
}

type RevisionInput struct {
	TenantID      string
	AssertionID   string
	RevisionID    string
	Version       int
	Subject       trustclaims.ResourceRef
	Predicate     string
	Value         string
	ValidTime     Interval
	RecordedAt    time.Time
	ClaimBindings []ClaimBinding
}

// SupersessionReceipt closes a prior revision's recorded-time interval without
// mutating that prior revision.
type SupersessionReceipt struct {
	SchemaVersion   string    `json:"schema_version"`
	TenantID        string    `json:"tenant_id"`
	AssertionID     string    `json:"assertion_id"`
	PriorDigest     string    `json:"prior_digest"`
	SuccessorDigest string    `json:"successor_digest"`
	RecordedAt      time.Time `json:"recorded_at"`
	Digest          string    `json:"digest"`
}

type Conflict struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	InputDigests     []string `json:"input_digests"`
	Values           []string `json:"values,omitempty"`
	CitationIDs      []string `json:"citation_ids,omitempty"`
	Reason           string   `json:"reason"`
	Resolvable       bool     `json:"resolvable"`
	ResolutionDigest string   `json:"resolution_digest,omitempty"`
}

type ConflictResolutionReceipt struct {
	SchemaVersion          string                       `json:"schema_version"`
	TenantID               string                       `json:"tenant_id"`
	AssertionID            string                       `json:"assertion_id"`
	ConflictID             string                       `json:"conflict_id"`
	InputDigests           []string                     `json:"input_digests"`
	Decision               string                       `json:"decision"`
	SelectedRevisionDigest string                       `json:"selected_revision_digest"`
	Reviewer               trustclaims.ReviewerApproval `json:"reviewer"`
	RecordedAt             time.Time                    `json:"recorded_at"`
	Digest                 string                       `json:"digest"`
}

type ResolutionInput struct {
	TenantID               string
	AssertionID            string
	ConflictID             string
	InputDigests           []string
	Decision               string
	SelectedRevisionDigest string
	Reviewer               trustclaims.ReviewerApproval
	RecordedAt             time.Time
}

type Ledger struct {
	Revisions     []TruthRevision
	Supersessions []SupersessionReceipt
	Resolutions   []ConflictResolutionReceipt
	Claims        []trustclaims.ClaimReceipt
}

type EvaluationQuery struct {
	TenantID    string
	AssertionID string
	AsKnownAt   time.Time
	EffectiveAt time.Time
}

type TruthEvaluation struct {
	TenantID           string     `json:"tenant_id"`
	AssertionID        string     `json:"assertion_id"`
	AsKnownAt          time.Time  `json:"as_known_at"`
	EffectiveAt        time.Time  `json:"effective_at"`
	State              string     `json:"state"`
	Qualified          bool       `json:"qualified"`
	Shareable          bool       `json:"shareable"`
	Value              string     `json:"value,omitempty"`
	RevisionDigests    []string   `json:"revision_digests,omitempty"`
	Conflicts          []Conflict `json:"conflicts,omitempty"`
	ResolvedConflicts  []Conflict `json:"resolved_conflicts,omitempty"`
	ResolutionReceipts []string   `json:"resolution_receipts,omitempty"`
	Digest             string     `json:"digest"`
}
