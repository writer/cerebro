package ports

import (
	"context"
	"errors"
	"time"
)

var (
	ErrEvidenceArtifactNotFound = errors.New("evidence artifact not found")
	ErrEvidenceVersionNotFound  = errors.New("evidence version not found")
	ErrEvidenceClaimNotFound    = errors.New("evidence claim not found")
	ErrEvidenceLedgerConflict   = errors.New("evidence ledger version conflict")
	ErrEvidenceAccessDenied     = errors.New("evidence access denied")
)

const (
	EvidenceStateCollected        = "collected"
	EvidenceStateValidationFailed = "validation_failed"
	EvidenceStateUnderReview      = "under_review"
	EvidenceStateApproved         = "approved"
	EvidenceStateStale            = "stale"
	EvidenceStateSuperseded       = "superseded"
	EvidenceStateRevoked          = "revoked"

	EvidenceReviewPending  = "pending"
	EvidenceReviewApproved = "approved"
	EvidenceReviewRejected = "rejected"

	EvidenceLinkDirect    = "direct"
	EvidenceLinkInherited = "inherited"
	EvidenceLinkInferred  = "inferred"

	EvidenceSensitivityPublic       = "public"
	EvidenceSensitivityInternal     = "internal"
	EvidenceSensitivityConfidential = "confidential"
	EvidenceSensitivityRestricted   = "restricted"
)

// EvidenceArtifact is the stable logical record. It never contains bytes.
type EvidenceArtifact struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Type        string    `json:"type"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

type EvidenceRevisionRef struct {
	ID            string    `json:"id"`
	RevisionID    string    `json:"revision_id"`
	Version       uint64    `json:"version"`
	ContentDigest string    `json:"content_digest"`
	LastModified  time.Time `json:"last_modified"`
}

type EvidenceSubjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type EvidenceContentRef struct {
	MediaType     string `json:"media_type"`
	URI           string `json:"uri"`
	ContentDigest string `json:"content_digest"`
	SizeBytes     uint64 `json:"size_bytes"`
}

type EvidenceProvenance struct {
	Producer              string    `json:"producer"`
	ProducerVersion       string    `json:"producer_version,omitempty"`
	CollectedAt           time.Time `json:"collected_at"`
	PeriodStart           time.Time `json:"period_start,omitempty"`
	PeriodEnd             time.Time `json:"period_end,omitempty"`
	SourceRuntimeID       string    `json:"source_runtime_id,omitempty"`
	SourceEventID         string    `json:"source_event_id,omitempty"`
	SourceProofRevisionID string    `json:"source_proof_revision_id"`
	DerivationIDs         []string  `json:"derivation_ids,omitempty"`
}

type EvidenceGovernance struct {
	Sensitivity    string    `json:"sensitivity"`
	AccessPolicy   string    `json:"access_policy"`
	RetentionUntil time.Time `json:"retention_until,omitempty"`
	LegalHold      bool      `json:"legal_hold,omitempty"`
	RedactionState string    `json:"redaction_state,omitempty"`
	ParserQuality  string    `json:"parser_quality,omitempty"`
}

// EvidenceVersion points to immutable bytes in the approved content-addressed
// system or an approved external reference. Content is never stored here.
type EvidenceVersion struct {
	ID               string               `json:"id"`
	TenantID         string               `json:"tenant_id"`
	ArtifactID       string               `json:"artifact_id"`
	Revision         EvidenceRevisionRef  `json:"revision"`
	Content          EvidenceContentRef   `json:"content"`
	Provenance       EvidenceProvenance   `json:"provenance"`
	Governance       EvidenceGovernance   `json:"governance"`
	ValidFrom        time.Time            `json:"valid_from"`
	ValidUntil       time.Time            `json:"valid_until,omitempty"`
	Subjects         []EvidenceSubjectRef `json:"subjects"`
	State            string               `json:"state"`
	QuarantineReason string               `json:"quarantine_reason,omitempty"`
	PredecessorID    string               `json:"predecessor_id,omitempty"`
	RecordedAt       time.Time            `json:"recorded_at"`
}

type EvidenceClaimScope struct {
	ObjectiveID              string               `json:"objective_id"`
	ImplementationRevisionID string               `json:"implementation_revision_id"`
	RequirementID            string               `json:"requirement_id"`
	Subjects                 []EvidenceSubjectRef `json:"subjects"`
	PeriodStart              time.Time            `json:"period_start"`
	PeriodEnd                time.Time            `json:"period_end"`
}

type EvidenceClaimDecision struct {
	ReviewState        string    `json:"review_state"`
	ReviewerID         string    `json:"reviewer_id,omitempty"`
	ReviewReason       string    `json:"review_reason,omitempty"`
	ReviewedAt         time.Time `json:"reviewed_at,omitempty"`
	InvalidatedAt      time.Time `json:"invalidated_at,omitempty"`
	InvalidationReason string    `json:"invalidation_reason,omitempty"`
}

type EvidenceClaim struct {
	ID                string                `json:"id"`
	TenantID          string                `json:"tenant_id"`
	ArtifactVersionID string                `json:"artifact_version_id"`
	Scope             EvidenceClaimScope    `json:"scope"`
	Linkage           string                `json:"linkage"`
	Strength          string                `json:"strength"`
	Limitation        string                `json:"limitation,omitempty"`
	MappingRationale  string                `json:"mapping_rationale"`
	Decision          EvidenceClaimDecision `json:"decision"`
	Version           uint64                `json:"version"`
	CreatedAt         time.Time             `json:"created_at"`
	CreatedBy         string                `json:"created_by"`
}

type EvidenceAccessRequest struct {
	TenantID           string
	Purpose            string
	MaximumSensitivity string
	ActorID            string
}

type EvidenceClaimValidation struct {
	Valid       bool     `json:"valid"`
	ReasonCodes []string `json:"reason_codes"`
	NextActions []string `json:"next_actions"`
}

// EvidenceLedgerStore applies append-log events idempotently to current state.
type EvidenceLedgerStore interface {
	ApplyEvidenceVersion(context.Context, string, EvidenceArtifact, EvidenceVersion) error
	ApplyEvidenceClaim(context.Context, string, EvidenceClaim, uint64) error
	GetEvidenceArtifact(context.Context, string, string) (EvidenceArtifact, error)
	GetEvidenceVersion(context.Context, string, string) (EvidenceVersion, error)
	GetEvidenceClaim(context.Context, string, string) (EvidenceClaim, error)
	ListEvidenceClaimsByVersion(context.Context, string, string) ([]EvidenceClaim, error)
}
