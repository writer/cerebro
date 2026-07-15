package trustclaims

import "time"

const (
	ReceiptSchemaVersion    = "trust-claim-receipt.v1"
	PackageSchemaVersion    = "trust-claim-package.v1"
	ObligationSchemaVersion = "trust-obligation.v1"

	ClaimOriginAuthored  = "authored"
	ClaimOriginGenerated = "generated"
	ClaimOriginExtracted = "extracted"

	ClaimStatusDraft        = "draft"
	ClaimStatusShareable    = "shareable"
	ClaimStatusAuditorReady = "auditor_ready"
	ClaimStatusWithdrawn    = "withdrawn"
	ClaimStatusReopened     = "reopened"
	ClaimStatusSuperseded   = "superseded"

	DisclosureInternal = "internal"
	DisclosureCustomer = "customer"
	DisclosureAuditor  = "auditor"

	CitationCurrent    = "current"
	CitationStale      = "stale"
	CitationRevoked    = "revoked"
	CitationConflicted = "conflicted"

	ApprovalApproved = "approved"

	TransitionClaimWithdrawn  = "trust_claim_withdrawn"
	TransitionClaimReopened   = "trust_claim_reopened"
	TransitionClaimSuperseded = "trust_claim_superseded"

	ObligationSuggested  = "suggested"
	ObligationActive     = "active"
	ObligationSuperseded = "superseded"
)

// ClaimReceipt is an immutable version of a factual external claim. A changed
// claim or dependency produces another receipt linked through PreviousDigest.
type ClaimReceipt struct {
	SchemaVersion     string             `json:"schema_version"`
	TenantID          string             `json:"tenant_id"`
	ReceiptID         string             `json:"receipt_id"`
	ClaimID           string             `json:"claim_id"`
	Version           int                `json:"version"`
	Statement         string             `json:"statement"`
	Origin            string             `json:"origin"`
	Status            string             `json:"status"`
	DisclosureClass   string             `json:"disclosure_class"`
	Citations         []Citation         `json:"citations,omitempty"`
	Controls          []VersionedRef     `json:"controls,omitempty"`
	Policies          []VersionedRef     `json:"policies,omitempty"`
	ResourceRefs      []ResourceRef      `json:"resource_refs,omitempty"`
	Generation        *GenerationReceipt `json:"generation,omitempty"`
	UnsupportedClaims []string           `json:"unsupported_claims,omitempty"`
	Approval          *ReviewerApproval  `json:"approval,omitempty"`
	FreshUntil        *time.Time         `json:"fresh_until,omitempty"`
	ExpiresAt         *time.Time         `json:"expires_at,omitempty"`
	IssuedAt          time.Time          `json:"issued_at"`
	PreviousDigest    string             `json:"previous_digest,omitempty"`
	TransitionReason  string             `json:"transition_reason,omitempty"`
	Digest            string             `json:"digest"`
}

type Citation struct {
	ID               string        `json:"id"`
	EvidenceID       string        `json:"evidence_id"`
	EvidencePacketID string        `json:"evidence_packet_id,omitempty"`
	EvidenceType     string        `json:"evidence_type,omitempty"`
	SourceID         string        `json:"source_id"`
	RuntimeID        string        `json:"runtime_id,omitempty"`
	SourceEventIDs   []string      `json:"source_event_ids"`
	ResourceRefs     []ResourceRef `json:"resource_refs,omitempty"`
	State            string        `json:"state"`
	Trusted          bool          `json:"trusted"`
	ObservedAt       time.Time     `json:"observed_at"`
	ExpiresAt        *time.Time    `json:"expires_at,omitempty"`
}

type ResourceRef struct {
	URN      string `json:"urn"`
	Revision string `json:"revision,omitempty"`
	Type     string `json:"type,omitempty"`
}

type VersionedRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type GenerationReceipt struct {
	ModelID       string `json:"model_id"`
	ModelVersion  string `json:"model_version"`
	PromptVersion string `json:"prompt_version"`
	PromptDigest  string `json:"prompt_digest,omitempty"`
}

type ReviewerApproval struct {
	ReviewerID string    `json:"reviewer_id"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
}

type ReceiptInput struct {
	TenantID          string
	ReceiptID         string
	ClaimID           string
	Version           int
	Statement         string
	Origin            string
	RequestedStatus   string
	DisclosureClass   string
	Citations         []Citation
	Controls          []VersionedRef
	Policies          []VersionedRef
	ResourceRefs      []ResourceRef
	Generation        *GenerationReceipt
	UnsupportedClaims []string
	Approval          *ReviewerApproval
	FreshUntil        *time.Time
	ExpiresAt         *time.Time
	IssuedAt          time.Time
	PreviousDigest    string
}

type EvidenceChange struct {
	TenantID   string
	CitationID string
	State      string
	Reason     string
	ObservedAt time.Time
}

type ClaimTransition struct {
	EventKind      string       `json:"event_kind"`
	TransitionType string       `json:"transition_type"`
	TenantID       string       `json:"tenant_id"`
	ClaimID        string       `json:"claim_id"`
	FromDigest     string       `json:"from_digest"`
	Receipt        ClaimReceipt `json:"receipt"`
}

// Obligation binds a confirmed commitment to the exact controls, evidence
// requirements, population, owner, and deadline used to operate it.
type Obligation struct {
	SchemaVersion        string             `json:"schema_version"`
	TenantID             string             `json:"tenant_id"`
	ObligationID         string             `json:"obligation_id"`
	Version              int                `json:"version"`
	Status               string             `json:"status"`
	ContractRef          VersionedRef       `json:"contract_ref"`
	CommitmentRef        string             `json:"commitment_ref"`
	Controls             []VersionedRef     `json:"controls"`
	EvidenceRequirements []VersionedRef     `json:"evidence_requirements"`
	ResourcePopulation   []ResourceRef      `json:"resource_population"`
	OwnerID              string             `json:"owner_id"`
	Deadline             *time.Time         `json:"deadline,omitempty"`
	SuggestedBy          *ExtractionReceipt `json:"suggested_by,omitempty"`
	ConfirmedBy          *ReviewerApproval  `json:"confirmed_by,omitempty"`
	PreviousDigest       string             `json:"previous_digest,omitempty"`
	SupersededBy         string             `json:"superseded_by,omitempty"`
	IssuedAt             time.Time          `json:"issued_at"`
	Digest               string             `json:"digest"`
}

type ExtractionReceipt struct {
	SourceRef     string `json:"source_ref"`
	ExtractorID   string `json:"extractor_id"`
	ModelVersion  string `json:"model_version,omitempty"`
	PromptVersion string `json:"prompt_version,omitempty"`
}

type ObligationInput struct {
	TenantID             string
	ObligationID         string
	Version              int
	ContractRef          VersionedRef
	CommitmentRef        string
	Controls             []VersionedRef
	EvidenceRequirements []VersionedRef
	ResourcePopulation   []ResourceRef
	OwnerID              string
	Deadline             *time.Time
	SuggestedBy          *ExtractionReceipt
	IssuedAt             time.Time
	PreviousDigest       string
}

type PackageRequest struct {
	TenantID      string
	Audience      string
	ReceiptIDs    []string
	ObligationIDs []string
	PackagedAt    time.Time
}

type ClaimPackage struct {
	SchemaVersion string         `json:"schema_version"`
	TenantID      string         `json:"tenant_id"`
	Audience      string         `json:"audience"`
	Receipts      []ClaimReceipt `json:"receipts"`
	Obligations   []Obligation   `json:"obligations,omitempty"`
	PackagedAt    time.Time      `json:"packaged_at"`
	Digest        string         `json:"digest"`
}
