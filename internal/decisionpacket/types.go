package decisionpacket

import (
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
)

const SchemaVersion = "2026-07-15"

const (
	DecisionSupported            = "supported"
	DecisionSupportedWithGaps    = "supported_with_gaps"
	DecisionBlocked              = "blocked"
	DecisionInsufficientEvidence = "insufficient_evidence"
	DecisionNotApplicable        = "not_applicable"
)

const (
	ConfidenceHigh    = "high"
	ConfidenceMedium  = "medium"
	ConfidenceLow     = "low"
	ConfidenceUnknown = "unknown"
)

const (
	CoverageComplete     = "complete"
	CoveragePartial      = "partial"
	CoverageStale        = "stale"
	CoverageFailed       = "failed"
	CoverageUnconfigured = "unconfigured"
	CoverageUnsupported  = "unsupported"
	CoverageUnverified   = "unverified"
)

const (
	ActionInformational    = "informational"
	ActionStateProposal    = "proposal"
	ActionApprovalRequired = "approval_required"
)

const (
	ContradictionUnresolved = "unresolved"
	ContradictionResolved   = "resolved"
)

type Request struct {
	Workflow        string   `json:"workflow"`
	Question        string   `json:"question"`
	ScopeURN        string   `json:"scope_urn,omitempty"`
	FindingIDs      []string `json:"finding_ids,omitempty"`
	ClaimIDs        []string `json:"claim_ids,omitempty"`
	EvidenceURNs    []string `json:"evidence_urns,omitempty"`
	AuditPacketIDs  []string `json:"audit_packet_ids,omitempty"`
	RequiredSources []string `json:"required_sources,omitempty"`
	RequestedAction string   `json:"requested_action,omitempty"`
	Budgets         Budgets  `json:"budgets"`
}

// AuthorizedTenant and AuthorizedActor are forced by transport authentication.
// They are intentionally separate from Request so callers cannot override them.
type AuthorizedTenant struct {
	ID string
}

type AuthorizedActor struct {
	ID     string
	Scopes []string
}

type Budgets struct {
	Evidence       int `json:"evidence,omitempty"`
	Contradictions int `json:"contradictions,omitempty"`
	CoverageGaps   int `json:"coverage_gaps,omitempty"`
	Affected       int `json:"affected,omitempty"`
	Controls       int `json:"controls,omitempty"`
	AuditPackets   int `json:"audit_packets,omitempty"`
	Actions        int `json:"actions,omitempty"`
	GraphRows      int `json:"graph_rows,omitempty"`
	GraphDepth     int `json:"graph_depth,omitempty"`
}

type Packet struct {
	SchemaVersion  string                                `json:"schema_version"`
	ID             string                                `json:"id"`
	GeneratedAt    time.Time                             `json:"generated_at"`
	Workflow       Workflow                              `json:"workflow"`
	Scope          Scope                                 `json:"scope"`
	Guardrails     agentplatform.AgentDecisionGuardrails `json:"guardrails"`
	Claim          agentplatform.ClaimVerification       `json:"claim"`
	Decision       Decision                              `json:"decision"`
	Confidence     Confidence                            `json:"confidence"`
	Freshness      Freshness                             `json:"freshness"`
	Evidence       []EvidenceReference                   `json:"evidence"`
	Contradictions []Contradiction                       `json:"contradictions"`
	CoverageGaps   []CoverageGap                         `json:"coverage_gaps"`
	Affected       []SubjectReference                    `json:"affected"`
	Controls       []ControlReference                    `json:"controls"`
	AuditPackets   []AuditPacketReference                `json:"audit_packets"`
	Actions        []ActionProposal                      `json:"actions"`
	Provenance     Provenance                            `json:"provenance"`
	Limits         ResultLimits                          `json:"limits"`
}

type Workflow struct {
	ID       string `json:"id"`
	Question string `json:"question"`
}

type Scope struct {
	TenantID string `json:"tenant_id"`
	ActorID  string `json:"actor_id"`
	URN      string `json:"urn,omitempty"`
}

type Decision struct {
	State     string   `json:"state"`
	Rationale string   `json:"rationale"`
	Reasons   []string `json:"reasons"`
}

type Confidence struct {
	Level string   `json:"level"`
	Basis []string `json:"basis"`
}

type Freshness struct {
	State            string    `json:"state"`
	OldestObservedAt time.Time `json:"oldest_observed_at,omitzero"`
	NewestObservedAt time.Time `json:"newest_observed_at,omitzero"`
	RequiredStale    bool      `json:"required_stale"`
}

type EvidenceReference struct {
	ID         string    `json:"id"`
	URN        string    `json:"urn,omitempty"`
	Kind       string    `json:"kind"`
	SourceID   string    `json:"source_id,omitempty"`
	SubjectURN string    `json:"subject_urn,omitempty"`
	Predicate  string    `json:"predicate,omitempty"`
	Value      string    `json:"value,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
	ValidFrom  time.Time `json:"valid_from,omitzero"`
	ValidTo    time.Time `json:"valid_to,omitzero"`
	Digest     string    `json:"digest,omitempty"`
}

type Contradiction struct {
	ID              string            `json:"id"`
	SubjectURN      string            `json:"subject_urn"`
	Predicate       string            `json:"predicate"`
	Left            EvidenceReference `json:"left"`
	Right           EvidenceReference `json:"right"`
	ResolutionState string            `json:"resolution_state"`
	PrimaryClaim    bool              `json:"primary_claim"`
}

type CoverageGap struct {
	ID                    string `json:"id"`
	SourceID              string `json:"source_id,omitempty"`
	Dimension             string `json:"dimension,omitempty"`
	State                 string `json:"state"`
	Required              bool   `json:"required"`
	CouldChangeConclusion bool   `json:"could_change_conclusion"`
	Reason                string `json:"reason"`
}

type SubjectReference struct {
	URN  string `json:"urn"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

type ControlReference struct {
	ID            string `json:"id"`
	Framework     string `json:"framework,omitempty"`
	Applicability string `json:"applicability"`
}

type AuditPacketReference struct {
	ID          string    `json:"id"`
	ScopeURN    string    `json:"scope_urn,omitempty"`
	Digest      string    `json:"digest"`
	GeneratedAt time.Time `json:"generated_at"`
	Freshness   string    `json:"freshness"`
}

type ActionProposal struct {
	ID                   string   `json:"id"`
	ActionID             string   `json:"action_id"`
	State                string   `json:"state"`
	TargetURNs           []string `json:"target_urns"`
	Rationale            string   `json:"rationale"`
	ApprovalRequirements []string `json:"approval_requirements,omitempty"`
	CatalogVersion       string   `json:"catalog_version,omitempty"`
	ProposalDigest       string   `json:"proposal_digest,omitempty"`
}

type Provenance struct {
	TraceID        string   `json:"trace_id,omitempty"`
	ResolverIDs    []string `json:"resolver_ids"`
	SourceIDs      []string `json:"source_ids"`
	EvidenceDigest string   `json:"evidence_digest,omitempty"`
	CoverageDigest string   `json:"coverage_digest,omitempty"`
}

type ResultLimits struct {
	Evidence       ResultLimit `json:"evidence"`
	Contradictions ResultLimit `json:"contradictions"`
	CoverageGaps   ResultLimit `json:"coverage_gaps"`
	Affected       ResultLimit `json:"affected"`
	Controls       ResultLimit `json:"controls"`
	AuditPackets   ResultLimit `json:"audit_packets"`
	Actions        ResultLimit `json:"actions"`
	GraphRows      ResultLimit `json:"graph_rows"`
	GraphDepth     ResultLimit `json:"graph_depth"`
}

type ResultLimit struct {
	Requested  int  `json:"requested"`
	Applied    int  `json:"applied"`
	Returned   int  `json:"returned"`
	TotalKnown int  `json:"total_known,omitempty"`
	Truncated  bool `json:"truncated"`
}

type DecisionInputs struct {
	ClaimVerdict     string
	Applicable       *bool
	RequiredGap      bool
	RequiredStale    bool
	PrimaryConflict  bool
	OutcomeTruncated bool
}

type ConfidenceInputs struct {
	SupportingEvidence int
	RequiredGap        bool
	RequiredStale      bool
	RequiredUnverified bool
	UnresolvedConflict bool
	OptionalGapMatters bool
	OutcomeTruncated   bool
	GuardrailsPassed   bool
}

type ClaimObservation struct {
	TenantID     string
	SubjectURN   string
	Predicate    string
	Value        string
	ValidFrom    time.Time
	ValidTo      time.Time
	ObservedAt   time.Time
	SourceID     string
	Evidence     EvidenceReference
	PrimaryClaim bool
}
