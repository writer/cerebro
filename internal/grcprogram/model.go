package grcprogram

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

const (
	ComplianceProgramDraft     = "draft"
	ComplianceProgramActive    = "active"
	ComplianceProgramSuspended = "suspended"
	ComplianceProgramRetired   = "retired"

	ScopeRevisionProposed = "proposed"
	ScopeRevisionActive   = "active"

	ScopeSelectorInclude = "include"
	ScopeSelectorExclude = "exclude"

	SubjectResolutionResolved   = "resolved"
	SubjectResolutionUnresolved = "unresolved"

	SubjectUnresolvedUnsupported          = "unsupported_selector"
	SubjectUnresolvedSourceUnavailable    = "source_unavailable"
	SubjectUnresolvedInvalidSelector      = "invalid_selector"
	SubjectUnresolvedWatermarkUnavailable = "watermark_unavailable"

	ImplementationPlanned       = "planned"
	ImplementationPartial       = "partial"
	ImplementationImplemented   = "implemented"
	ImplementationAlternative   = "alternative"
	ImplementationNotApplicable = "not_applicable"
	ImplementationRetired       = "retired"

	ResponsibilityDirect                 = "direct"
	ResponsibilityProvided               = "provided"
	ResponsibilityCustomerResponsibility = "customer_responsibility"
	ResponsibilityShared                 = "shared"
	ResponsibilityInherited              = "inherited"
)

type ComplianceProgramRecord struct {
	TenantID               string    `json:"tenant_id"`
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	OwnerTeam              string    `json:"owner_team"`
	RiskOwner              string    `json:"risk_owner,omitempty"`
	Status                 string    `json:"status"`
	ScopeID                string    `json:"scope_id,omitempty"`
	CurrentScopeRevisionID string    `json:"current_scope_revision_id,omitempty"`
	AggregateVersion       uint64    `json:"aggregate_version"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type ScopeSelectorCriterion struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type ProgramScopeSelector struct {
	ID                   string                   `json:"id"`
	Kind                 string                   `json:"kind"`
	Mode                 string                   `json:"mode"`
	Criteria             []ScopeSelectorCriterion `json:"criteria"`
	Source               string                   `json:"source"`
	Reason               string                   `json:"reason"`
	ApproverID           string                   `json:"approver_id"`
	EffectiveFrom        time.Time                `json:"effective_from"`
	EffectiveUntil       time.Time                `json:"effective_until,omitempty"`
	ReviewAt             time.Time                `json:"review_at,omitempty"`
	SupersedesSelectorID string                   `json:"supersedes_selector_id,omitempty"`
}

type ScopeParameter struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Rationale string `json:"rationale"`
}

type SelectorResolution struct {
	SelectorID string                  `json:"selector_id"`
	State      string                  `json:"state"`
	ReasonCode string                  `json:"reason_code,omitempty"`
	Subjects   []compliance.SubjectRef `json:"subjects"`
}

type SubjectResolutionRequest struct {
	TenantID  string                 `json:"tenant_id"`
	Selectors []ProgramScopeSelector `json:"selectors"`
	Cutoff    time.Time              `json:"cutoff"`
}

type SubjectResolutionBatch struct {
	Watermark   string               `json:"watermark"`
	Cutoff      time.Time            `json:"cutoff"`
	Resolutions []SelectorResolution `json:"resolutions"`
}

type ProgramSubjectManifest struct {
	Subjects              []compliance.SubjectRef  `json:"subjects"`
	SelectorResolutions   []SelectorResolution     `json:"selector_resolutions"`
	ZeroMatchSelectorIDs  []string                 `json:"zero_match_selector_ids"`
	UnresolvedSelectorIDs []string                 `json:"unresolved_selector_ids"`
	Watermark             string                   `json:"watermark"`
	Cutoff                time.Time                `json:"cutoff"`
	ContentDigest         compliance.ContentDigest `json:"content_digest"`
}

type ProgramScopeSpecification struct {
	FrameworkRevisions []compliance.RevisionRef `json:"framework_revisions"`
	ProfileRevisions   []compliance.RevisionRef `json:"profile_revisions"`
	Selectors          []ProgramScopeSelector   `json:"selectors"`
	Parameters         []ScopeParameter         `json:"parameters"`
	SubjectManifest    ProgramSubjectManifest   `json:"subject_manifest"`
	EvidenceWindow     string                   `json:"evidence_window,omitempty"`
	MonitoringCadence  string                   `json:"monitoring_cadence,omitempty"`
	SourceProofPolicy  string                   `json:"source_proof_policy,omitempty"`
	MaterialityLevel   string                   `json:"materiality_level,omitempty"`
}

type ProgramScopeRevisionRecord struct {
	TenantID      string                     `json:"tenant_id"`
	ProgramID     string                     `json:"program_id"`
	State         string                     `json:"state"`
	Version       compliance.VersionMetadata `json:"version"`
	ChangeSummary string                     `json:"change_summary"`
	Specification ProgramScopeSpecification  `json:"specification"`
}

type ControlMappingRef struct {
	ID                  string                          `json:"id"`
	RevisionID          string                          `json:"revision_id"`
	Relationship        compliance.MappingRelationship  `json:"relationship"`
	Granularity         string                          `json:"granularity"`
	Source              compliance.RevisionRef          `json:"source"`
	Target              compliance.RevisionRef          `json:"target"`
	Method              string                          `json:"method"`
	Rationale           string                          `json:"rationale"`
	CoverageBasisPoints uint16                          `json:"coverage_basis_points"`
	Gaps                []string                        `json:"gaps,omitempty"`
	Provenance          []compliance.SubjectRef         `json:"provenance,omitempty"`
	DecisionState       compliance.MappingDecisionState `json:"decision_state"`
	AuthorID            string                          `json:"author_id"`
	ReviewerID          string                          `json:"reviewer_id,omitempty"`
}

type ImplementationReviewPolicy struct {
	Cadence        string    `json:"cadence"`
	EffectiveFrom  time.Time `json:"effective_from"`
	EffectiveUntil time.Time `json:"effective_until,omitempty"`
}

type ControlImplementationRecord struct {
	TenantID          string    `json:"tenant_id"`
	ProgramID         string    `json:"program_id"`
	ID                string    `json:"id"`
	CurrentRevisionID string    `json:"current_revision_id"`
	AggregateVersion  uint64    `json:"aggregate_version"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ControlImplementationSpecification struct {
	ScopeRevisionID         string                     `json:"scope_revision_id"`
	ControlRef              compliance.ControlRef      `json:"control_ref"`
	StatementID             string                     `json:"statement_id,omitempty"`
	ObjectiveIDs            []string                   `json:"objective_ids"`
	Status                  string                     `json:"status"`
	Narrative               string                     `json:"narrative"`
	Procedure               string                     `json:"procedure,omitempty"`
	OwnerTeam               string                     `json:"owner_team"`
	ReviewPolicy            ImplementationReviewPolicy `json:"review_policy"`
	ResponsibleRoles        []string                   `json:"responsible_roles"`
	AccountableRoles        []string                   `json:"accountable_roles"`
	Responsibility          string                     `json:"responsibility"`
	UpstreamImplementation  *compliance.SubjectRef     `json:"upstream_implementation,omitempty"`
	SubjectRefs             []compliance.SubjectRef    `json:"subject_refs"`
	ParameterValues         []ScopeParameter           `json:"parameter_values"`
	MappingRefs             []ControlMappingRef        `json:"mapping_refs"`
	ExpectedTestRefs        []compliance.SubjectRef    `json:"expected_test_refs"`
	EvidenceRequirementRefs []compliance.SubjectRef    `json:"evidence_requirement_refs"`
	SourceDimensionRefs     []compliance.SubjectRef    `json:"source_dimension_refs"`
	RiskRefs                []compliance.SubjectRef    `json:"risk_refs"`
	ExceptionRefs           []compliance.SubjectRef    `json:"exception_refs"`
	MaterialChangeCriteria  []string                   `json:"material_change_criteria"`
	InvalidationRules       []string                   `json:"invalidation_rules"`
}

type ControlImplementationRevisionRecord struct {
	TenantID         string                             `json:"tenant_id"`
	ProgramID        string                             `json:"program_id"`
	ImplementationID string                             `json:"implementation_id"`
	Version          compliance.VersionMetadata         `json:"version"`
	ChangeSummary    string                             `json:"change_summary"`
	Specification    ControlImplementationSpecification `json:"specification"`
}

// ControlImplementationRecordedPayload is the bounded event payload used to
// reconstruct both the implementation current pointer and its immutable
// revision from the append log.
type ControlImplementationRecordedPayload struct {
	Implementation ControlImplementationRecord         `json:"implementation"`
	Revision       ControlImplementationRevisionRecord `json:"revision"`
}

type AppendProgramScopeRevisionRequest struct {
	TenantID               string
	ProgramID              string
	ExpectedProgramVersion uint64
	Revision               ProgramScopeRevisionRecord
}

type AppendControlImplementationRevisionRequest struct {
	TenantID                      string
	ProgramID                     string
	ExpectedProgramVersion        uint64
	ExpectedImplementationVersion uint64
	Implementation                ControlImplementationRecord
	Revision                      ControlImplementationRevisionRecord
}

type ComplianceProgramStore interface {
	Ping(context.Context) error
	CreateComplianceProgram(context.Context, ComplianceProgramRecord) (*ComplianceProgramRecord, error)
	GetComplianceProgram(context.Context, string, string) (*ComplianceProgramRecord, error)
	GetProgramScopeRevision(context.Context, string, string, string) (*ProgramScopeRevisionRecord, error)
	AppendProgramScopeRevision(context.Context, AppendProgramScopeRevisionRequest) (*ComplianceProgramRecord, error)
	GetControlImplementation(context.Context, string, string, string) (*ControlImplementationRecord, error)
	GetControlImplementationRevision(context.Context, string, string, string, string) (*ControlImplementationRevisionRecord, error)
	AppendControlImplementationRevision(context.Context, AppendControlImplementationRevisionRequest) (*ComplianceProgramRecord, *ControlImplementationRecord, error)
}

type ProgramSubjectResolver interface {
	ResolveProgramSubjects(context.Context, SubjectResolutionRequest) (SubjectResolutionBatch, error)
}
