package complianceimprovement

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

const (
	StateDetected      = "detected"
	StateResearching   = "researching"
	StateProposed      = "proposed"
	StateValidated     = "validated"
	StateDraftPROpened = "draft_pr_opened"
	StateAccepted      = "accepted"
	StateRejected      = "rejected"
	StateExpired       = "expired"
	StateSuperseded    = "superseded"

	ChangeKindControlDefinition = "control_definition"
	ChangeKindEvidencePolicy    = "evidence_policy"
	ChangeKindAssessmentTest    = "assessment_test"
	ChangeKindMonitoringRule    = "monitoring_rule"
	ChangeKindDocumentation     = "documentation"

	FileOperationCreate = "create"
	FileOperationUpdate = "update"

	VerificationPass  = "pass"
	VerificationWarn  = "warn"
	VerificationBlock = "block"

	DecisionAccept = "accept"
	DecisionReject = "reject"
)

const (
	MaxInputRevisions  = 256
	MaxClaims          = 128
	MaxCitations       = 256
	MaxUnknowns        = 64
	MaxFileChanges     = 25
	MaxPatchBytes      = 256 * 1024
	MaxValidationSteps = 50
)

// AgentRole describes one bounded participant in the improvement loop.
type AgentRole struct {
	ID             string   `json:"id"`
	Purpose        string   `json:"purpose"`
	Reads          []string `json:"reads"`
	Produces       []string `json:"produces"`
	MaxAction      string   `json:"max_action"`
	RequiredChecks []string `json:"required_checks"`
}

// InputRevision binds a proposal to an exact, immutable input.
type InputRevision struct {
	Kind string                 `json:"kind"`
	Ref  compliance.RevisionRef `json:"ref"`
}

type Measurement struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type TargetMeasurement struct {
	Name       string  `json:"name"`
	Comparator string  `json:"comparator"`
	Value      float64 `json:"value"`
	Unit       string  `json:"unit"`
}

type Guardrail struct {
	Name       string  `json:"name"`
	Comparator string  `json:"comparator"`
	Value      float64 `json:"value"`
	Unit       string  `json:"unit"`
}

type ProgramGap struct {
	Kind       string            `json:"kind"`
	Summary    string            `json:"summary"`
	Current    Measurement       `json:"current"`
	Target     TargetMeasurement `json:"target"`
	Guardrails []Guardrail       `json:"guardrails"`
	DetectedBy string            `json:"detected_by"`
	DetectedAt time.Time         `json:"detected_at"`
}

// Citation points to a source snapshot. The source content remains outside the
// repository patch and public pull-request metadata.
type Citation struct {
	ID               string                 `json:"id"`
	SourceURN        string                 `json:"source_urn"`
	SnapshotRevision compliance.RevisionRef `json:"snapshot_revision"`
	CapturedAt       time.Time              `json:"captured_at"`
	ExpiresAt        time.Time              `json:"expires_at,omitempty"`
}

type ResearchClaim struct {
	ID          string   `json:"id"`
	Statement   string   `json:"statement"`
	CitationIDs []string `json:"citation_ids"`
}

type ResearchPacket struct {
	Claims          []ResearchClaim `json:"claims"`
	Counterevidence []ResearchClaim `json:"counterevidence"`
	Citations       []Citation      `json:"citations"`
	Unknowns        []string        `json:"unknowns"`
	ResearchedBy    string          `json:"researched_by"`
	ResearchedAt    time.Time       `json:"researched_at"`
}

// ExpectedProgramImpact makes score-gaming effects explicit and reviewable.
// Positive removal counts are always blocking in the automated path.
type ExpectedProgramImpact struct {
	ScopeSubjectsRemoved        uint32 `json:"scope_subjects_removed"`
	ControlsRemoved             uint32 `json:"controls_removed"`
	EvidenceRequirementsRemoved uint32 `json:"evidence_requirements_removed"`
	OwnersRemoved               uint32 `json:"owners_removed"`
	ReviewRequirementsRemoved   uint32 `json:"review_requirements_removed"`
	ExpectedBenefit             string `json:"expected_benefit"`
}

type FileChange struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Content   string `json:"content"`
}

type RepositoryPatch struct {
	Repository      string       `json:"repository"`
	BaseBranch      string       `json:"base_branch"`
	BaseCommitSHA   string       `json:"base_commit_sha"`
	ProposalBranch  string       `json:"proposal_branch"`
	ChangeKind      string       `json:"change_kind"`
	Changes         []FileChange `json:"changes"`
	ValidationSteps []string     `json:"validation_steps"`
	RollbackSteps   []string     `json:"rollback_steps"`
}

type VerificationResult struct {
	VerifierID string   `json:"verifier_id"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	Evidence   []string `json:"evidence,omitempty"`
}

type VerificationRecord struct {
	Results    []VerificationResult `json:"results"`
	VerifiedBy string               `json:"verified_by"`
	VerifiedAt time.Time            `json:"verified_at"`
}

type DraftPullRequestReceipt struct {
	Repository     string    `json:"repository"`
	Number         uint64    `json:"number"`
	URL            string    `json:"url"`
	HeadCommitSHA  string    `json:"head_commit_sha"`
	BaseCommitSHA  string    `json:"base_commit_sha"`
	Draft          bool      `json:"draft"`
	ProposalDigest string    `json:"proposal_digest"`
	OpenedAt       time.Time `json:"opened_at"`
}

type TeamUpdate struct {
	ProposalDigest  string                  `json:"proposal_digest"`
	State           string                  `json:"state"`
	GapSummary      string                  `json:"gap_summary"`
	Current         Measurement             `json:"current"`
	Target          TargetMeasurement       `json:"target"`
	Guardrails      []Guardrail             `json:"guardrails"`
	Supporting      []ResearchClaim         `json:"supporting"`
	Counterevidence []ResearchClaim         `json:"counterevidence"`
	Unknowns        []string                `json:"unknowns"`
	Verification    []VerificationResult    `json:"verification"`
	PullRequest     DraftPullRequestReceipt `json:"pull_request"`
	DecisionOwner   string                  `json:"decision_owner"`
	RequiredAction  string                  `json:"required_action"`
	CreatedAt       time.Time               `json:"created_at"`
}

type TeamUpdateReceipt struct {
	OutboxID       string    `json:"outbox_id"`
	ProposalDigest string    `json:"proposal_digest"`
	QueuedAt       time.Time `json:"queued_at"`
}

type HumanDecision struct {
	Decision       string    `json:"decision"`
	ActorID        string    `json:"actor_id"`
	Rationale      string    `json:"rationale"`
	ProposalDigest string    `json:"proposal_digest"`
	DecidedAt      time.Time `json:"decided_at"`
}

type ImprovementProposal struct {
	Inputs           []InputRevision          `json:"inputs"`
	Gap              ProgramGap               `json:"gap"`
	Research         ResearchPacket           `json:"research"`
	Impact           ExpectedProgramImpact    `json:"impact"`
	Patch            RepositoryPatch          `json:"patch"`
	Verification     VerificationRecord       `json:"verification"`
	DraftPullRequest *DraftPullRequestReceipt `json:"draft_pull_request,omitempty"`
	TeamUpdate       *TeamUpdateReceipt       `json:"team_update,omitempty"`
	Decision         *HumanDecision           `json:"decision,omitempty"`
	ContentDigest    compliance.ContentDigest `json:"content_digest"`
}

type ImprovementRun struct {
	TenantID          string    `json:"tenant_id"`
	ID                string    `json:"id"`
	ProgramID         string    `json:"program_id"`
	State             string    `json:"state"`
	DecisionOwner     string    `json:"decision_owner"`
	AggregateVersion  uint64    `json:"aggregate_version"`
	CurrentRevisionID string    `json:"current_revision_id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ImprovementRevision struct {
	TenantID string                     `json:"tenant_id"`
	RunID    string                     `json:"run_id"`
	Version  compliance.VersionMetadata `json:"version"`
	Proposal ImprovementProposal        `json:"proposal"`
}

type ImprovementRecord struct {
	Run      ImprovementRun      `json:"run"`
	Revision ImprovementRevision `json:"revision"`
}

type CreateRecordRequest struct {
	Run      ImprovementRun
	Revision ImprovementRevision
}

type AppendRevisionRequest struct {
	TenantID        string
	RunID           string
	ExpectedVersion uint64
	Run             ImprovementRun
	Revision        ImprovementRevision
}

type Store interface {
	CreateComplianceImprovement(context.Context, CreateRecordRequest) (ImprovementRecord, bool, error)
	GetComplianceImprovement(context.Context, string, string) (ImprovementRecord, error)
	AppendComplianceImprovementRevision(context.Context, AppendRevisionRequest) (ImprovementRecord, error)
}

type InputRevisionVerifier interface {
	VerifyInputRevisions(context.Context, string, []InputRevision) ([]VerificationResult, error)
}

type RepositoryChangeVerifier interface {
	VerifyRepositoryChange(context.Context, RepositoryPatch) ([]VerificationResult, error)
}

// DraftPullRequestPublisher intentionally exposes no merge, approval,
// readiness, retarget, close, or default-branch write operation.
type DraftPullRequestPublisher interface {
	OpenDraftPullRequest(context.Context, OpenDraftPullRequestRequest) (DraftPullRequestReceipt, error)
}

type OpenDraftPullRequestRequest struct {
	ProposalDigest string       `json:"proposal_digest"`
	Repository     string       `json:"repository"`
	BaseBranch     string       `json:"base_branch"`
	BaseCommitSHA  string       `json:"base_commit_sha"`
	ProposalBranch string       `json:"proposal_branch"`
	Title          string       `json:"title"`
	Body           string       `json:"body"`
	Changes        []FileChange `json:"changes"`
	IdempotencyKey string       `json:"idempotency_key"`
	Draft          bool         `json:"draft"`
}

type TeamUpdateOutbox interface {
	EnqueueTeamUpdate(context.Context, string, string, TeamUpdate) (TeamUpdateReceipt, error)
}
