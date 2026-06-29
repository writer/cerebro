package grcpolicylifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/ports"
)

const (
	grcPolicyLifecycleDefaultLimit         = 100
	grcPolicyLifecycleDefaultRelationLimit = 2000
	grcPolicyLifecycleExceptionWindow      = 30 * 24 * time.Hour
)

type Scope struct {
	TenantID    string
	SourceID    string
	RuntimeID   string
	Limit       uint32
	RuleProfile string
}

var grcPolicyLifecycleEntityTypes = []string{
	"claim",
	"document",
	"policy",
	"policy.template",
	"policy.version",
	"policy.approval",
	"policy.acceptance",
	"policy.review",
	"policy.exception",
	"policy.reminder",
	"policy.lifecycle.event",
	"policy.evidence_snippet",
}

var grcPolicyLifecycleAnchorEntityTypes = []string{
	"policy",
	"policy.template",
	"policy.version",
	"policy.approval",
	"policy.acceptance",
	"policy.review",
	"policy.exception",
	"policy.reminder",
}

const grcPolicyLifecycleRiskScenarioAttrFragment = `"claim_type":"risk_scenario"`

var grcPolicyLifecycleDocumentAttrFragments = []string{
	`"category":"control_narrative"`,
	`"category":"exception_register"`,
	`"category":"policy"`,
	`"category":"procedure"`,
	`"category":"risk_register"`,
	`"category":"standard"`,
	`"category":"training"`,
	`"category":"training_material"`,
	`"category":"waiver_register"`,
	`"control_id":"`,
	`"control_ids":`,
	`"document_class":"control_narrative"`,
	`"document_class":"exception_register"`,
	`"document_class":"policy"`,
	`"document_class":"procedure"`,
	`"document_class":"risk_register"`,
	`"document_class":"standard"`,
	`"document_class":"training"`,
	`"document_class":"training_material"`,
	`"document_class":"waiver_register"`,
	`"document_type":"control_narrative`,
	`"document_type":"exception_register`,
	`"document_type":"policy`,
	`"document_type":"procedure`,
	`"document_type":"risk_assessment`,
	`"document_type":"risk_register`,
	`"document_type":"standard`,
	`"document_type":"training`,
	`"document_type":"training_material`,
	`"document_type":"waiver_register`,
	`"evidence_id":"`,
	`"evidence_ids":`,
	`"policy_document_type":"`,
	`"policy_id":"`,
	`"policy_ids":`,
	`"policy_urn":"`,
	`"risk_id":"`,
	`"risk_ids":`,
	`"risk_scenario_id":"`,
}

const grcPolicyLifecycleEntitiesQuery = `UNWIND $entity_types AS entity_type
CALL {
  WITH entity_type
  MATCH (e:Entity)
  WHERE ($tenant_id = '' OR e.tenant_id = $tenant_id)
    AND ($source_id = '' OR e.source_id = $source_id)
    AND ($runtime_id = '' OR coalesce(e.runtime_id, '') = $runtime_id)
    AND e.entity_type = entity_type
  WITH entity_type, e, toLower(coalesce(e.attributes_json, '')) AS attrs
  WHERE (entity_type <> 'claim' OR attrs CONTAINS $risk_scenario_attr_fragment)
    AND (entity_type <> 'document' OR ANY(fragment IN $document_attr_fragments WHERE attrs CONTAINS fragment))
  RETURN e
  ORDER BY coalesce(e.label, e.urn), e.urn
  LIMIT $type_limit
}
RETURN e.urn AS urn,
       e.tenant_id AS tenant_id,
       e.source_id AS source_id,
       coalesce(e.runtime_id, '') AS runtime_id,
       e.entity_type AS entity_type,
       coalesce(e.label, e.urn) AS label,
       coalesce(e.attributes_json, '{}') AS attributes_json
ORDER BY e.entity_type, e.label, e.urn`

const grcPolicyLifecycleRelationsQuery = `MATCH (left:Entity)-[r:RELATION]->(right:Entity)
WHERE ($tenant_id = '' OR left.tenant_id = $tenant_id)
  AND ($tenant_id = '' OR right.tenant_id = $tenant_id)
  AND (
    $source_id = '' OR
    (left.entity_type IN $entity_types AND left.source_id = $source_id) OR
    (right.entity_type IN $entity_types AND right.source_id = $source_id)
  )
  AND (
    $runtime_id = '' OR
    (left.entity_type IN $entity_types AND coalesce(left.runtime_id, '') = $runtime_id) OR
    (right.entity_type IN $entity_types AND coalesce(right.runtime_id, '') = $runtime_id)
  )
  AND (left.entity_type IN $entity_types OR right.entity_type IN $entity_types)
WITH left, r, right,
     toLower(coalesce(left.attributes_json, '')) AS left_attrs,
     toLower(coalesce(right.attributes_json, '')) AS right_attrs
WHERE (left.entity_type <> 'claim' OR left_attrs CONTAINS $risk_scenario_attr_fragment)
  AND (right.entity_type <> 'claim' OR right_attrs CONTAINS $risk_scenario_attr_fragment)
  AND (
    left.entity_type <> 'document' OR
    ANY(fragment IN $document_attr_fragments WHERE left_attrs CONTAINS fragment) OR
    right.entity_type IN $policy_anchor_entity_types
  )
  AND (
    right.entity_type <> 'document' OR
    ANY(fragment IN $document_attr_fragments WHERE right_attrs CONTAINS fragment) OR
    left.entity_type IN $policy_anchor_entity_types
  )
RETURN left.urn AS left_urn,
       left.tenant_id AS left_tenant_id,
       left.source_id AS left_source_id,
       coalesce(left.runtime_id, '') AS left_runtime_id,
       left.entity_type AS left_entity_type,
       coalesce(left.label, left.urn) AS left_label,
       coalesce(left.attributes_json, '{}') AS left_attributes_json,
       r.relation AS relation,
       coalesce(r.attributes_json, '{}') AS relation_attributes_json,
       right.urn AS right_urn,
       right.tenant_id AS right_tenant_id,
       right.source_id AS right_source_id,
       coalesce(right.runtime_id, '') AS right_runtime_id,
       right.entity_type AS right_entity_type,
       coalesce(right.label, right.urn) AS right_label,
       coalesce(right.attributes_json, '{}') AS right_attributes_json
ORDER BY left.urn, r.relation, right.urn
LIMIT $limit`

type Response struct {
	Summary           grcPolicyLifecycleSummary      `json:"summary"`
	Templates         []grcPolicyTemplateItem        `json:"templates"`
	Policies          []grcPolicyLifecyclePolicy     `json:"policies"`
	Documents         []grcPolicyDocumentItem        `json:"documents"`
	RiskRegister      []grcPolicyRiskRegisterItem    `json:"risk_register"`
	EvidenceSnippets  []grcPolicyEvidenceSnippetItem `json:"evidence_snippets,omitempty"`
	GovernanceGaps    []grcPolicyGovernanceGap       `json:"governance_gaps"`
	GovernanceRules   []grcPolicyGovernanceRule      `json:"governance_rules,omitempty"`
	GapRollups        grcPolicyGovernanceGapRollups  `json:"governance_gap_rollups"`
	WorkQueue         []grcPolicyLifecycleWork       `json:"work_queue"`
	DocumentWorkQueue []grcPolicyDocumentWork        `json:"document_work_queue"`
	Reminders         []grcPolicyReminderItem        `json:"reminders"`
	Events            []grcPolicyLifecycleEventItem  `json:"events,omitempty"`
	AvailableActions  []ActionDefinition             `json:"available_actions,omitempty"`
	VersionDiffs      []grcPolicyVersionDiffItem     `json:"version_diffs,omitempty"`
	ReminderPlan      []grcPolicyReminderPlanItem    `json:"reminder_plan,omitempty"`
	Mappings          []grcPolicyLifecycleMapping    `json:"mappings"`
	GeneratedAt       time.Time                      `json:"generated_at"`
}

type grcPolicyLifecycleSummary struct {
	GRCPolicyLifecycleInventorySummary
	GRCPolicyLifecycleReviewSummary
	GRCPolicyLifecycleGovernanceSummary
	GRCPolicyLifecycleRiskSummary
	GRCPolicyLifecycleEvidenceSummary
}

type GRCPolicyLifecycleInventorySummary struct {
	Policies          int `json:"policies"`
	Templates         int `json:"templates"`
	LifecycleEvents   int `json:"lifecycle_events"`
	PolicyDocuments   int `json:"policy_documents"`
	RiskRegisterItems int `json:"risk_register_items"`
}

type GRCPolicyLifecycleReviewSummary struct {
	DraftVersions         int `json:"draft_versions"`
	DraftDocuments        int `json:"draft_documents"`
	PendingApprovals      int `json:"pending_approvals"`
	OverdueReviews        int `json:"overdue_reviews"`
	DocumentsDueForReview int `json:"documents_due_for_review"`
}

type GRCPolicyLifecycleGovernanceSummary struct {
	GovernanceGaps     int `json:"governance_gaps"`
	PolicyDocumentGaps int `json:"policy_document_gaps"`
	RiskRegisterGaps   int `json:"risk_register_gaps"`
	OpenGovernanceGaps int `json:"open_governance_gaps"`
	InProgressGaps     int `json:"in_progress_governance_gaps"`
	AcknowledgedGaps   int `json:"acknowledged_governance_gaps"`
	SnoozedGaps        int `json:"snoozed_governance_gaps"`
	AcceptedGaps       int `json:"accepted_governance_gaps"`
	ResolvedGaps       int `json:"resolved_governance_gaps"`
	HighGovernanceGaps int `json:"high_governance_gaps"`
}

type GRCPolicyLifecycleRiskSummary struct {
	OpenExceptions     int `json:"open_exceptions"`
	ExpiringExceptions int `json:"expiring_exceptions"`
	OpenRisks          int `json:"open_risks"`
	HighRisks          int `json:"high_risks"`
}

type GRCPolicyLifecycleEvidenceSummary struct {
	AttestationCoveragePct int `json:"attestation_coverage_pct"`
	OverdueAttestations    int `json:"overdue_attestations"`
	NextReminders          int `json:"next_reminders"`
	MappedControls         int `json:"mapped_controls"`
	EvidenceItems          int `json:"evidence_items"`
	EvidenceSnippets       int `json:"evidence_snippets"`
	SnippetsNeedingReview  int `json:"snippets_needing_review"`
}

type grcPolicyTemplateItem struct {
	ID         string                 `json:"id"`
	URN        string                 `json:"urn"`
	Title      string                 `json:"title"`
	Status     string                 `json:"status,omitempty"`
	Category   string                 `json:"category,omitempty"`
	Frameworks []string               `json:"frameworks,omitempty"`
	Owner      string                 `json:"owner,omitempty"`
	Controls   []grcPolicyControlRef  `json:"controls,omitempty"`
	Evidence   []grcPolicyEvidenceRef `json:"evidence,omitempty"`
	Attributes map[string]string      `json:"attributes,omitempty"`
}

type grcPolicyDocumentItem struct {
	ID    string `json:"id"`
	URN   string `json:"urn"`
	Title string `json:"title"`
	grcPolicyDocumentMetadata
	Policies         []grcPolicyDocumentRef         `json:"policies,omitempty"`
	Risks            []grcPolicyRiskRef             `json:"risks,omitempty"`
	Controls         []grcPolicyControlRef          `json:"controls,omitempty"`
	Evidence         []grcPolicyEvidenceRef         `json:"evidence,omitempty"`
	EvidenceSnippets []grcPolicyEvidenceSnippetItem `json:"evidence_snippets,omitempty"`
	Attributes       map[string]string              `json:"attributes,omitempty"`
}

type grcPolicyDocumentMetadata struct {
	PolicyType              string `json:"policy_type,omitempty"`
	DocumentType            string `json:"document_type,omitempty"`
	DocumentClass           string `json:"document_class,omitempty"`
	Status                  string `json:"status,omitempty"`
	Owner                   string `json:"owner,omitempty"`
	ApprovingAuthority      string `json:"approving_authority,omitempty"`
	Version                 string `json:"version,omitempty"`
	ReviewCadence           string `json:"review_cadence,omitempty"`
	LastReviewedAt          string `json:"last_reviewed_at,omitempty"`
	NextReviewDueAt         string `json:"next_review_due_at,omitempty"`
	ApprovedAt              string `json:"approved_at,omitempty"`
	EffectiveAt             string `json:"effective_at,omitempty"`
	AcknowledgementEvidence string `json:"acknowledgement_evidence,omitempty"`
	ExceptionPath           string `json:"exception_path,omitempty"`
	SourceProvenance        string `json:"source_provenance,omitempty"`
	SourceURL               string `json:"source_url,omitempty"`
}

type grcPolicyDocumentRef struct {
	ID        string `json:"id,omitempty"`
	URN       string `json:"urn"`
	Title     string `json:"title"`
	Reference string `json:"reference,omitempty"`
}

type grcPolicyRiskRef struct {
	ID     string `json:"id,omitempty"`
	URN    string `json:"urn"`
	Title  string `json:"title"`
	Status string `json:"status,omitempty"`
}

type grcPolicyRiskRegisterItem struct {
	ID                  string                 `json:"id"`
	URN                 string                 `json:"urn"`
	Title               string                 `json:"title"`
	Status              string                 `json:"status,omitempty"`
	Owner               string                 `json:"owner,omitempty"`
	Category            string                 `json:"category,omitempty"`
	InherentRisk        string                 `json:"inherent_risk,omitempty"`
	ResidualRisk        string                 `json:"residual_risk,omitempty"`
	Likelihood          string                 `json:"likelihood,omitempty"`
	Impact              string                 `json:"impact,omitempty"`
	Treatment           string                 `json:"treatment,omitempty"`
	ReviewDueAt         string                 `json:"review_due_at,omitempty"`
	TreatmentDueAt      string                 `json:"treatment_due_at,omitempty"`
	SourceDocumentID    string                 `json:"source_document_id,omitempty"`
	SourceDocumentTitle string                 `json:"source_document_title,omitempty"`
	Policies            []grcPolicyDocumentRef `json:"policies,omitempty"`
	Controls            []grcPolicyControlRef  `json:"controls,omitempty"`
	Evidence            []grcPolicyEvidenceRef `json:"evidence,omitempty"`
	Attributes          map[string]string      `json:"attributes,omitempty"`
}

type grcPolicyGovernanceGap struct {
	ID             string                        `json:"id"`
	Subject        string                        `json:"subject"`
	SubjectID      string                        `json:"subject_id,omitempty"`
	Title          string                        `json:"title"`
	Status         string                        `json:"status,omitempty"`
	Owner          string                        `json:"owner,omitempty"`
	Severity       string                        `json:"severity"`
	Reason         string                        `json:"reason"`
	Action         string                        `json:"action"`
	ActionID       string                        `json:"action_id,omitempty"`
	RuleID         string                        `json:"rule_id,omitempty"`
	GapState       string                        `json:"gap_state"`
	DueAt          string                        `json:"due_at,omitempty"`
	StateReason    string                        `json:"state_reason,omitempty"`
	StateUpdatedAt string                        `json:"state_updated_at,omitempty"`
	LastAction     string                        `json:"last_action,omitempty"`
	LastActor      string                        `json:"last_actor,omitempty"`
	MissingFields  []string                      `json:"missing_fields,omitempty"`
	SourceFields   map[string]string             `json:"source_fields,omitempty"`
	Trace          []grcPolicyGovernanceGapTrace `json:"trace,omitempty"`
	PolicyID       string                        `json:"policy_id,omitempty"`
	DocumentID     string                        `json:"document_id,omitempty"`
	RiskID         string                        `json:"risk_id,omitempty"`
}

type grcPolicyGovernanceGapTrace struct {
	EventID    string `json:"event_id,omitempty"`
	Action     string `json:"action,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Status     string `json:"status,omitempty"`
	OccurredAt string `json:"occurred_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type grcPolicyGovernanceRule struct {
	ID         string   `json:"id"`
	Profile    string   `json:"profile"`
	Subject    string   `json:"subject"`
	Field      string   `json:"field"`
	Label      string   `json:"label"`
	Severity   string   `json:"severity"`
	Required   bool     `json:"required"`
	ActionID   string   `json:"action_id"`
	Action     string   `json:"action"`
	AppliesTo  []string `json:"applies_to,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
}

type grcPolicyGovernanceGapRollups struct {
	ByState    []grcPolicyGovernanceGapRollup `json:"by_state,omitempty"`
	ByOwner    []grcPolicyGovernanceGapRollup `json:"by_owner,omitempty"`
	BySeverity []grcPolicyGovernanceGapRollup `json:"by_severity,omitempty"`
	BySubject  []grcPolicyGovernanceGapRollup `json:"by_subject,omitempty"`
}

type grcPolicyGovernanceGapRollup struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type grcPolicyLifecyclePolicy struct {
	ID             string `json:"id"`
	URN            string `json:"urn"`
	Title          string `json:"title"`
	LatestVersion  string `json:"latest_version,omitempty"`
	VersionStatus  string `json:"version_status,omitempty"`
	ApprovalStatus string `json:"approval_status,omitempty"`
	grcPolicyLifecyclePolicyMetadata
	AcceptanceSummary grcPolicyAcceptanceSummary `json:"acceptance_summary"`
	ExceptionSummary  grcPolicyExceptionSummary  `json:"exception_summary"`
	Versions          []grcPolicyVersionItem     `json:"versions,omitempty"`
	Approvals         []grcPolicyApprovalItem    `json:"approvals,omitempty"`
	Attestations      []grcPolicyAcceptanceItem  `json:"attestations,omitempty"`
	Reviews           []grcPolicyReviewItem      `json:"reviews,omitempty"`
	Exceptions        []grcPolicyExceptionItem   `json:"exceptions,omitempty"`
	grcPolicyLifecyclePolicyActivity
	Assignments      []grcPolicyAssignmentItem      `json:"assignments,omitempty"`
	Controls         []grcPolicyControlRef          `json:"controls,omitempty"`
	Evidence         []grcPolicyEvidenceRef         `json:"evidence,omitempty"`
	EvidenceSnippets []grcPolicyEvidenceSnippetItem `json:"evidence_snippets,omitempty"`
	Attributes       map[string]string              `json:"attributes,omitempty"`
}

type grcPolicyEvidenceSnippetItem struct {
	ID                string                `json:"id"`
	URN               string                `json:"urn"`
	Title             string                `json:"title"`
	PolicyID          string                `json:"policy_id,omitempty"`
	DocumentID        string                `json:"document_id,omitempty"`
	SectionID         string                `json:"section_id,omitempty"`
	SectionTitle      string                `json:"section_title,omitempty"`
	Page              string                `json:"page,omitempty"`
	Text              string                `json:"text,omitempty"`
	PolicyCitations   []string              `json:"policy_citations,omitempty"`
	Confidence        string                `json:"confidence,omitempty"`
	ReviewState       string                `json:"review_state,omitempty"`
	ManualReviewState string                `json:"manual_review_state,omitempty"`
	UnsupportedClaims []string              `json:"unsupported_claims,omitempty"`
	SourceProvenance  string                `json:"source_provenance,omitempty"`
	Controls          []grcPolicyControlRef `json:"controls,omitempty"`
	QuestionIDs       []string              `json:"question_ids,omitempty"`
	Attributes        map[string]string     `json:"attributes,omitempty"`
}

type grcPolicyLifecyclePolicyMetadata struct {
	PolicyType         string `json:"policy_type,omitempty"`
	Status             string `json:"status,omitempty"`
	Owner              string `json:"owner,omitempty"`
	Reviewer           string `json:"reviewer,omitempty"`
	ApprovingAuthority string `json:"approving_authority,omitempty"`
	ReviewCadence      string `json:"review_cadence,omitempty"`
	LastReviewedAt     string `json:"last_reviewed_at,omitempty"`
	NextReviewDueAt    string `json:"next_review_due_at,omitempty"`
	EffectiveAt        string `json:"effective_at,omitempty"`
	ExceptionPath      string `json:"exception_path,omitempty"`
}

type grcPolicyLifecyclePolicyActivity struct {
	Events       []grcPolicyLifecycleEventItem  `json:"events,omitempty"`
	Actions      []grcPolicyLifecycleActionItem `json:"actions,omitempty"`
	VersionDiffs []grcPolicyVersionDiffItem     `json:"version_diffs,omitempty"`
	ReminderPlan []grcPolicyReminderPlanItem    `json:"reminder_plan,omitempty"`
}

type grcPolicyVersionItem struct {
	ID            string                    `json:"id"`
	URN           string                    `json:"urn"`
	PolicyID      string                    `json:"policy_id,omitempty"`
	Title         string                    `json:"title"`
	Version       string                    `json:"version,omitempty"`
	Status        string                    `json:"status,omitempty"`
	Author        string                    `json:"author,omitempty"`
	Owner         string                    `json:"owner,omitempty"`
	CreatedAt     string                    `json:"created_at,omitempty"`
	ApprovedAt    string                    `json:"approved_at,omitempty"`
	EffectiveAt   string                    `json:"effective_at,omitempty"`
	ChangeSummary string                    `json:"change_summary,omitempty"`
	DiffSummary   string                    `json:"diff_summary,omitempty"`
	DiffURL       string                    `json:"diff_url,omitempty"`
	Controls      []grcPolicyControlRef     `json:"controls,omitempty"`
	Evidence      []grcPolicyEvidenceRef    `json:"evidence,omitempty"`
	Assignments   []grcPolicyAssignmentItem `json:"assignments,omitempty"`
}

type grcPolicyApprovalItem struct {
	ID          string   `json:"id"`
	URN         string   `json:"urn"`
	PolicyID    string   `json:"policy_id,omitempty"`
	VersionID   string   `json:"policy_version_id,omitempty"`
	Step        string   `json:"step,omitempty"`
	Status      string   `json:"status,omitempty"`
	Approvers   []string `json:"approvers,omitempty"`
	RequestedBy string   `json:"requested_by,omitempty"`
	RequestedAt string   `json:"requested_at,omitempty"`
	ApprovedAt  string   `json:"approved_at,omitempty"`
	DueAt       string   `json:"due_at,omitempty"`
}

type grcPolicyAcceptanceItem struct {
	ID         string   `json:"id"`
	URN        string   `json:"urn"`
	PolicyID   string   `json:"policy_id,omitempty"`
	VersionID  string   `json:"policy_version_id,omitempty"`
	Person     string   `json:"person,omitempty"`
	Assignees  []string `json:"assignees,omitempty"`
	Status     string   `json:"status,omitempty"`
	AcceptedAt string   `json:"accepted_at,omitempty"`
	DueAt      string   `json:"due_at,omitempty"`
}

type grcPolicyReviewItem struct {
	ID          string   `json:"id"`
	URN         string   `json:"urn"`
	PolicyID    string   `json:"policy_id,omitempty"`
	VersionID   string   `json:"policy_version_id,omitempty"`
	Status      string   `json:"status,omitempty"`
	Cadence     string   `json:"cadence,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Reviewers   []string `json:"reviewers,omitempty"`
	ReviewDueAt string   `json:"review_due_at,omitempty"`
	ReviewedAt  string   `json:"reviewed_at,omitempty"`
}

type grcPolicyExceptionItem struct {
	ID         string                `json:"id"`
	URN        string                `json:"urn"`
	PolicyID   string                `json:"policy_id,omitempty"`
	VersionID  string                `json:"policy_version_id,omitempty"`
	Title      string                `json:"title"`
	Status     string                `json:"status,omitempty"`
	Owner      string                `json:"owner,omitempty"`
	Approvers  []string              `json:"approvers,omitempty"`
	Targets    []grcPolicyTargetRef  `json:"targets,omitempty"`
	Controls   []grcPolicyControlRef `json:"controls,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	ApprovedAt string                `json:"approved_at,omitempty"`
	ExpiresAt  string                `json:"expires_at,omitempty"`
}

type grcPolicyReminderItem struct {
	ID          string   `json:"id"`
	URN         string   `json:"urn"`
	PolicyID    string   `json:"policy_id,omitempty"`
	VersionID   string   `json:"policy_version_id,omitempty"`
	Title       string   `json:"title"`
	Status      string   `json:"status,omitempty"`
	Channel     string   `json:"channel,omitempty"`
	Recipients  []string `json:"recipients,omitempty"`
	EscalatedTo []string `json:"escalated_to,omitempty"`
	DueAt       string   `json:"due_at,omitempty"`
	SentAt      string   `json:"sent_at,omitempty"`
}

type grcPolicyLifecycleEventItem struct {
	ID         string            `json:"id"`
	URN        string            `json:"urn"`
	PolicyID   string            `json:"policy_id,omitempty"`
	VersionID  string            `json:"policy_version_id,omitempty"`
	RecordURN  string            `json:"record_urn,omitempty"`
	RecordType string            `json:"record_type,omitempty"`
	EventKind  string            `json:"event_kind,omitempty"`
	Action     string            `json:"action,omitempty"`
	Status     string            `json:"status,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	OccurredAt string            `json:"occurred_at,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type grcPolicyLifecycleActionItem struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Label      string `json:"label"`
	PolicyID   string `json:"policy_id,omitempty"`
	Policy     string `json:"policy,omitempty"`
	VersionID  string `json:"policy_version_id,omitempty"`
	RecordURN  string `json:"record_urn,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Status     string `json:"status,omitempty"`
	Owner      string `json:"owner,omitempty"`
	DueAt      string `json:"due_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type grcPolicyVersionDiffItem struct {
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyTitle   string `json:"policy_title,omitempty"`
	FromVersionID string `json:"from_version_id,omitempty"`
	FromVersion   string `json:"from_version,omitempty"`
	ToVersionID   string `json:"to_version_id,omitempty"`
	ToVersion     string `json:"to_version,omitempty"`
	Status        string `json:"status,omitempty"`
	ChangeSummary string `json:"change_summary,omitempty"`
	DiffSummary   string `json:"diff_summary,omitempty"`
	DiffURL       string `json:"diff_url,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	ApprovedAt    string `json:"approved_at,omitempty"`
}

type grcPolicyReminderPlanItem struct {
	ID         string   `json:"id"`
	PolicyID   string   `json:"policy_id,omitempty"`
	Policy     string   `json:"policy,omitempty"`
	RecordURN  string   `json:"record_urn,omitempty"`
	RecordType string   `json:"record_type,omitempty"`
	Action     string   `json:"action"`
	Owner      string   `json:"owner,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
	DueAt      string   `json:"due_at,omitempty"`
	EscalateAt string   `json:"escalate_at,omitempty"`
	Channel    string   `json:"channel,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

type grcPolicyLifecycleMapping struct {
	PolicyID    string                 `json:"policy_id,omitempty"`
	PolicyTitle string                 `json:"policy_title,omitempty"`
	SourceURN   string                 `json:"source_urn"`
	SourceType  string                 `json:"source_type"`
	Target      grcPolicyTargetRef     `json:"target"`
	Controls    []grcPolicyControlRef  `json:"controls,omitempty"`
	Evidence    []grcPolicyEvidenceRef `json:"evidence,omitempty"`
}

type grcPolicyLifecycleWork struct {
	ID        string `json:"id"`
	PolicyID  string `json:"policy_id,omitempty"`
	Policy    string `json:"policy,omitempty"`
	RecordURN string `json:"record_urn"`
	Type      string `json:"type"`
	Status    string `json:"status,omitempty"`
	Owner     string `json:"owner,omitempty"`
	DueAt     string `json:"due_at,omitempty"`
	Action    string `json:"action"`
}

type grcPolicyDocumentWork struct {
	ID         string `json:"id"`
	DocumentID string `json:"document_id,omitempty"`
	Document   string `json:"document,omitempty"`
	RecordURN  string `json:"record_urn"`
	Type       string `json:"type"`
	Status     string `json:"status,omitempty"`
	Owner      string `json:"owner,omitempty"`
	DueAt      string `json:"due_at,omitempty"`
	Action     string `json:"action"`
	PolicyID   string `json:"policy_id,omitempty"`
	RiskID     string `json:"risk_id,omitempty"`
}

type grcPolicyAcceptanceSummary struct {
	Accepted int `json:"accepted"`
	Overdue  int `json:"overdue"`
	Pending  int `json:"pending"`
	Total    int `json:"total"`
}

type grcPolicyExceptionSummary struct {
	Active   int `json:"active"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
}

type grcPolicyAssignmentItem struct {
	TargetURN  string `json:"target_urn"`
	TargetType string `json:"target_type,omitempty"`
	Label      string `json:"label"`
	Scope      string `json:"scope,omitempty"`
}

type grcPolicyControlRef struct {
	URN       string `json:"urn"`
	ControlID string `json:"control_id,omitempty"`
	Framework string `json:"framework,omitempty"`
	Title     string `json:"title,omitempty"`
}

type grcPolicyEvidenceRef struct {
	URN          string `json:"urn"`
	EntityType   string `json:"entity_type,omitempty"`
	Title        string `json:"title,omitempty"`
	DocumentID   string `json:"document_id,omitempty"`
	EvidenceType string `json:"evidence_type,omitempty"`
}

type grcPolicyTargetRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type,omitempty"`
	Label      string `json:"label"`
}

type grcPolicyGraphNode struct {
	URN        string
	TenantID   string
	SourceID   string
	RuntimeID  string
	EntityType string
	Label      string
	Attrs      map[string]string
}

type grcPolicyGraphRelation struct {
	From     *grcPolicyGraphNode
	To       *grcPolicyGraphNode
	Relation string
	Attrs    map[string]string
}

func Build(ctx context.Context, store ports.GraphQueryStore, scope Scope) (Response, error) {
	limit := int(scope.Limit)
	if limit <= 0 {
		limit = grcPolicyLifecycleDefaultLimit
	}
	entityTypeLimit := grcPolicyLifecycleEntityTypeLimit(limit)
	entityRowLimit := grcPolicyLifecycleEntityRowLimit(entityTypeLimit)
	entityRows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: grcPolicyLifecycleEntitiesQuery,
		Params: map[string]any{
			"tenant_id":                   scope.TenantID,
			"source_id":                   scope.SourceID,
			"runtime_id":                  scope.RuntimeID,
			"entity_types":                grcPolicyLifecycleEntityTypes,
			"type_limit":                  entityTypeLimit,
			"risk_scenario_attr_fragment": grcPolicyLifecycleRiskScenarioAttrFragment,
			"document_attr_fragments":     grcPolicyLifecycleDocumentAttrFragments,
		},
		RowLimit: entityRowLimit,
	})
	if err != nil {
		return Response{}, err
	}
	relationLimit := limit * 20
	if relationLimit < grcPolicyLifecycleDefaultRelationLimit {
		relationLimit = grcPolicyLifecycleDefaultRelationLimit
	}
	if relationLimit > ports.MaxCypherQueryRows {
		relationLimit = ports.MaxCypherQueryRows
	}
	relationRows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: grcPolicyLifecycleRelationsQuery,
		Params: map[string]any{
			"tenant_id":                   scope.TenantID,
			"source_id":                   scope.SourceID,
			"runtime_id":                  scope.RuntimeID,
			"entity_types":                grcPolicyLifecycleEntityTypes,
			"limit":                       relationLimit,
			"risk_scenario_attr_fragment": grcPolicyLifecycleRiskScenarioAttrFragment,
			"document_attr_fragments":     grcPolicyLifecycleDocumentAttrFragments,
			"policy_anchor_entity_types":  grcPolicyLifecycleAnchorEntityTypes,
		},
		RowLimit: relationLimit,
	})
	if err != nil {
		return Response{}, err
	}
	return grcPolicyLifecycleFromGraphWithScope(entityRows, relationRows, time.Now().UTC(), scope), nil
}

func grcPolicyLifecycleEntityTypeLimit(limit int) int {
	if limit <= 0 {
		limit = grcPolicyLifecycleDefaultLimit
	}
	maxPerType := ports.MaxCypherQueryRows / len(grcPolicyLifecycleEntityTypes)
	if maxPerType > 0 && limit > maxPerType {
		return maxPerType
	}
	return limit
}

func grcPolicyLifecycleEntityRowLimit(typeLimit int) int {
	if typeLimit <= 0 {
		typeLimit = grcPolicyLifecycleDefaultLimit
	}
	rowLimit := typeLimit * len(grcPolicyLifecycleEntityTypes)
	if rowLimit > ports.MaxCypherQueryRows {
		return ports.MaxCypherQueryRows
	}
	return rowLimit
}

func grcPolicyLifecycleFromGraph(entityRows []ports.CypherRow, relationRows []ports.CypherRow, generatedAt time.Time) Response {
	return grcPolicyLifecycleFromGraphWithScope(entityRows, relationRows, generatedAt, Scope{})
}

func grcPolicyLifecycleFromGraphWithScope(entityRows []ports.CypherRow, relationRows []ports.CypherRow, generatedAt time.Time, scope Scope) Response {
	nodes := map[string]*grcPolicyGraphNode{}
	entityNodeURNs := map[string]struct{}{}
	for _, row := range entityRows {
		node := grcPolicyNodeFromRow(row, "")
		if node != nil {
			nodes[node.URN] = node
			entityNodeURNs[node.URN] = struct{}{}
		}
	}
	relations := make([]grcPolicyGraphRelation, 0, len(relationRows))
	for _, row := range relationRows {
		from := grcPolicyNodeFromRow(row, "left_")
		to := grcPolicyNodeFromRow(row, "right_")
		if from == nil || to == nil {
			continue
		}
		nodes[from.URN] = from
		nodes[to.URN] = to
		relations = append(relations, grcPolicyGraphRelation{
			From:     from,
			To:       to,
			Relation: grcPolicyRowString(row, "relation"),
			Attrs:    grcPolicyAttrs(grcPolicyRowString(row, "relation_attributes_json")),
		})
	}

	policyBuilders := map[string]*grcPolicyLifecyclePolicy{}
	policyURNToID := map[string]string{}
	for _, node := range nodes {
		if _, ok := entityNodeURNs[node.URN]; !ok {
			continue
		}
		if !grcPolicyIsPolicyNode(node) {
			continue
		}
		item := grcPolicyLifecyclePolicy{
			ID:    grcPolicyPolicyID(node),
			URN:   node.URN,
			Title: grcPolicyNodeTitle(node),
			grcPolicyLifecyclePolicyMetadata: grcPolicyLifecyclePolicyMetadata{
				PolicyType:         grcPolicyAttr(node, "policy_document_type", "policy_category", "category", "document_type", "policy_type"),
				Status:             grcPolicyAttr(node, "status", "policy_status", "lifecycle_state"),
				Owner:              grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
				Reviewer:           firstNonEmptyWith(grcPolicyAttr(node, "reviewer", "reviewer_user_id"), grcPolicyActionActors(node.URN, relations, "reviewed")),
				ApprovingAuthority: grcPolicyAttr(node, "approving_authority", "approval_authority", "authority"),
				ReviewCadence:      grcPolicyAttr(node, "review_cadence", "cadence"),
				LastReviewedAt:     grcPolicyAttr(node, "last_reviewed_at", "reviewed_at", "last_review_at"),
				NextReviewDueAt:    grcPolicyAttr(node, "next_review_due_at", "review_due_at", "due_at"),
				EffectiveAt:        grcPolicyAttr(node, "effective_at"),
				ExceptionPath:      grcPolicyAttr(node, "exception_path", "exception_procedure", "waiver_path"),
			},
			Controls:    grcPolicyControlsFor(node.URN, relations),
			Evidence:    grcPolicyEvidenceFor(node.URN, relations),
			Assignments: grcPolicyAssignmentsFor(node.URN, relations),
			Attributes:  grcPolicyPublicAttrs(node.Attrs),
		}
		if item.ID == "" {
			item.ID = node.URN
		}
		policyBuilders[item.ID] = &item
		policyURNToID[node.URN] = item.ID
	}
	ensurePolicy := func(policyID string, label string) *grcPolicyLifecyclePolicy {
		policyID = strings.TrimSpace(policyID)
		if policyID == "" {
			policyID = strings.TrimSpace(label)
		}
		if policyID == "" {
			policyID = "unmapped"
		}
		if item, ok := policyBuilders[policyID]; ok {
			return item
		}
		item := &grcPolicyLifecyclePolicy{ID: policyID, Title: firstNonEmpty(label, policyID)}
		policyBuilders[policyID] = item
		return item
	}

	templates := []grcPolicyTemplateItem{}
	documents := []grcPolicyDocumentItem{}
	riskRegister := []grcPolicyRiskRegisterItem{}
	evidenceSnippets := []grcPolicyEvidenceSnippetItem{}
	reminders := []grcPolicyReminderItem{}
	events := []grcPolicyLifecycleEventItem{}
	mappings := []grcPolicyLifecycleMapping{}
	for _, node := range nodes {
		if _, ok := entityNodeURNs[node.URN]; !ok {
			continue
		}
		switch node.EntityType {
		case "document":
			item := grcPolicyDocumentFromNode(node, relations, policyURNToID)
			if grcPolicyDocumentInScope(item) {
				documents = append(documents, item)
				mappings = append(mappings, grcPolicyDocumentMappings(item)...)
			}
		case "claim":
			if !grcPolicyIsRiskScenarioNode(node) {
				continue
			}
			item := grcPolicyRiskRegisterFromNode(node, relations, policyURNToID)
			riskRegister = append(riskRegister, item)
		case "policy.template":
			templates = append(templates, grcPolicyTemplateFromNode(node, relations))
			mappings = append(mappings, grcPolicyMappingForNode(node, "", "", relations)...)
		case "policy.version":
			item := grcPolicyVersionFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Versions = append(policy.Versions, item)
			policy.Assignments = appendPolicyAssignments(policy.Assignments, item.Assignments)
			policy.Controls = appendPolicyControls(policy.Controls, item.Controls)
			policy.Evidence = appendPolicyEvidence(policy.Evidence, item.Evidence)
			mappings = append(mappings, grcPolicyMappingForNode(node, policy.ID, policy.Title, relations)...)
		case "policy.approval":
			item := grcPolicyApprovalFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Approvals = append(policy.Approvals, item)
		case "policy.acceptance":
			item := grcPolicyAcceptanceFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Attestations = append(policy.Attestations, item)
			policy.Assignments = appendPolicyAssignments(policy.Assignments, grcPolicyAssignmentsFor(node.URN, relations))
		case "policy.review":
			item := grcPolicyReviewFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Reviews = append(policy.Reviews, item)
		case "policy.exception":
			item := grcPolicyExceptionFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Exceptions = append(policy.Exceptions, item)
			policy.Controls = appendPolicyControls(policy.Controls, item.Controls)
			mappings = append(mappings, grcPolicyMappingForNode(node, policy.ID, policy.Title, relations)...)
		case "policy.reminder":
			item := grcPolicyReminderFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			reminders = append(reminders, item)
		case "policy.lifecycle.event":
			item := grcPolicyLifecycleEventFromNode(node, relations)
			if firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)) != "" || item.RecordType != "governance.gap" {
				policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
				item.PolicyID = policy.ID
				policy.Events = append(policy.Events, item)
			}
			events = append(events, item)
		case "policy.evidence_snippet":
			item := grcPolicyEvidenceSnippetFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.EvidenceSnippets = appendPolicyEvidenceSnippets(policy.EvidenceSnippets, []grcPolicyEvidenceSnippetItem{item})
			policy.Controls = appendPolicyControls(policy.Controls, item.Controls)
			evidenceSnippets = append(evidenceSnippets, item)
			mappings = append(mappings, grcPolicyMappingForNode(node, policy.ID, policy.Title, relations)...)
		}
	}

	policies := make([]grcPolicyLifecyclePolicy, 0, len(policyBuilders))
	versionDiffs := []grcPolicyVersionDiffItem{}
	reminderPlan := []grcPolicyReminderPlanItem{}
	for _, policy := range policyBuilders {
		grcPolicyFinalize(policy, generatedAt)
		versionDiffs = append(versionDiffs, policy.VersionDiffs...)
		reminderPlan = append(reminderPlan, policy.ReminderPlan...)
		policies = append(policies, *policy)
	}
	sort.Slice(policies, func(i, j int) bool {
		return strings.ToLower(policies[i].Title) < strings.ToLower(policies[j].Title)
	})
	sort.Slice(templates, func(i, j int) bool {
		return strings.ToLower(templates[i].Title) < strings.ToLower(templates[j].Title)
	})
	sort.Slice(documents, func(i, j int) bool {
		return strings.ToLower(documents[i].Title) < strings.ToLower(documents[j].Title)
	})
	sort.Slice(riskRegister, func(i, j int) bool {
		left := grcPolicySortDate(riskRegister[i].ReviewDueAt, riskRegister[i].TreatmentDueAt)
		right := grcPolicySortDate(riskRegister[j].ReviewDueAt, riskRegister[j].TreatmentDueAt)
		if left.Equal(right) {
			return strings.ToLower(riskRegister[i].Title) < strings.ToLower(riskRegister[j].Title)
		}
		return left.Before(right)
	})
	sort.Slice(evidenceSnippets, func(i, j int) bool {
		if evidenceSnippets[i].DocumentID == evidenceSnippets[j].DocumentID {
			return evidenceSnippets[i].SectionID < evidenceSnippets[j].SectionID
		}
		return evidenceSnippets[i].DocumentID < evidenceSnippets[j].DocumentID
	})
	grcPolicyAttachEvidenceSnippetsToDocuments(documents, evidenceSnippets)
	sort.Slice(reminders, func(i, j int) bool {
		return grcPolicySortDate(reminders[i].DueAt, reminders[i].SentAt).Before(grcPolicySortDate(reminders[j].DueAt, reminders[j].SentAt))
	})
	sort.Slice(events, func(i, j int) bool {
		left := grcPolicySortDate(events[i].OccurredAt)
		right := grcPolicySortDate(events[j].OccurredAt)
		if left.Equal(right) {
			return events[i].URN < events[j].URN
		}
		return left.After(right)
	})
	sort.Slice(versionDiffs, func(i, j int) bool {
		left := grcPolicySortDate(versionDiffs[i].CreatedAt, versionDiffs[i].ApprovedAt)
		right := grcPolicySortDate(versionDiffs[j].CreatedAt, versionDiffs[j].ApprovedAt)
		if left.Equal(right) {
			return versionDiffs[i].ToVersionID < versionDiffs[j].ToVersionID
		}
		return left.After(right)
	})
	sort.Slice(reminderPlan, func(i, j int) bool {
		left := grcPolicySortDate(reminderPlan[i].DueAt, reminderPlan[i].EscalateAt)
		right := grcPolicySortDate(reminderPlan[j].DueAt, reminderPlan[j].EscalateAt)
		if left.Equal(right) {
			return reminderPlan[i].ID < reminderPlan[j].ID
		}
		return left.Before(right)
	})
	governanceRules := grcPolicyGovernanceRules(scope.RuleProfile)
	governanceGaps := grcPolicyGovernanceGapsFor(documents, riskRegister, governanceRules, events, generatedAt)
	return Response{
		Summary:           grcPolicyLifecycleSummaryFrom(policies, templates, documents, riskRegister, mappings, governanceGaps, generatedAt),
		Templates:         templates,
		Policies:          policies,
		Documents:         documents,
		RiskRegister:      riskRegister,
		EvidenceSnippets:  evidenceSnippets,
		GovernanceGaps:    governanceGaps,
		GovernanceRules:   governanceRules,
		GapRollups:        grcPolicyGovernanceGapRollupsFrom(governanceGaps),
		WorkQueue:         grcPolicyLifecycleWorkQueue(policies, generatedAt),
		DocumentWorkQueue: grcPolicyDocumentWorkQueue(documents, riskRegister, generatedAt),
		Reminders:         reminders,
		Events:            events,
		AvailableActions:  ActionDefinitions(),
		VersionDiffs:      versionDiffs,
		ReminderPlan:      reminderPlan,
		Mappings:          grcPolicyDeduplicateMappings(mappings),
		GeneratedAt:       generatedAt,
	}
}

func grcPolicyNodeFromRow(row ports.CypherRow, prefix string) *grcPolicyGraphNode {
	urn := grcPolicyRowString(row, prefix+"urn")
	if urn == "" {
		return nil
	}
	return &grcPolicyGraphNode{
		URN:        urn,
		TenantID:   grcPolicyRowString(row, prefix+"tenant_id"),
		SourceID:   grcPolicyRowString(row, prefix+"source_id"),
		RuntimeID:  grcPolicyRowString(row, prefix+"runtime_id"),
		EntityType: grcPolicyRowString(row, prefix+"entity_type"),
		Label:      grcPolicyRowString(row, prefix+"label"),
		Attrs:      grcPolicyAttrs(grcPolicyRowString(row, prefix+"attributes_json")),
	}
}

func grcPolicyTemplateFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyTemplateItem {
	return grcPolicyTemplateItem{
		ID:         grcPolicyNodeID(node, "template_id", "policy_template_id"),
		URN:        node.URN,
		Title:      grcPolicyNodeTitle(node),
		Status:     grcPolicyAttr(node, "status", "template_status", "lifecycle_state"),
		Category:   grcPolicyAttr(node, "category", "policy_category"),
		Frameworks: grcPolicyListAttr(node, "frameworks", "framework"),
		Owner:      grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		Controls:   grcPolicyControlsFor(node.URN, relations),
		Evidence:   grcPolicyEvidenceFor(node.URN, relations),
		Attributes: grcPolicyPublicAttrs(node.Attrs),
	}
}

func grcPolicyDocumentFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation, policyURNToID map[string]string) grcPolicyDocumentItem {
	return grcPolicyDocumentItem{
		ID:    grcPolicyNodeID(node, "document_id", "policy_document_id", "external_id"),
		URN:   node.URN,
		Title: grcPolicyNodeTitle(node),
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			PolicyType:              grcPolicyAttr(node, "policy_document_type", "policy_category", "category", "policy_type"),
			DocumentType:            firstNonEmpty(grcPolicyAttr(node, "document_type", "file_type", "policy_document_type"), grcPolicyAttr(node, "category")),
			DocumentClass:           grcPolicyDocumentClass(node),
			Status:                  grcPolicyAttr(node, "status", "document_status", "lifecycle_state"),
			Owner:                   firstNonEmpty(grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true), grcPolicyAttr(node, "owner", "owner_email")),
			ApprovingAuthority:      grcPolicyAttr(node, "approving_authority", "approval_authority", "authority"),
			Version:                 grcPolicyAttr(node, "version", "version_number"),
			ReviewCadence:           grcPolicyAttr(node, "review_cadence", "cadence"),
			LastReviewedAt:          grcPolicyAttr(node, "last_reviewed_at", "reviewed_at", "last_review_at"),
			NextReviewDueAt:         grcPolicyAttr(node, "next_review_due_at", "review_due_at", "due_at"),
			ApprovedAt:              grcPolicyAttr(node, "approved_at"),
			EffectiveAt:             grcPolicyAttr(node, "effective_at"),
			AcknowledgementEvidence: grcPolicyAttr(node, "acknowledgement_evidence", "acknowledgment_evidence", "attestation_evidence", "acceptance_evidence"),
			ExceptionPath:           grcPolicyAttr(node, "exception_path", "exception_procedure", "waiver_path"),
			SourceProvenance:        grcPolicyAttr(node, "source_provenance", "source_system", "provider", "parse_provider"),
			SourceURL:               grcPolicyAttr(node, "url", "document_url", "file_url", "download_url", "source_url"),
		},
		Policies:   grcPolicyDocumentPoliciesFor(node.URN, relations, policyURNToID),
		Risks:      grcPolicyDocumentRisksFor(node.URN, relations),
		Controls:   grcPolicyControlsFor(node.URN, relations),
		Evidence:   grcPolicyEvidenceFor(node.URN, relations),
		Attributes: grcPolicyPublicAttrs(node.Attrs),
	}
}

func grcPolicyRiskRegisterFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation, policyURNToID map[string]string) grcPolicyRiskRegisterItem {
	documents := grcPolicyRiskDocumentsFor(node.URN, relations)
	sourceDocumentID := ""
	sourceDocumentTitle := ""
	if len(documents) > 0 {
		sourceDocumentID = documents[0].ID
		sourceDocumentTitle = documents[0].Title
	}
	return grcPolicyRiskRegisterItem{
		ID:                  grcPolicyNodeID(node, "risk_id", "risk_register_id", "external_id"),
		URN:                 node.URN,
		Title:               grcPolicyRiskTitle(node),
		Status:              grcPolicyAttr(node, "status", "risk_status", "review_status", "lifecycle_state"),
		Owner:               firstNonEmpty(grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationAssignedTo, true), grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true), grcPolicyAttr(node, "owner", "risk_owner", "owner_email")),
		Category:            grcPolicyAttr(node, "risk_category", "category", "domain"),
		InherentRisk:        grcPolicyAttr(node, "inherent_risk_level", "inherent_risk", "risk_level"),
		ResidualRisk:        grcPolicyAttr(node, "residual_risk_level", "residual_risk"),
		Likelihood:          grcPolicyAttr(node, "likelihood", "likelihood_level"),
		Impact:              grcPolicyAttr(node, "impact", "impact_level"),
		Treatment:           grcPolicyAttr(node, "treatment", "treatment_plan", "response", "mitigation"),
		ReviewDueAt:         grcPolicyAttr(node, "review_due_at", "next_review_due_at", "due_at"),
		TreatmentDueAt:      grcPolicyAttr(node, "treatment_due_at", "mitigation_due_at", "target_due_at"),
		SourceDocumentID:    sourceDocumentID,
		SourceDocumentTitle: sourceDocumentTitle,
		Policies:            grcPolicyRiskPoliciesFor(node.URN, relations, policyURNToID),
		Controls:            grcPolicyControlsFor(node.URN, relations),
		Evidence:            grcPolicyEvidenceFor(node.URN, relations),
		Attributes:          grcPolicyPublicAttrs(node.Attrs),
	}
}

func grcPolicyVersionFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyVersionItem {
	return grcPolicyVersionItem{
		ID:            grcPolicyNodeID(node, "policy_version_id", "version_id"),
		URN:           node.URN,
		PolicyID:      grcPolicyAttr(node, "policy_id"),
		Title:         grcPolicyNodeTitle(node),
		Version:       grcPolicyAttr(node, "version", "version_number"),
		Status:        grcPolicyAttr(node, "status", "policy_status", "lifecycle_state"),
		Author:        firstNonEmpty(grcPolicyActionActors(node.URN, relations, "authored")...),
		Owner:         grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		CreatedAt:     grcPolicyAttr(node, "created_at"),
		ApprovedAt:    grcPolicyAttr(node, "approved_at"),
		EffectiveAt:   grcPolicyAttr(node, "effective_at"),
		ChangeSummary: grcPolicyAttr(node, "change_summary", "summary"),
		DiffSummary:   grcPolicyAttr(node, "diff_summary", "diff"),
		DiffURL:       grcPolicyAttr(node, "diff_url", "compare_url"),
		Controls:      grcPolicyControlsFor(node.URN, relations),
		Evidence:      grcPolicyEvidenceFor(node.URN, relations),
		Assignments:   grcPolicyAssignmentsFor(node.URN, relations),
	}
}

func grcPolicyApprovalFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyApprovalItem {
	approvers := append([]string{}, grcPolicyActionActors(node.URN, relations, "approved")...)
	approvers = append(approvers, grcPolicyActionActors(node.URN, relations, "rejected")...)
	return grcPolicyApprovalItem{
		ID:          grcPolicyNodeID(node, "approval_id", "policy_approval_id"),
		URN:         node.URN,
		PolicyID:    grcPolicyAttr(node, "policy_id"),
		VersionID:   grcPolicyAttr(node, "policy_version_id", "version_id"),
		Step:        grcPolicyAttr(node, "approval_step", "step"),
		Status:      grcPolicyAttr(node, "status", "approval_status"),
		Approvers:   uniqueStrings(append(approvers, grcPolicyListAttr(node, "approver_user_id", "approver_user_ids", "approved_by_user_id")...)),
		RequestedBy: firstNonEmpty(grcPolicyActionActors(node.URN, relations, "requested_approval")...),
		RequestedAt: grcPolicyAttr(node, "requested_at"),
		ApprovedAt:  grcPolicyAttr(node, "approved_at", "reviewed_at"),
		DueAt:       grcPolicyAttr(node, "due_at", "approval_due_at"),
	}
}

func grcPolicyAcceptanceFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyAcceptanceItem {
	return grcPolicyAcceptanceItem{
		ID:         grcPolicyNodeID(node, "acceptance_id", "policy_acceptance_id", "attestation_id"),
		URN:        node.URN,
		PolicyID:   grcPolicyAttr(node, "policy_id"),
		VersionID:  grcPolicyAttr(node, "policy_version_id", "version_id"),
		Person:     firstNonEmpty(grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationHasEvidence, false), grcPolicyAttr(node, "person_name", "email", "person_id", "user_id")),
		Assignees:  grcPolicyAssignmentLabelsFor(node.URN, relations),
		Status:     grcPolicyAttr(node, "status", "acceptance_status"),
		AcceptedAt: grcPolicyAttr(node, "accepted_at", "completed_at"),
		DueAt:      grcPolicyAttr(node, "due_at", "acceptance_due_at"),
	}
}

func grcPolicyReviewFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyReviewItem {
	return grcPolicyReviewItem{
		ID:          grcPolicyNodeID(node, "review_id", "policy_review_id"),
		URN:         node.URN,
		PolicyID:    grcPolicyAttr(node, "policy_id"),
		VersionID:   grcPolicyAttr(node, "policy_version_id", "version_id"),
		Status:      grcPolicyAttr(node, "status", "review_status"),
		Cadence:     grcPolicyAttr(node, "review_cadence", "cadence"),
		Owner:       grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		Reviewers:   uniqueStrings(append(grcPolicyActionActors(node.URN, relations, "reviewed"), grcPolicyListAttr(node, "reviewer_user_id", "reviewer_user_ids", "reviewed_by_user_id")...)),
		ReviewDueAt: grcPolicyAttr(node, "review_due_at", "due_at"),
		ReviewedAt:  grcPolicyAttr(node, "reviewed_at", "completed_at"),
	}
}

func grcPolicyExceptionFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyExceptionItem {
	return grcPolicyExceptionItem{
		ID:         grcPolicyNodeID(node, "exception_id", "waiver_id", "policy_exception_id"),
		URN:        node.URN,
		PolicyID:   grcPolicyAttr(node, "policy_id"),
		VersionID:  grcPolicyAttr(node, "policy_version_id", "version_id"),
		Title:      grcPolicyNodeTitle(node),
		Status:     grcPolicyAttr(node, "status", "exception_status", "waiver_status"),
		Owner:      grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		Approvers:  uniqueStrings(append(grcPolicyActionActors(node.URN, relations, "approved_exception"), grcPolicyListAttr(node, "approver_user_id", "approved_by_user_id")...)),
		Targets:    grcPolicyTargetsFor(node.URN, relations),
		Controls:   grcPolicyControlsFor(node.URN, relations),
		Reason:     grcPolicyAttr(node, "reason", "justification", "summary"),
		ApprovedAt: grcPolicyAttr(node, "approved_at"),
		ExpiresAt:  grcPolicyAttr(node, "expires_at", "expiration_at"),
	}
}

func grcPolicyReminderFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyReminderItem {
	return grcPolicyReminderItem{
		ID:          grcPolicyNodeID(node, "reminder_id", "policy_reminder_id", "escalation_id"),
		URN:         node.URN,
		PolicyID:    grcPolicyAttr(node, "policy_id"),
		VersionID:   grcPolicyAttr(node, "policy_version_id", "version_id"),
		Title:       grcPolicyNodeTitle(node),
		Status:      grcPolicyAttr(node, "status", "reminder_status", "escalation_status"),
		Channel:     grcPolicyAttr(node, "channel", "delivery_channel"),
		Recipients:  grcPolicyAssignmentLabelsFor(node.URN, relations),
		EscalatedTo: grcPolicyActionActors(node.URN, relations, "escalated"),
		DueAt:       grcPolicyAttr(node, "due_at", "scheduled_at"),
		SentAt:      grcPolicyAttr(node, "sent_at"),
	}
}

func grcPolicyLifecycleEventFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyLifecycleEventItem {
	return grcPolicyLifecycleEventItem{
		ID:         grcPolicyNodeID(node, "lifecycle_event_id", "source_event_id", "event_id"),
		URN:        node.URN,
		PolicyID:   grcPolicyAttr(node, "policy_id"),
		VersionID:  grcPolicyAttr(node, "policy_version_id", "version_id"),
		RecordURN:  grcPolicyAttr(node, "record_urn"),
		RecordType: grcPolicyAttr(node, "record_type"),
		EventKind:  grcPolicyAttr(node, "event_kind", "kind"),
		Action:     grcPolicyAttr(node, "action", "lifecycle_action"),
		Status:     grcPolicyAttr(node, "status"),
		Actor:      firstNonEmpty(grcPolicyActionActors(node.URN, relations, "")...),
		Reason:     grcPolicyAttr(node, "reason", "justification"),
		OccurredAt: grcPolicyAttr(node, "occurred_at", "created_at", "updated_at"),
		Attributes: grcPolicyPublicAttrs(node.Attrs),
	}
}

func grcPolicyEvidenceSnippetFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyEvidenceSnippetItem {
	return grcPolicyEvidenceSnippetItem{
		ID:                grcPolicyNodeID(node, "snippet_id", "evidence_snippet_id"),
		URN:               node.URN,
		Title:             grcPolicyNodeTitle(node),
		PolicyID:          grcPolicyAttr(node, "policy_id"),
		DocumentID:        grcPolicyAttr(node, "document_id"),
		SectionID:         grcPolicyAttr(node, "section_id"),
		SectionTitle:      grcPolicyAttr(node, "section_title"),
		Page:              grcPolicyAttr(node, "page"),
		Text:              grcPolicyAttr(node, "policy_citations", "snippet_text", "citation_text"),
		PolicyCitations:   grcPolicyCitationList(node),
		Confidence:        grcPolicyAttr(node, "confidence"),
		ReviewState:       grcPolicyAttr(node, "review_state", "manual_review_state"),
		ManualReviewState: grcPolicyAttr(node, "manual_review_state", "review_state"),
		UnsupportedClaims: grcPolicyListAttr(node, "unsupported_claims", "unsupported_claim"),
		SourceProvenance:  grcPolicyAttr(node, "source_provenance", "source_system", "provider"),
		Controls:          grcPolicyControlsFor(node.URN, relations),
		QuestionIDs:       grcPolicyListAttr(node, "question_ids", "question_id"),
		Attributes:        grcPolicyPublicAttrs(node.Attrs),
	}
}

func grcPolicyAttachEvidenceSnippetsToDocuments(documents []grcPolicyDocumentItem, snippets []grcPolicyEvidenceSnippetItem) {
	if len(documents) == 0 || len(snippets) == 0 {
		return
	}
	for index := range documents {
		for _, snippet := range snippets {
			if snippet.DocumentID != "" && snippet.DocumentID == documents[index].ID {
				documents[index].EvidenceSnippets = append(documents[index].EvidenceSnippets, snippet)
			}
		}
		documents[index].EvidenceSnippets = uniquePolicyEvidenceSnippets(documents[index].EvidenceSnippets)
	}
}

func grcPolicyFinalize(policy *grcPolicyLifecyclePolicy, now time.Time) {
	sort.Slice(policy.Versions, func(i, j int) bool {
		iDate, iOK := grcPolicyFirstDate(policy.Versions[i].ApprovedAt, policy.Versions[i].CreatedAt, policy.Versions[i].EffectiveAt)
		jDate, jOK := grcPolicyFirstDate(policy.Versions[j].ApprovedAt, policy.Versions[j].CreatedAt, policy.Versions[j].EffectiveAt)
		if iOK != jOK {
			return iOK
		}
		if iDate.Equal(jDate) {
			return firstNonEmpty(policy.Versions[i].URN, policy.Versions[i].ID) < firstNonEmpty(policy.Versions[j].URN, policy.Versions[j].ID)
		}
		return iDate.After(jDate)
	})
	sort.Slice(policy.Approvals, func(i, j int) bool {
		return grcPolicySortDate(policy.Approvals[i].DueAt, policy.Approvals[i].RequestedAt).Before(grcPolicySortDate(policy.Approvals[j].DueAt, policy.Approvals[j].RequestedAt))
	})
	sort.Slice(policy.Attestations, func(i, j int) bool {
		return grcPolicySortDate(policy.Attestations[i].DueAt, policy.Attestations[i].AcceptedAt).Before(grcPolicySortDate(policy.Attestations[j].DueAt, policy.Attestations[j].AcceptedAt))
	})
	sort.Slice(policy.Reviews, func(i, j int) bool {
		return grcPolicySortDate(policy.Reviews[i].ReviewDueAt, policy.Reviews[i].ReviewedAt).Before(grcPolicySortDate(policy.Reviews[j].ReviewDueAt, policy.Reviews[j].ReviewedAt))
	})
	lastReviewedAt := ""
	if policy.LastReviewedAt == "" {
		for _, review := range policy.Reviews {
			lastReviewedAt = grcPolicyLaterDateString(lastReviewedAt, review.ReviewedAt)
		}
	}
	for _, review := range policy.Reviews {
		if policy.Reviewer == "" {
			policy.Reviewer = firstNonEmpty(review.Reviewers...)
		}
		if policy.ReviewCadence == "" {
			policy.ReviewCadence = review.Cadence
		}
		if policy.NextReviewDueAt == "" {
			policy.NextReviewDueAt = review.ReviewDueAt
		}
		if policy.Reviewer != "" && policy.ReviewCadence != "" && policy.NextReviewDueAt != "" {
			break
		}
	}
	if policy.LastReviewedAt == "" {
		policy.LastReviewedAt = lastReviewedAt
	}
	sort.Slice(policy.Exceptions, func(i, j int) bool {
		return grcPolicySortDate(policy.Exceptions[i].ExpiresAt, policy.Exceptions[i].ApprovedAt).Before(grcPolicySortDate(policy.Exceptions[j].ExpiresAt, policy.Exceptions[j].ApprovedAt))
	})
	sort.Slice(policy.Events, func(i, j int) bool {
		left := grcPolicySortDate(policy.Events[i].OccurredAt)
		right := grcPolicySortDate(policy.Events[j].OccurredAt)
		if left.Equal(right) {
			return policy.Events[i].URN < policy.Events[j].URN
		}
		return left.After(right)
	})
	sort.Slice(policy.EvidenceSnippets, func(i, j int) bool {
		if policy.EvidenceSnippets[i].DocumentID == policy.EvidenceSnippets[j].DocumentID {
			return policy.EvidenceSnippets[i].SectionID < policy.EvidenceSnippets[j].SectionID
		}
		return policy.EvidenceSnippets[i].DocumentID < policy.EvidenceSnippets[j].DocumentID
	})
	if len(policy.Versions) > 0 {
		policy.LatestVersion = firstNonEmpty(policy.Versions[0].Version, policy.Versions[0].ID)
		policy.VersionStatus = policy.Versions[0].Status
		if policy.Owner == "" {
			policy.Owner = policy.Versions[0].Owner
		}
		if policy.EffectiveAt == "" {
			policy.EffectiveAt = policy.Versions[0].EffectiveAt
		}
	}
	for _, approval := range policy.Approvals {
		if policy.ApprovingAuthority == "" {
			policy.ApprovingAuthority = firstNonEmpty(approval.Step, firstNonEmpty(approval.Approvers...))
		}
		if grcPolicyPendingStatus(approval.Status) {
			policy.ApprovalStatus = approval.Status
			break
		}
	}
	if policy.ApprovalStatus == "" && len(policy.Approvals) > 0 {
		policy.ApprovalStatus = policy.Approvals[0].Status
	}
	policy.AcceptanceSummary = grcPolicyAcceptanceRollup(policy.Attestations, now)
	policy.ExceptionSummary = grcPolicyExceptionRollup(policy.Exceptions, now)
	policy.Actions = grcPolicyLifecyclePolicyActions(*policy, now)
	policy.VersionDiffs = grcPolicyVersionDiffsForPolicy(*policy)
	policy.ReminderPlan = grcPolicyReminderPlanForPolicy(*policy, now)
	policy.Assignments = uniqueAssignments(policy.Assignments)
	policy.Controls = uniqueControls(policy.Controls)
	policy.Evidence = uniqueEvidence(policy.Evidence)
	policy.EvidenceSnippets = uniquePolicyEvidenceSnippets(policy.EvidenceSnippets)
}

func grcPolicyLifecycleSummaryFrom(policies []grcPolicyLifecyclePolicy, templates []grcPolicyTemplateItem, documents []grcPolicyDocumentItem, riskRegister []grcPolicyRiskRegisterItem, mappings []grcPolicyLifecycleMapping, governanceGaps []grcPolicyGovernanceGap, now time.Time) grcPolicyLifecycleSummary {
	summary := grcPolicyLifecycleSummary{
		GRCPolicyLifecycleInventorySummary: GRCPolicyLifecycleInventorySummary{
			Policies:          len(policies),
			Templates:         len(templates),
			PolicyDocuments:   len(documents),
			RiskRegisterItems: len(riskRegister),
		},
	}
	accepted := 0
	totalAttestations := 0
	mappedControls := map[string]struct{}{}
	evidence := map[string]struct{}{}
	snippetsSeen := map[string]struct{}{}
	for _, template := range templates {
		for _, control := range template.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range template.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
	}
	for _, document := range documents {
		if grcPolicyDraftStatus(document.Status) {
			summary.DraftDocuments++
		}
		if grcPolicyDocumentDueForReview(document, now) {
			summary.DocumentsDueForReview++
		}
		for _, control := range document.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range document.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
		for _, snippet := range document.EvidenceSnippets {
			if snippet.URN != "" {
				evidence[snippet.URN] = struct{}{}
				if _, ok := snippetsSeen[snippet.URN]; !ok {
					snippetsSeen[snippet.URN] = struct{}{}
					summary.EvidenceSnippets++
					if strings.Contains(strings.ToLower(snippet.ReviewState), "review") {
						summary.SnippetsNeedingReview++
					}
				}
			}
		}
	}
	for _, risk := range riskRegister {
		openRisk := grcPolicyRiskOpen(risk.Status)
		if openRisk {
			summary.OpenRisks++
			if grcPolicyHighRisk(risk.ResidualRisk, risk.InherentRisk) {
				summary.HighRisks++
			}
		}
		for _, control := range risk.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range risk.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
	}
	for _, mapping := range mappings {
		for _, control := range mapping.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range mapping.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
	}
	for _, policy := range policies {
		for _, version := range policy.Versions {
			if grcPolicyDraftStatus(version.Status) {
				summary.DraftVersions++
			}
		}
		for _, approval := range policy.Approvals {
			if grcPolicyPendingStatus(approval.Status) {
				summary.PendingApprovals++
			}
		}
		for _, review := range policy.Reviews {
			if grcPolicyOverdue(review.ReviewDueAt, review.Status, now) {
				summary.OverdueReviews++
			}
		}
		summary.OpenExceptions += policy.ExceptionSummary.Active
		summary.ExpiringExceptions += policy.ExceptionSummary.Expiring
		summary.OverdueAttestations += policy.AcceptanceSummary.Overdue
		summary.LifecycleEvents += len(policy.Events)
		summary.NextReminders += len(policy.ReminderPlan)
		accepted += policy.AcceptanceSummary.Accepted
		totalAttestations += policy.AcceptanceSummary.Total
		for _, control := range policy.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range policy.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
		for _, snippet := range policy.EvidenceSnippets {
			if snippet.URN != "" {
				evidence[snippet.URN] = struct{}{}
				if _, ok := snippetsSeen[snippet.URN]; !ok {
					snippetsSeen[snippet.URN] = struct{}{}
					summary.EvidenceSnippets++
					if strings.Contains(strings.ToLower(snippet.ReviewState), "review") {
						summary.SnippetsNeedingReview++
					}
				}
			}
		}
	}
	if totalAttestations > 0 {
		summary.AttestationCoveragePct = int(float64(accepted) / float64(totalAttestations) * 100)
	}
	for _, gap := range governanceGaps {
		summary.GovernanceGaps++
		switch gap.GapState {
		case "acknowledged":
			summary.AcknowledgedGaps++
		case "snoozed":
			summary.SnoozedGaps++
		case "accepted":
			summary.AcceptedGaps++
		case "resolved":
			summary.ResolvedGaps++
		case "in_progress":
			summary.InProgressGaps++
		default:
			summary.OpenGovernanceGaps++
		}
		if gap.Severity == "high" {
			summary.HighGovernanceGaps++
		}
		switch gap.Subject {
		case "document":
			summary.PolicyDocumentGaps++
		case "risk":
			summary.RiskRegisterGaps++
		}
	}
	summary.MappedControls = len(mappedControls)
	summary.EvidenceItems = len(evidence)
	return summary
}

func grcPolicyGovernanceGaps(documents []grcPolicyDocumentItem, riskRegister []grcPolicyRiskRegisterItem) []grcPolicyGovernanceGap {
	return grcPolicyGovernanceGapsFor(documents, riskRegister, grcPolicyGovernanceRules(""), nil, time.Time{})
}

func grcPolicyGovernanceGapsFor(documents []grcPolicyDocumentItem, riskRegister []grcPolicyRiskRegisterItem, rules []grcPolicyGovernanceRule, events []grcPolicyLifecycleEventItem, now time.Time) []grcPolicyGovernanceGap {
	gaps := []grcPolicyGovernanceGap{}
	rulesByID := grcPolicyGovernanceRuleMap(rules)
	for _, document := range documents {
		// Drafts are still authored; no-status imports stay in scope for metadata gaps.
		if grcPolicyDraftStatus(document.Status) {
			continue
		}
		policyID := grcPolicyFirstDocumentRefID(document.Policies)
		documentID := firstNonEmpty(document.ID, document.URN)
		sourceFields := grcPolicyDocumentGapSourceFields(document)
		if rule, ok := rulesByID["document.owner"]; ok && strings.TrimSpace(document.Owner) == "" {
			gaps = append(gaps, grcPolicyDocumentGovernanceGap(document, rule, documentID, policyID, "owner", "Missing owner"))
		}
		if rule, ok := rulesByID["document.review_date"]; ok && strings.TrimSpace(document.NextReviewDueAt) == "" {
			gaps = append(gaps, grcPolicyDocumentGovernanceGap(document, rule, documentID, policyID, "next_review_due_at", "Missing review date"))
		}
		if rule, ok := rulesByID["document.policy"]; ok && len(document.Policies) == 0 {
			gaps = append(gaps, grcPolicyDocumentGovernanceGap(document, rule, documentID, policyID, "policies", "No linked policy"))
		}
		if rule, ok := rulesByID["document.controls"]; ok && grcPolicyDocumentNeedsControlMapping(document) && len(document.Controls) == 0 {
			gaps = append(gaps, grcPolicyDocumentGovernanceGap(document, rule, documentID, policyID, "controls", "No mapped controls"))
		}
		if rule, ok := rulesByID["document.evidence"]; ok && grcPolicyDocumentNeedsControlMapping(document) && len(document.Evidence) == 0 {
			gap := grcPolicyDocumentGovernanceGap(document, rule, documentID, policyID, "evidence", "No evidence")
			gap.SourceFields = sourceFields
			gaps = append(gaps, gap)
		}
	}
	for _, risk := range riskRegister {
		if !grcPolicyRiskOpen(risk.Status) {
			continue
		}
		policyID := grcPolicyFirstDocumentRefID(risk.Policies)
		riskID := firstNonEmpty(risk.ID, risk.URN)
		severity := grcPolicyRiskGapSeverity(risk)
		if rule, ok := rulesByID["risk.owner"]; ok && strings.TrimSpace(risk.Owner) == "" {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule.withSeverity(severity), riskID, policyID, "owner", "Missing owner"))
		}
		if rule, ok := rulesByID["risk.treatment"]; ok && strings.TrimSpace(risk.Treatment) == "" {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule.withSeverity(severity), riskID, policyID, "treatment", "Missing treatment"))
		}
		if rule, ok := rulesByID["risk.treatment_due"]; ok && strings.TrimSpace(risk.TreatmentDueAt) == "" {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule.withSeverity(severity), riskID, policyID, "treatment_due_at", "Missing treatment date"))
		}
		if rule, ok := rulesByID["risk.review_date"]; ok && strings.TrimSpace(risk.ReviewDueAt) == "" {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule, riskID, policyID, "review_due_at", "Missing review date"))
		}
		if rule, ok := rulesByID["risk.source_document"]; ok && strings.TrimSpace(risk.SourceDocumentID) == "" {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule.withSeverity(severity), riskID, policyID, "source_document_id", "No source document"))
		}
		if rule, ok := rulesByID["risk.policy"]; ok && len(risk.Policies) == 0 {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule.withSeverity(severity), riskID, policyID, "policies", "No linked policy"))
		}
		if rule, ok := rulesByID["risk.controls"]; ok && len(risk.Controls) == 0 {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule.withSeverity(severity), riskID, policyID, "controls", "No mapped controls"))
		}
		if rule, ok := rulesByID["risk.evidence"]; ok && len(risk.Evidence) == 0 {
			gaps = append(gaps, grcPolicyRiskGovernanceGap(risk, rule, riskID, policyID, "evidence", "No evidence"))
		}
	}
	grcPolicyApplyGapEvents(gaps, events, now)
	sort.Slice(gaps, func(i, j int) bool {
		leftState := grcPolicyGapStateRank(gaps[i].GapState)
		rightState := grcPolicyGapStateRank(gaps[j].GapState)
		if leftState != rightState {
			return leftState < rightState
		}
		left := grcPolicyGapSeverityRank(gaps[i].Severity)
		right := grcPolicyGapSeverityRank(gaps[j].Severity)
		if left != right {
			return left < right
		}
		if gaps[i].Subject != gaps[j].Subject {
			return gaps[i].Subject < gaps[j].Subject
		}
		if gaps[i].Title != gaps[j].Title {
			return strings.ToLower(gaps[i].Title) < strings.ToLower(gaps[j].Title)
		}
		return gaps[i].Reason < gaps[j].Reason
	})
	return gaps
}

func (rule grcPolicyGovernanceRule) withSeverity(severity string) grcPolicyGovernanceRule {
	rule.Severity = severity
	return rule
}

func grcPolicyGovernanceRuleMap(rules []grcPolicyGovernanceRule) map[string]grcPolicyGovernanceRule {
	out := make(map[string]grcPolicyGovernanceRule, len(rules))
	for _, rule := range rules {
		out[rule.ID] = rule
	}
	return out
}

func grcPolicyDocumentGovernanceGap(document grcPolicyDocumentItem, rule grcPolicyGovernanceRule, documentID string, policyID string, missingField string, reason string) grcPolicyGovernanceGap {
	return grcPolicyGovernanceGap{
		ID:            document.URN + ":gap:" + strings.TrimPrefix(rule.ID, "document."),
		Subject:       "document",
		SubjectID:     documentID,
		Title:         document.Title,
		Status:        document.Status,
		Owner:         document.Owner,
		Severity:      rule.Severity,
		Reason:        reason,
		Action:        rule.Action,
		ActionID:      rule.ActionID,
		RuleID:        rule.ID,
		GapState:      "open",
		MissingFields: []string{missingField},
		SourceFields:  grcPolicyDocumentGapSourceFields(document),
		PolicyID:      policyID,
		DocumentID:    document.ID,
	}
}

func grcPolicyRiskGovernanceGap(risk grcPolicyRiskRegisterItem, rule grcPolicyGovernanceRule, riskID string, policyID string, missingField string, reason string) grcPolicyGovernanceGap {
	return grcPolicyGovernanceGap{
		ID:            risk.URN + ":gap:" + strings.TrimPrefix(rule.ID, "risk."),
		Subject:       "risk",
		SubjectID:     riskID,
		Title:         risk.Title,
		Status:        risk.Status,
		Owner:         risk.Owner,
		Severity:      rule.Severity,
		Reason:        reason,
		Action:        rule.Action,
		ActionID:      rule.ActionID,
		RuleID:        rule.ID,
		GapState:      "open",
		MissingFields: []string{missingField},
		SourceFields:  grcPolicyRiskGapSourceFields(risk),
		PolicyID:      policyID,
		DocumentID:    risk.SourceDocumentID,
		RiskID:        risk.ID,
	}
}

func grcPolicyGovernanceRules(profile string) []grcPolicyGovernanceRule {
	profile = grcPolicyGovernanceRuleProfile(profile)
	rules := []grcPolicyGovernanceRule{
		{ID: "document.owner", Profile: profile, Subject: "document", Field: "owner", Label: "Document owner", Severity: "medium", Required: true, ActionID: "governance_gap.assign_owner", Action: "Assign owner"},
		{ID: "document.review_date", Profile: profile, Subject: "document", Field: "next_review_due_at", Label: "Document review date", Severity: "medium", Required: true, ActionID: "governance_gap.set_review_date", Action: "Set review date"},
		{ID: "document.policy", Profile: profile, Subject: "document", Field: "policies", Label: "Linked policy", Severity: "medium", Required: true, ActionID: "governance_gap.link_policy", Action: "Link policy"},
		{ID: "document.controls", Profile: profile, Subject: "document", Field: "controls", Label: "Mapped controls", Severity: "medium", Required: true, ActionID: "governance_gap.map_controls", Action: "Map controls", AppliesTo: []string{"policy", "procedure", "standard", "control_narrative"}},
		{ID: "risk.owner", Profile: profile, Subject: "risk", Field: "owner", Label: "Risk owner", Severity: "medium", Required: true, ActionID: "governance_gap.assign_owner", Action: "Assign owner"},
		{ID: "risk.treatment", Profile: profile, Subject: "risk", Field: "treatment", Label: "Risk treatment", Severity: "medium", Required: true, ActionID: "governance_gap.add_treatment", Action: "Add treatment"},
		{ID: "risk.treatment_due", Profile: profile, Subject: "risk", Field: "treatment_due_at", Label: "Treatment date", Severity: "medium", Required: true, ActionID: "governance_gap.set_treatment_date", Action: "Set treatment date"},
		{ID: "risk.review_date", Profile: profile, Subject: "risk", Field: "review_due_at", Label: "Risk review date", Severity: "medium", Required: true, ActionID: "governance_gap.set_review_date", Action: "Set review date"},
		{ID: "risk.source_document", Profile: profile, Subject: "risk", Field: "source_document_id", Label: "Source document", Severity: "medium", Required: true, ActionID: "governance_gap.link_source_document", Action: "Link source document"},
		{ID: "risk.policy", Profile: profile, Subject: "risk", Field: "policies", Label: "Linked policy", Severity: "medium", Required: true, ActionID: "governance_gap.link_policy", Action: "Link policy"},
		{ID: "risk.controls", Profile: profile, Subject: "risk", Field: "controls", Label: "Mapped controls", Severity: "medium", Required: true, ActionID: "governance_gap.map_controls", Action: "Map controls"},
		{ID: "risk.evidence", Profile: profile, Subject: "risk", Field: "evidence", Label: "Risk evidence", Severity: "medium", Required: true, ActionID: "governance_gap.attach_evidence", Action: "Attach evidence"},
	}
	if profile == "strict" {
		rules = append(rules, grcPolicyGovernanceRule{ID: "document.evidence", Profile: profile, Subject: "document", Field: "evidence", Label: "Document evidence", Severity: "low", Required: true, ActionID: "governance_gap.attach_evidence", Action: "Attach evidence", AppliesTo: []string{"policy", "procedure", "standard", "control_narrative"}, Confidence: "strict"})
	}
	return rules
}

func grcPolicyGovernanceRuleProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "strict", "strict_evidence", "evidence":
		return "strict"
	default:
		return "baseline"
	}
}

func grcPolicyDocumentGapSourceFields(document grcPolicyDocumentItem) map[string]string {
	return map[string]string{
		"document_id":        document.ID,
		"document_class":     document.DocumentClass,
		"document_type":      document.DocumentType,
		"status":             document.Status,
		"owner":              document.Owner,
		"next_review_due_at": document.NextReviewDueAt,
		"policy_count":       fmt.Sprint(len(document.Policies)),
		"control_count":      fmt.Sprint(len(document.Controls)),
		"evidence_count":     fmt.Sprint(len(document.Evidence)),
	}
}

func grcPolicyRiskGapSourceFields(risk grcPolicyRiskRegisterItem) map[string]string {
	return map[string]string{
		"risk_id":            risk.ID,
		"status":             risk.Status,
		"owner":              risk.Owner,
		"residual_risk":      risk.ResidualRisk,
		"inherent_risk":      risk.InherentRisk,
		"treatment":          risk.Treatment,
		"review_due_at":      risk.ReviewDueAt,
		"treatment_due_at":   risk.TreatmentDueAt,
		"source_document_id": risk.SourceDocumentID,
		"policy_count":       fmt.Sprint(len(risk.Policies)),
		"control_count":      fmt.Sprint(len(risk.Controls)),
		"evidence_count":     fmt.Sprint(len(risk.Evidence)),
	}
}

func grcPolicyApplyGapEvents(gaps []grcPolicyGovernanceGap, events []grcPolicyLifecycleEventItem, now time.Time) {
	if len(gaps) == 0 || len(events) == 0 {
		return
	}
	eventsByGapID := map[string][]grcPolicyLifecycleEventItem{}
	for _, event := range events {
		for _, gapID := range grcPolicyLifecycleEventGapIDs(event) {
			eventsByGapID[gapID] = append(eventsByGapID[gapID], event)
		}
	}
	for gapID := range eventsByGapID {
		sort.Slice(eventsByGapID[gapID], func(i, j int) bool {
			left := grcPolicySortDate(eventsByGapID[gapID][i].OccurredAt)
			right := grcPolicySortDate(eventsByGapID[gapID][j].OccurredAt)
			if left.Equal(right) {
				return eventsByGapID[gapID][i].ID < eventsByGapID[gapID][j].ID
			}
			return left.Before(right)
		})
	}
	for idx := range gaps {
		gapEvents := eventsByGapID[gaps[idx].ID]
		for _, event := range gapEvents {
			grcPolicyApplyGapEvent(&gaps[idx], event, now)
		}
	}
}

func grcPolicyLifecycleEventGapIDs(event grcPolicyLifecycleEventItem) []string {
	gapIDs := []string{}
	if event.Attributes != nil {
		for _, value := range grcPolicyListValue(event.Attributes["gap_ids"]) {
			if strings.Contains(value, ":gap:") {
				gapIDs = append(gapIDs, value)
			}
		}
		if value := firstNonEmpty(event.Attributes["gap_id"], event.Attributes["record_id"], event.Attributes["record_urn"]); strings.Contains(value, ":gap:") {
			gapIDs = append(gapIDs, value)
		}
	}
	if strings.Contains(event.RecordURN, ":gap:") {
		gapIDs = append(gapIDs, event.RecordURN)
	}
	if strings.Contains(event.ID, ":gap:") {
		gapIDs = append(gapIDs, event.ID)
	}
	return uniqueStrings(gapIDs)
}

func grcPolicyListValue(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
}

func grcPolicyApplyGapEvent(gap *grcPolicyGovernanceGap, event grcPolicyLifecycleEventItem, now time.Time) {
	if gap == nil {
		return
	}
	state := firstNonEmpty(event.Attributes["gap_state"], event.Status)
	if state == "" {
		state = grcPolicyGapStateForAction(event.Action)
	}
	state = grcPolicyNormalizeGapState(state)
	if state == "" {
		state = grcPolicyGapStateForAction(event.Action)
	}
	if state == "" {
		state = "in_progress"
	}
	gap.GapState = state
	gap.StateReason = event.Reason
	gap.StateUpdatedAt = firstNonEmpty(event.OccurredAt, now.Format(time.RFC3339))
	gap.LastAction = event.Action
	gap.LastActor = event.Actor
	gap.DueAt = firstNonEmpty(event.Attributes["due_at"], event.Attributes["expires_at"], gap.DueAt)
	if event.Action == "governance_gap.assign_owner" {
		if owner := firstNonEmpty(event.Attributes["assigned_user_ids"], event.Actor); owner != "" {
			gap.Owner = owner
		}
	} else if gap.Owner == "" {
		gap.Owner = firstNonEmpty(event.Attributes["assigned_user_ids"], event.Actor)
	}
	gap.Trace = append(gap.Trace, grcPolicyGovernanceGapTrace{
		EventID:    event.ID,
		Action:     event.Action,
		Actor:      event.Actor,
		Status:     state,
		OccurredAt: event.OccurredAt,
		Reason:     event.Reason,
	})
}

func grcPolicyGapStateForAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "governance_gap.acknowledge":
		return "acknowledged"
	case "governance_gap.snooze":
		return "snoozed"
	case "governance_gap.accept":
		return "accepted"
	case "governance_gap.resolve":
		return "resolved"
	case "governance_gap.assign_owner", "governance_gap.set_review_date", "governance_gap.link_policy", "governance_gap.map_controls", "governance_gap.add_treatment", "governance_gap.set_treatment_date", "governance_gap.link_source_document", "governance_gap.attach_evidence":
		return "in_progress"
	default:
		return ""
	}
}

func grcPolicyNormalizeGapState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "open", "in_progress", "acknowledged", "snoozed", "accepted", "resolved":
		return strings.ToLower(strings.TrimSpace(state))
	case "done", "closed", "complete", "completed":
		return "resolved"
	case "risk_accepted":
		return "accepted"
	default:
		return ""
	}
}

func grcPolicyGapStateRank(state string) int {
	switch grcPolicyNormalizeGapState(state) {
	case "open":
		return 0
	case "in_progress":
		return 1
	case "acknowledged":
		return 2
	case "snoozed":
		return 3
	case "accepted":
		return 4
	case "resolved":
		return 5
	default:
		return 0
	}
}

func grcPolicyGovernanceGapRollupsFrom(gaps []grcPolicyGovernanceGap) grcPolicyGovernanceGapRollups {
	return grcPolicyGovernanceGapRollups{
		ByState:    grcPolicyGovernanceGapRollupFor(gaps, func(gap grcPolicyGovernanceGap) string { return firstNonEmpty(gap.GapState, "open") }),
		ByOwner:    grcPolicyGovernanceGapRollupFor(gaps, func(gap grcPolicyGovernanceGap) string { return firstNonEmpty(gap.Owner, "unassigned") }),
		BySeverity: grcPolicyGovernanceGapRollupFor(gaps, func(gap grcPolicyGovernanceGap) string { return firstNonEmpty(gap.Severity, "unknown") }),
		BySubject:  grcPolicyGovernanceGapRollupFor(gaps, func(gap grcPolicyGovernanceGap) string { return firstNonEmpty(gap.Subject, "unknown") }),
	}
}

func grcPolicyGovernanceGapRollupFor(gaps []grcPolicyGovernanceGap, keyFn func(grcPolicyGovernanceGap) string) []grcPolicyGovernanceGapRollup {
	counts := map[string]int{}
	for _, gap := range gaps {
		key := strings.TrimSpace(keyFn(gap))
		if key == "" {
			key = "unknown"
		}
		counts[key]++
	}
	items := make([]grcPolicyGovernanceGapRollup, 0, len(counts))
	for key, count := range counts {
		items = append(items, grcPolicyGovernanceGapRollup{Key: key, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	return items
}

func grcPolicyFirstDocumentRefID(refs []grcPolicyDocumentRef) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0].ID
}

func grcPolicyDocumentNeedsControlMapping(document grcPolicyDocumentItem) bool {
	switch document.DocumentClass {
	case "policy", "procedure", "standard", "control_narrative":
		return true
	default:
		return false
	}
}

func grcPolicyRiskGapSeverity(risk grcPolicyRiskRegisterItem) string {
	if grcPolicyHighRisk(risk.ResidualRisk, risk.InherentRisk) {
		return "high"
	}
	return "medium"
}

func grcPolicyGapSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func grcPolicyLifecycleWorkQueue(policies []grcPolicyLifecyclePolicy, now time.Time) []grcPolicyLifecycleWork {
	items := []grcPolicyLifecycleWork{}
	for _, policy := range policies {
		for _, version := range policy.Versions {
			if grcPolicyDraftStatus(version.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: version.URN + ":draft", PolicyID: policy.ID, Policy: policy.Title, RecordURN: version.URN, Type: "version", Status: version.Status, Owner: firstNonEmpty(version.Owner, policy.Owner), DueAt: firstNonEmpty(version.EffectiveAt, version.CreatedAt), Action: "Review draft"})
			}
		}
		for _, approval := range policy.Approvals {
			if grcPolicyPendingStatus(approval.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: approval.URN + ":approval", PolicyID: policy.ID, Policy: policy.Title, RecordURN: approval.URN, Type: "approval", Status: approval.Status, Owner: firstNonEmpty(approval.RequestedBy, firstNonEmpty(approval.Approvers...)), DueAt: approval.DueAt, Action: "Approve version"})
			}
		}
		for _, review := range policy.Reviews {
			if grcPolicyOverdue(review.ReviewDueAt, review.Status, now) || grcPolicyPendingStatus(review.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: review.URN + ":review", PolicyID: policy.ID, Policy: policy.Title, RecordURN: review.URN, Type: "review", Status: review.Status, Owner: firstNonEmpty(review.Owner, firstNonEmpty(review.Reviewers...), policy.Owner), DueAt: review.ReviewDueAt, Action: "Complete owner review"})
			}
		}
		for _, attestation := range policy.Attestations {
			if grcPolicyAcceptanceOpenStatus(attestation.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: attestation.URN + ":attestation", PolicyID: policy.ID, Policy: policy.Title, RecordURN: attestation.URN, Type: "attestation", Status: attestation.Status, Owner: firstNonEmpty(attestation.Person, firstNonEmpty(attestation.Assignees...)), DueAt: attestation.DueAt, Action: "Send reminder"})
			}
		}
		for _, exception := range policy.Exceptions {
			if grcPolicyExceptionOpen(exception.Status) {
				action := "Review exception"
				if grcPolicyExpiring(exception.ExpiresAt, now) {
					action = "Renew or close exception"
				}
				items = append(items, grcPolicyLifecycleWork{ID: exception.URN + ":exception", PolicyID: policy.ID, Policy: policy.Title, RecordURN: exception.URN, Type: "exception", Status: exception.Status, Owner: firstNonEmpty(exception.Owner, firstNonEmpty(exception.Approvers...)), DueAt: exception.ExpiresAt, Action: action})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		left := grcPolicySortDate(items[i].DueAt)
		right := grcPolicySortDate(items[j].DueAt)
		if left.Equal(right) {
			return items[i].RecordURN < items[j].RecordURN
		}
		return left.Before(right)
	})
	return items
}

func grcPolicyDocumentWorkQueue(documents []grcPolicyDocumentItem, riskRegister []grcPolicyRiskRegisterItem, now time.Time) []grcPolicyDocumentWork {
	items := []grcPolicyDocumentWork{}
	for _, document := range documents {
		policyID := ""
		if len(document.Policies) > 0 {
			policyID = document.Policies[0].ID
		}
		if grcPolicyDraftStatus(document.Status) {
			items = append(items, grcPolicyDocumentWork{ID: document.URN + ":draft", DocumentID: document.ID, Document: document.Title, RecordURN: document.URN, Type: "document", Status: document.Status, Owner: document.Owner, DueAt: firstNonEmpty(document.EffectiveAt, document.NextReviewDueAt), Action: "Review draft document", PolicyID: policyID})
		}
		if grcPolicyDocumentDueForReview(document, now) {
			items = append(items, grcPolicyDocumentWork{ID: document.URN + ":review", DocumentID: document.ID, Document: document.Title, RecordURN: document.URN, Type: "document", Status: document.Status, Owner: document.Owner, DueAt: document.NextReviewDueAt, Action: "Complete document review", PolicyID: policyID})
		}
	}
	for _, risk := range riskRegister {
		if !grcPolicyRiskOpen(risk.Status) {
			continue
		}
		if grcPolicyOverdue(risk.ReviewDueAt, risk.Status, now) || grcPolicyOverdue(risk.TreatmentDueAt, risk.Status, now) || grcPolicyHighRisk(risk.ResidualRisk, risk.InherentRisk) {
			dueAt := firstNonEmpty(risk.TreatmentDueAt, risk.ReviewDueAt)
			policyID := ""
			if len(risk.Policies) > 0 {
				policyID = risk.Policies[0].ID
			}
			items = append(items, grcPolicyDocumentWork{ID: risk.URN + ":risk", DocumentID: risk.SourceDocumentID, Document: firstNonEmpty(risk.SourceDocumentTitle, risk.Title), RecordURN: risk.URN, Type: "risk", Status: risk.Status, Owner: risk.Owner, DueAt: dueAt, Action: "Review risk treatment", RiskID: risk.ID, PolicyID: policyID})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		left := grcPolicySortDate(items[i].DueAt)
		right := grcPolicySortDate(items[j].DueAt)
		if left.Equal(right) {
			return items[i].RecordURN < items[j].RecordURN
		}
		return left.Before(right)
	})
	return items
}

func grcPolicyLifecyclePolicyActions(policy grcPolicyLifecyclePolicy, now time.Time) []grcPolicyLifecycleActionItem {
	items := []grcPolicyLifecycleActionItem{}
	for _, version := range policy.Versions {
		if grcPolicyDraftStatus(version.Status) {
			items = append(items, grcPolicyLifecycleActionItem{
				ID:         version.URN + ":draft.submit",
				Action:     "draft.submit",
				Label:      "Submit draft",
				PolicyID:   policy.ID,
				Policy:     policy.Title,
				VersionID:  version.ID,
				RecordURN:  version.URN,
				RecordType: "policy.version",
				Status:     version.Status,
				Owner:      firstNonEmpty(version.Owner, policy.Owner),
				DueAt:      firstNonEmpty(version.EffectiveAt, version.CreatedAt),
				Reason:     "Draft version",
			})
		}
		if strings.EqualFold(version.Status, "approved") && version.EffectiveAt != "" && !grcPolicyPast(version.EffectiveAt, now) {
			items = append(items, grcPolicyLifecycleActionItem{
				ID:         version.URN + ":version.publish",
				Action:     "version.publish",
				Label:      "Publish version",
				PolicyID:   policy.ID,
				Policy:     policy.Title,
				VersionID:  version.ID,
				RecordURN:  version.URN,
				RecordType: "policy.version",
				Status:     version.Status,
				Owner:      firstNonEmpty(version.Owner, policy.Owner),
				DueAt:      version.EffectiveAt,
				Reason:     "Approved version",
			})
		}
	}
	for _, approval := range policy.Approvals {
		if !grcPolicyPendingStatus(approval.Status) {
			continue
		}
		base := grcPolicyLifecycleActionItem{
			PolicyID:   policy.ID,
			Policy:     policy.Title,
			VersionID:  approval.VersionID,
			RecordURN:  approval.URN,
			RecordType: "policy.approval",
			Status:     approval.Status,
			Owner:      firstNonEmpty(firstNonEmpty(approval.Approvers...), approval.RequestedBy),
			DueAt:      approval.DueAt,
			Reason:     "Pending approval",
		}
		approve := base
		approve.ID = approval.URN + ":approval.approve"
		approve.Action = "approval.approve"
		approve.Label = "Approve version"
		items = append(items, approve)
		reject := base
		reject.ID = approval.URN + ":approval.reject"
		reject.Action = "approval.reject"
		reject.Label = "Reject version"
		items = append(items, reject)
	}
	for _, review := range policy.Reviews {
		if grcPolicyOverdue(review.ReviewDueAt, review.Status, now) || grcPolicyPendingStatus(review.Status) {
			items = append(items, grcPolicyLifecycleActionItem{
				ID:         review.URN + ":review.complete",
				Action:     "review.complete",
				Label:      "Complete review",
				PolicyID:   policy.ID,
				Policy:     policy.Title,
				VersionID:  review.VersionID,
				RecordURN:  review.URN,
				RecordType: "policy.review",
				Status:     review.Status,
				Owner:      firstNonEmpty(review.Owner, firstNonEmpty(review.Reviewers...), policy.Owner),
				DueAt:      review.ReviewDueAt,
				Reason:     "Owner review",
			})
		}
	}
	for _, attestation := range policy.Attestations {
		if !grcPolicyAcceptanceOpenStatus(attestation.Status) {
			continue
		}
		items = append(items, grcPolicyLifecycleActionItem{
			ID:         attestation.URN + ":attestation.accept",
			Action:     "attestation.accept",
			Label:      "Record attestation",
			PolicyID:   policy.ID,
			Policy:     policy.Title,
			VersionID:  attestation.VersionID,
			RecordURN:  attestation.URN,
			RecordType: "policy.acceptance",
			Status:     attestation.Status,
			Owner:      firstNonEmpty(attestation.Person, firstNonEmpty(attestation.Assignees...)),
			DueAt:      attestation.DueAt,
			Reason:     "Open attestation",
		})
		action := "reminder.send"
		label := "Send reminder"
		reason := "Open attestation"
		if grcPolicyOverdue(attestation.DueAt, attestation.Status, now) {
			action = "reminder.escalate"
			label = "Escalate reminder"
			reason = "Overdue attestation"
		}
		items = append(items, grcPolicyLifecycleActionItem{
			ID:         attestation.URN + ":" + action,
			Action:     action,
			Label:      label,
			PolicyID:   policy.ID,
			Policy:     policy.Title,
			VersionID:  attestation.VersionID,
			RecordURN:  attestation.URN,
			RecordType: "policy.acceptance",
			Status:     attestation.Status,
			Owner:      firstNonEmpty(attestation.Person, firstNonEmpty(attestation.Assignees...)),
			DueAt:      attestation.DueAt,
			Reason:     reason,
		})
	}
	for _, exception := range policy.Exceptions {
		if !grcPolicyExceptionOpen(exception.Status) {
			continue
		}
		if grcPolicyPendingStatus(exception.Status) {
			items = append(items, grcPolicyExceptionAction(policy, exception, "exception.approve", "Approve exception", "Pending exception"))
			continue
		}
		if grcPolicyExpiring(exception.ExpiresAt, now) {
			items = append(items, grcPolicyExceptionAction(policy, exception, "exception.renew", "Renew exception", "Expiring exception"))
		}
		items = append(items, grcPolicyExceptionAction(policy, exception, "exception.close", "Close exception", "Open exception"))
	}
	sort.Slice(items, func(i, j int) bool {
		left := grcPolicySortDate(items[i].DueAt)
		right := grcPolicySortDate(items[j].DueAt)
		if left.Equal(right) {
			return items[i].ID < items[j].ID
		}
		return left.Before(right)
	})
	return items
}

func grcPolicyExceptionAction(policy grcPolicyLifecyclePolicy, exception grcPolicyExceptionItem, action string, label string, reason string) grcPolicyLifecycleActionItem {
	return grcPolicyLifecycleActionItem{
		ID:         exception.URN + ":" + action,
		Action:     action,
		Label:      label,
		PolicyID:   policy.ID,
		Policy:     policy.Title,
		VersionID:  exception.VersionID,
		RecordURN:  exception.URN,
		RecordType: "policy.exception",
		Status:     exception.Status,
		Owner:      firstNonEmpty(exception.Owner, firstNonEmpty(exception.Approvers...), policy.Owner),
		DueAt:      exception.ExpiresAt,
		Reason:     reason,
	}
}

func grcPolicyVersionDiffsForPolicy(policy grcPolicyLifecyclePolicy) []grcPolicyVersionDiffItem {
	diffs := []grcPolicyVersionDiffItem{}
	for idx, version := range policy.Versions {
		if version.ChangeSummary == "" && version.DiffSummary == "" && version.DiffURL == "" {
			continue
		}
		item := grcPolicyVersionDiffItem{
			PolicyID:      policy.ID,
			PolicyTitle:   policy.Title,
			ToVersionID:   version.ID,
			ToVersion:     firstNonEmpty(version.Version, version.ID),
			Status:        version.Status,
			ChangeSummary: version.ChangeSummary,
			DiffSummary:   version.DiffSummary,
			DiffURL:       version.DiffURL,
			CreatedAt:     version.CreatedAt,
			ApprovedAt:    version.ApprovedAt,
		}
		if idx+1 < len(policy.Versions) {
			item.FromVersionID = policy.Versions[idx+1].ID
			item.FromVersion = firstNonEmpty(policy.Versions[idx+1].Version, policy.Versions[idx+1].ID)
		}
		diffs = append(diffs, item)
	}
	return diffs
}

func grcPolicyReminderPlanForPolicy(policy grcPolicyLifecyclePolicy, now time.Time) []grcPolicyReminderPlanItem {
	items := []grcPolicyReminderPlanItem{}
	for _, review := range policy.Reviews {
		if !grcPolicyPendingStatus(review.Status) && !grcPolicyOverdue(review.ReviewDueAt, review.Status, now) {
			continue
		}
		items = append(items, grcPolicyReminderPlanItem{
			ID:         review.URN + ":review",
			PolicyID:   policy.ID,
			Policy:     policy.Title,
			RecordURN:  review.URN,
			RecordType: "policy.review",
			Action:     "Review reminder",
			Owner:      firstNonEmpty(review.Owner, policy.Owner),
			Recipients: review.Reviewers,
			DueAt:      review.ReviewDueAt,
			EscalateAt: grcPolicyReminderEscalateAt(review.ReviewDueAt),
			Channel:    "email",
			Reason:     "Owner review",
		})
	}
	for _, attestation := range policy.Attestations {
		if !grcPolicyAcceptanceOpenStatus(attestation.Status) {
			continue
		}
		action := "Attestation reminder"
		reason := "Open attestation"
		if grcPolicyOverdue(attestation.DueAt, attestation.Status, now) {
			action = "Attestation escalation"
			reason = "Overdue attestation"
		}
		items = append(items, grcPolicyReminderPlanItem{
			ID:         attestation.URN + ":attestation",
			PolicyID:   policy.ID,
			Policy:     policy.Title,
			RecordURN:  attestation.URN,
			RecordType: "policy.acceptance",
			Action:     action,
			Owner:      firstNonEmpty(attestation.Person, firstNonEmpty(attestation.Assignees...)),
			Recipients: attestation.Assignees,
			DueAt:      attestation.DueAt,
			EscalateAt: grcPolicyReminderEscalateAt(attestation.DueAt),
			Channel:    "email",
			Reason:     reason,
		})
	}
	for _, exception := range policy.Exceptions {
		if !grcPolicyExceptionOpen(exception.Status) || !grcPolicyExpiring(exception.ExpiresAt, now) {
			continue
		}
		items = append(items, grcPolicyReminderPlanItem{
			ID:         exception.URN + ":exception",
			PolicyID:   policy.ID,
			Policy:     policy.Title,
			RecordURN:  exception.URN,
			RecordType: "policy.exception",
			Action:     "Exception renewal",
			Owner:      firstNonEmpty(exception.Owner, policy.Owner),
			Recipients: exception.Approvers,
			DueAt:      exception.ExpiresAt,
			EscalateAt: grcPolicyReminderEscalateAt(exception.ExpiresAt),
			Channel:    "email",
			Reason:     "Expiring exception",
		})
	}
	sort.Slice(items, func(i, j int) bool {
		left := grcPolicySortDate(items[i].DueAt)
		right := grcPolicySortDate(items[j].DueAt)
		if left.Equal(right) {
			return items[i].ID < items[j].ID
		}
		return left.Before(right)
	})
	return items
}

func grcPolicyReminderEscalateAt(rawDueAt string) string {
	dueAt, ok := grcPolicyTime(rawDueAt)
	if !ok {
		return ""
	}
	return dueAt.Add(72 * time.Hour).Format("2006-01-02")
}

func grcPolicyAcceptanceRollup(items []grcPolicyAcceptanceItem, now time.Time) grcPolicyAcceptanceSummary {
	var summary grcPolicyAcceptanceSummary
	for _, item := range items {
		if grcPolicyClosedStatus(item.Status) {
			continue
		}
		status := strings.TrimSpace(item.Status)
		if grcPolicyAcceptedStatus(item.Status) || (status == "" && item.AcceptedAt != "") {
			summary.Total++
			summary.Accepted++
			continue
		}
		if !grcPolicyAcceptanceOpenStatus(item.Status) {
			continue
		}
		summary.Total++
		if grcPolicyOverdue(item.DueAt, item.Status, now) {
			summary.Overdue++
		} else {
			summary.Pending++
		}
	}
	return summary
}

func grcPolicyExceptionRollup(items []grcPolicyExceptionItem, now time.Time) grcPolicyExceptionSummary {
	var summary grcPolicyExceptionSummary
	for _, item := range items {
		if strings.TrimSpace(item.Status) == "" {
			continue
		}
		if grcPolicyClosedStatus(item.Status) {
			if grcPolicyPast(item.ExpiresAt, now) {
				summary.Expired++
			}
			continue
		}
		if grcPolicyPast(item.ExpiresAt, now) {
			summary.Expired++
			continue
		}
		summary.Active++
		if grcPolicyExpiring(item.ExpiresAt, now) {
			summary.Expiring++
		}
	}
	return summary
}

func grcPolicyMappingForNode(node *grcPolicyGraphNode, policyID string, policyTitle string, relations []grcPolicyGraphRelation) []grcPolicyLifecycleMapping {
	controls := grcPolicyControlsFor(node.URN, relations)
	evidence := grcPolicyEvidenceFor(node.URN, relations)
	targets := grcPolicyTargetsFor(node.URN, relations)
	if len(targets) == 0 && (len(controls) > 0 || len(evidence) > 0) {
		targets = []grcPolicyTargetRef{{URN: node.URN, EntityType: node.EntityType, Label: grcPolicyNodeTitle(node)}}
	}
	mappings := make([]grcPolicyLifecycleMapping, 0, len(targets))
	for _, target := range targets {
		mappings = append(mappings, grcPolicyLifecycleMapping{
			PolicyID:    firstNonEmpty(policyID, grcPolicyAttr(node, "policy_id")),
			PolicyTitle: policyTitle,
			SourceURN:   node.URN,
			SourceType:  node.EntityType,
			Target:      target,
			Controls:    controls,
			Evidence:    evidence,
		})
	}
	return mappings
}

func grcPolicyDocumentMappings(document grcPolicyDocumentItem) []grcPolicyLifecycleMapping {
	if len(document.Controls) == 0 && len(document.Evidence) == 0 && len(document.Risks) == 0 {
		return nil
	}
	targets := []grcPolicyTargetRef{{URN: document.URN, EntityType: "document", Label: document.Title}}
	for _, risk := range document.Risks {
		targets = append(targets, grcPolicyTargetRef{URN: risk.URN, EntityType: "claim", Label: risk.Title})
	}
	policyID := ""
	policyTitle := ""
	if len(document.Policies) > 0 {
		policyID = document.Policies[0].ID
		policyTitle = document.Policies[0].Title
	}
	mappings := make([]grcPolicyLifecycleMapping, 0, len(targets))
	for _, target := range uniqueTargets(targets) {
		mappings = append(mappings, grcPolicyLifecycleMapping{
			PolicyID:    policyID,
			PolicyTitle: policyTitle,
			SourceURN:   document.URN,
			SourceType:  "document",
			Target:      target,
			Controls:    document.Controls,
			Evidence:    document.Evidence,
		})
	}
	return mappings
}

func grcPolicyPolicyIDFromRelations(urn string, relations []grcPolicyGraphRelation, policyURNToID map[string]string) string {
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn {
			continue
		}
		if relation.Relation != fabriccontract.RelationAssociatedWith && relation.Relation != fabriccontract.RelationBelongsTo {
			continue
		}
		if policyID := policyURNToID[relation.To.URN]; policyID != "" {
			return policyID
		}
		if relation.To.EntityType == "policy.version" {
			return grcPolicyAttr(relation.To, "policy_id")
		}
	}
	return ""
}

func grcPolicyControlsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyControlRef {
	controls := []grcPolicyControlRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn {
			continue
		}
		if relation.Relation != fabriccontract.RelationSupports && relation.Relation != fabriccontract.RelationAssociatedWith {
			continue
		}
		if !grcPolicyIsControlNode(relation.To) {
			continue
		}
		controls = append(controls, grcPolicyControlRef{
			URN:       relation.To.URN,
			ControlID: grcPolicyAttr(relation.To, "control_external_id", "control_id", "policy_id"),
			Framework: grcPolicyAttr(relation.To, "framework", "framework_name"),
			Title:     grcPolicyNodeTitle(relation.To),
		})
	}
	return uniqueControls(controls)
}

func grcPolicyEvidenceFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyEvidenceRef {
	evidence := []grcPolicyEvidenceRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn || relation.Relation != fabriccontract.RelationHasEvidence {
			continue
		}
		evidence = append(evidence, grcPolicyEvidenceRef{
			URN:          relation.To.URN,
			EntityType:   relation.To.EntityType,
			Title:        grcPolicyNodeTitle(relation.To),
			DocumentID:   grcPolicyAttr(relation.To, "document_id"),
			EvidenceType: grcPolicyAttr(relation.To, "evidence_type", "document_type"),
		})
	}
	return uniqueEvidence(evidence)
}

func grcPolicyAssignmentsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyAssignmentItem {
	items := []grcPolicyAssignmentItem{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn || relation.Relation != fabriccontract.RelationAssignedTo {
			continue
		}
		items = append(items, grcPolicyAssignmentItem{
			TargetURN:  relation.To.URN,
			TargetType: relation.To.EntityType,
			Label:      grcPolicyNodeTitle(relation.To),
			Scope:      grcPolicyAttrMap(relation.Attrs, "scope", "assignment_scope"),
		})
	}
	return uniqueAssignments(items)
}

func grcPolicyAssignmentLabelsFor(urn string, relations []grcPolicyGraphRelation) []string {
	assignments := grcPolicyAssignmentsFor(urn, relations)
	labels := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		labels = append(labels, assignment.Label)
	}
	return uniqueStrings(labels)
}

func grcPolicyTargetsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyTargetRef {
	targets := []grcPolicyTargetRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn || relation.Relation != fabriccontract.RelationTargeted {
			continue
		}
		targets = append(targets, grcPolicyTargetRef{URN: relation.To.URN, EntityType: relation.To.EntityType, Label: grcPolicyNodeTitle(relation.To)})
	}
	return uniqueTargets(targets)
}

func grcPolicyDocumentPoliciesFor(urn string, relations []grcPolicyGraphRelation, policyURNToID map[string]string) []grcPolicyDocumentRef {
	refs := []grcPolicyDocumentRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil {
			continue
		}
		switch {
		case relation.From.URN == urn && (relation.Relation == fabriccontract.RelationAssociatedWith || relation.Relation == fabriccontract.RelationBelongsTo):
			if ref, ok := grcPolicyDocumentRefForNode(relation.To, policyURNToID); ok {
				refs = append(refs, ref)
			}
		case relation.To.URN == urn && relation.Relation == fabriccontract.RelationHasEvidence:
			if ref, ok := grcPolicyDocumentRefForNode(relation.From, policyURNToID); ok {
				refs = append(refs, ref)
			}
		}
	}
	return uniqueDocumentRefs(refs)
}

func grcPolicyRiskPoliciesFor(urn string, relations []grcPolicyGraphRelation, policyURNToID map[string]string) []grcPolicyDocumentRef {
	refs := []grcPolicyDocumentRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil {
			continue
		}
		if relation.From.URN == urn && (relation.Relation == fabriccontract.RelationAssociatedWith || relation.Relation == fabriccontract.RelationBelongsTo) {
			if ref, ok := grcPolicyDocumentRefForNode(relation.To, policyURNToID); ok {
				refs = append(refs, ref)
			}
		}
	}
	return uniqueDocumentRefs(refs)
}

func grcPolicyDocumentRefForNode(node *grcPolicyGraphNode, policyURNToID map[string]string) (grcPolicyDocumentRef, bool) {
	if node == nil {
		return grcPolicyDocumentRef{}, false
	}
	if grcPolicyIsPolicyNode(node) {
		return grcPolicyDocumentRef{ID: firstNonEmpty(policyURNToID[node.URN], grcPolicyPolicyID(node)), URN: node.URN, Title: grcPolicyNodeTitle(node), Reference: "policy"}, true
	}
	if node.EntityType == "policy.version" {
		return grcPolicyDocumentRef{ID: grcPolicyAttr(node, "policy_id"), URN: node.URN, Title: grcPolicyNodeTitle(node), Reference: "policy_version"}, true
	}
	if node.EntityType == "policy.template" {
		return grcPolicyDocumentRef{ID: grcPolicyAttr(node, "policy_id"), URN: node.URN, Title: grcPolicyNodeTitle(node), Reference: "policy_template"}, true
	}
	if node.EntityType == "policy.exception" {
		return grcPolicyDocumentRef{ID: grcPolicyAttr(node, "policy_id"), URN: node.URN, Title: grcPolicyNodeTitle(node), Reference: "policy_exception"}, true
	}
	return grcPolicyDocumentRef{}, false
}

func grcPolicyDocumentRisksFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyRiskRef {
	refs := []grcPolicyRiskRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil {
			continue
		}
		if relation.From.URN == urn && (relation.Relation == fabriccontract.RelationAssociatedWith || relation.Relation == fabriccontract.RelationHasEvidence) && grcPolicyIsRiskScenarioNode(relation.To) {
			refs = append(refs, grcPolicyRiskRefFromNode(relation.To))
		}
		if relation.To.URN == urn && (relation.Relation == fabriccontract.RelationAssociatedWith || relation.Relation == fabriccontract.RelationHasEvidence) && grcPolicyIsRiskScenarioNode(relation.From) {
			refs = append(refs, grcPolicyRiskRefFromNode(relation.From))
		}
	}
	return uniqueRiskRefs(refs)
}

func grcPolicyRiskDocumentsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyDocumentRef {
	refs := []grcPolicyDocumentRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil {
			continue
		}
		if relation.From.URN == urn && relation.To.EntityType == "document" && (relation.Relation == fabriccontract.RelationHasEvidence || relation.Relation == fabriccontract.RelationAssociatedWith) {
			refs = append(refs, grcPolicyDocumentRef{ID: grcPolicyNodeID(relation.To, "document_id", "policy_document_id"), URN: relation.To.URN, Title: grcPolicyNodeTitle(relation.To), Reference: firstNonEmpty(grcPolicyDocumentClass(relation.To), "document")})
		}
		if relation.To.URN == urn && relation.From.EntityType == "document" && (relation.Relation == fabriccontract.RelationHasEvidence || relation.Relation == fabriccontract.RelationAssociatedWith) {
			refs = append(refs, grcPolicyDocumentRef{ID: grcPolicyNodeID(relation.From, "document_id", "policy_document_id"), URN: relation.From.URN, Title: grcPolicyNodeTitle(relation.From), Reference: firstNonEmpty(grcPolicyDocumentClass(relation.From), "document")})
		}
	}
	return uniqueDocumentRefs(refs)
}

func grcPolicyRiskRefFromNode(node *grcPolicyGraphNode) grcPolicyRiskRef {
	return grcPolicyRiskRef{
		ID:     grcPolicyNodeID(node, "risk_id", "risk_register_id"),
		URN:    node.URN,
		Title:  grcPolicyRiskTitle(node),
		Status: grcPolicyAttr(node, "status", "risk_status", "review_status"),
	}
}

func grcPolicyActionActors(urn string, relations []grcPolicyGraphRelation, action string) []string {
	actors := []string{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.To.URN != urn || relation.Relation != fabriccontract.RelationActedOn {
			continue
		}
		if action != "" && !strings.EqualFold(grcPolicyAttrMap(relation.Attrs, "action"), action) {
			continue
		}
		actors = append(actors, grcPolicyNodeTitle(relation.From))
	}
	return uniqueStrings(actors)
}

func grcPolicyRelatedLabel(urn string, relations []grcPolicyGraphRelation, relationName string, outgoing bool) string {
	for _, relation := range relations {
		if relation.Relation != relationName || relation.From == nil || relation.To == nil {
			continue
		}
		if outgoing && relation.From.URN == urn {
			return grcPolicyNodeTitle(relation.To)
		}
		if !outgoing && relation.To.URN == urn {
			return grcPolicyNodeTitle(relation.From)
		}
	}
	return ""
}

func grcPolicyIsPolicyNode(node *grcPolicyGraphNode) bool {
	if node == nil || node.EntityType != "policy" {
		return false
	}
	return strings.EqualFold(grcPolicyAttr(node, "policy_type"), "policy")
}

func grcPolicyIsControlNode(node *grcPolicyGraphNode) bool {
	if node == nil || node.EntityType != "policy" {
		return false
	}
	return strings.EqualFold(grcPolicyAttr(node, "policy_type"), "control")
}

func grcPolicyIsRiskScenarioNode(node *grcPolicyGraphNode) bool {
	if node == nil || node.EntityType != "claim" {
		return false
	}
	return strings.EqualFold(grcPolicyAttr(node, "claim_type"), "risk_scenario")
}

func grcPolicyDocumentClass(node *grcPolicyGraphNode) string {
	raw := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		grcPolicyAttr(node, "document_class", "document_type", "file_type", "category", "policy_document_type"),
		node.Label,
	)))
	normalized := strings.NewReplacer("-", "_", " ", "_", "/", "_").Replace(raw)
	for strings.Contains(normalized, "__") {
		normalized = strings.ReplaceAll(normalized, "__", "_")
	}
	switch {
	case strings.Contains(normalized, "risk_register"):
		return "risk_register"
	case strings.Contains(normalized, "procedure"):
		return "procedure"
	case strings.Contains(normalized, "standard"):
		return "standard"
	case strings.Contains(normalized, "control_narrative"):
		return "control_narrative"
	case strings.Contains(normalized, "exception_register") || strings.Contains(normalized, "waiver_register"):
		return "exception_register"
	case strings.Contains(normalized, "training"):
		return "training_material"
	case strings.Contains(normalized, "policy"):
		return "policy"
	default:
		return firstNonEmpty(grcPolicyAttr(node, "document_class"), "document")
	}
}

func grcPolicyDocumentInScope(item grcPolicyDocumentItem) bool {
	if item.URN == "" {
		return false
	}
	if item.DocumentClass == "risk_register" || item.DocumentClass == "policy" || item.DocumentClass == "standard" || item.DocumentClass == "procedure" || item.DocumentClass == "control_narrative" || item.DocumentClass == "exception_register" || item.DocumentClass == "training_material" {
		return true
	}
	return len(item.Policies) > 0 || len(item.Risks) > 0 || len(item.Controls) > 0
}

func grcPolicyRiskTitle(node *grcPolicyGraphNode) string {
	return firstNonEmpty(grcPolicyAttr(node, "title", "description", "risk_statement", "name"), node.Label, grcPolicyNodeID(node, "risk_id"))
}

func grcPolicyDocumentDueForReview(document grcPolicyDocumentItem, now time.Time) bool {
	if grcPolicyDraftStatus(document.Status) {
		return false
	}
	return grcPolicyOverdue(document.NextReviewDueAt, document.Status, now)
}

func grcPolicyRiskOpen(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "" {
		return false
	}
	switch normalized {
	case "resolved", "mitigated", "remediated", "transferred", "treated":
		return false
	default:
		return !grcPolicyAcceptedStatus(normalized) && !grcPolicyClosedStatus(normalized)
	}
}

func grcPolicyHighRisk(values ...string) bool {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "critical", "high", "very_high", "very high", "severe":
			return true
		}
	}
	return false
}

func grcPolicyNodeID(node *grcPolicyGraphNode, keys ...string) string {
	if node == nil {
		return ""
	}
	if value := grcPolicyAttr(node, keys...); value != "" {
		return value
	}
	if node.URN == "" {
		return ""
	}
	parts := strings.Split(node.URN, ":")
	return strings.TrimSpace(parts[len(parts)-1])
}

func grcPolicyPolicyID(node *grcPolicyGraphNode) string {
	if value := grcPolicyAttr(node, "policy_id"); value != "" {
		return value
	}
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.URN)
}

func grcPolicyNodeTitle(node *grcPolicyGraphNode) string {
	if node == nil {
		return ""
	}
	return firstNonEmpty(grcPolicyAttr(node, "title", "name", "policy_name", "display_name"), node.Label, grcPolicyNodeID(node, "id"))
}

func grcPolicyAttr(node *grcPolicyGraphNode, keys ...string) string {
	if node == nil {
		return ""
	}
	return grcPolicyAttrMap(node.Attrs, keys...)
}

func grcPolicyAttrMap(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func grcPolicyListAttr(node *grcPolicyGraphNode, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		values = append(values, strings.FieldsFunc(grcPolicyAttr(node, key), func(r rune) bool {
			return r == ',' || r == ';' || r == '\n'
		})...)
	}
	return uniqueStrings(values)
}

func grcPolicyCitationList(node *grcPolicyGraphNode) []string {
	citation := grcPolicyAttr(node, "policy_citations", "snippet_text", "citation_text")
	if citation == "" {
		return nil
	}
	return []string{citation}
}

func grcPolicyPublicAttrs(attrs map[string]string) map[string]string {
	allowed := map[string]string{}
	for _, key := range []string{"action", "assigned_user_ids", "category", "confidence", "control_ids", "document_class", "document_id", "document_type", "due_at", "event_kind", "evidence_cas_uri", "expires_at", "framework", "frameworks", "gap_id", "gap_ids", "gap_state", "impact", "inherent_risk", "inherent_risk_level", "likelihood", "lifecycle_action", "manual_review_state", "policy_citations", "policy_id", "policy_version_id", "question_ids", "reason", "record_id", "record_type", "record_urn", "residual_risk", "residual_risk_level", "review_cadence", "review_due_at", "review_state", "risk_category", "risk_id", "section_id", "section_title", "source_document_id", "source_event_id", "source_provenance", "source_system", "state_updated_at", "status", "target_policy_id", "treatment", "treatment_due_at", "unsupported_claims"} {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			allowed[key] = value
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func grcPolicyAttrs(raw string) map[string]string {
	attrs := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return attrs
	}
	values := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return attrs
	}
	for key, value := range values {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				attrs[key] = trimmed
			}
		case []any:
			parts := []string{}
			for _, item := range typed {
				if trimmed := strings.TrimSpace(fmt.Sprint(item)); trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
			if len(parts) > 0 {
				attrs[key] = strings.Join(parts, ",")
			}
		case bool, float64:
			attrs[key] = fmt.Sprint(typed)
		}
	}
	return attrs
}

func grcPolicyRowString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	value := row.Values[key]
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func grcPolicyAcceptedStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "accepted" || normalized == "completed" || normalized == "acknowledged"
}

func grcPolicyClosedStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "closed" || normalized == "expired" || normalized == "rejected" || normalized == "retired"
}

func grcPolicyDraftStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "draft" || normalized == "changes_requested"
}

func grcPolicyPendingStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "pending" || normalized == "requested" || normalized == "in_review" || normalized == "due" || normalized == "overdue"
}

func grcPolicyAcceptanceOpenStatus(status string) bool {
	return strings.TrimSpace(status) != "" && !grcPolicyAcceptedStatus(status) && !grcPolicyClosedStatus(status)
}

func grcPolicyExceptionOpen(status string) bool {
	return strings.TrimSpace(status) != "" && !grcPolicyClosedStatus(status)
}

func grcPolicyOverdue(rawDueAt string, status string, now time.Time) bool {
	if strings.TrimSpace(status) == "" || grcPolicyAcceptedStatus(status) || grcPolicyClosedStatus(status) {
		return false
	}
	dueAt, ok := grcPolicyTime(rawDueAt)
	return ok && dueAt.Before(now)
}

func grcPolicyPast(raw string, now time.Time) bool {
	value, ok := grcPolicyTime(raw)
	return ok && value.Before(now)
}

func grcPolicyExpiring(raw string, now time.Time) bool {
	value, ok := grcPolicyTime(raw)
	return ok && value.After(now) && value.Sub(now) <= grcPolicyLifecycleExceptionWindow
}

func grcPolicySortDate(values ...string) time.Time {
	if value, ok := grcPolicyFirstDate(values...); ok {
		return value
	}
	return time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
}

func grcPolicyLaterDateString(current string, candidate string) string {
	candidateDate, candidateOK := grcPolicyFirstDate(candidate)
	if !candidateOK {
		return current
	}
	currentDate, currentOK := grcPolicyFirstDate(current)
	if !currentOK || candidateDate.After(currentDate) {
		return candidate
	}
	return current
}

func grcPolicyFirstDate(values ...string) (time.Time, bool) {
	for _, value := range values {
		if parsed, ok := grcPolicyTime(value); ok {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func grcPolicyTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func appendPolicyAssignments(left []grcPolicyAssignmentItem, right []grcPolicyAssignmentItem) []grcPolicyAssignmentItem {
	return uniqueAssignments(append(left, right...))
}

func appendPolicyControls(left []grcPolicyControlRef, right []grcPolicyControlRef) []grcPolicyControlRef {
	return uniqueControls(append(left, right...))
}

func appendPolicyEvidence(left []grcPolicyEvidenceRef, right []grcPolicyEvidenceRef) []grcPolicyEvidenceRef {
	return uniqueEvidence(append(left, right...))
}

func appendPolicyEvidenceSnippets(left []grcPolicyEvidenceSnippetItem, right []grcPolicyEvidenceSnippetItem) []grcPolicyEvidenceSnippetItem {
	return uniquePolicyEvidenceSnippets(append(left, right...))
}

func uniqueAssignments(items []grcPolicyAssignmentItem) []grcPolicyAssignmentItem {
	seen := map[string]struct{}{}
	out := []grcPolicyAssignmentItem{}
	for _, item := range items {
		key := item.TargetURN
		if key == "" {
			key = item.Label
		}
		if strings.TrimSpace(key) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueControls(items []grcPolicyControlRef) []grcPolicyControlRef {
	seen := map[string]struct{}{}
	out := []grcPolicyControlRef{}
	for _, item := range items {
		key := firstNonEmpty(item.ControlID, item.URN)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return firstNonEmpty(out[i].ControlID, out[i].Title) < firstNonEmpty(out[j].ControlID, out[j].Title)
	})
	return out
}

func uniqueEvidence(items []grcPolicyEvidenceRef) []grcPolicyEvidenceRef {
	seen := map[string]struct{}{}
	out := []grcPolicyEvidenceRef{}
	for _, item := range items {
		key := item.URN
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniquePolicyEvidenceSnippets(items []grcPolicyEvidenceSnippetItem) []grcPolicyEvidenceSnippetItem {
	seen := map[string]struct{}{}
	out := []grcPolicyEvidenceSnippetItem{}
	for _, item := range items {
		key := firstNonEmpty(item.URN, item.ID, item.DocumentID+"|"+item.SectionID+"|"+item.Text)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueTargets(items []grcPolicyTargetRef) []grcPolicyTargetRef {
	seen := map[string]struct{}{}
	out := []grcPolicyTargetRef{}
	for _, item := range items {
		key := item.URN
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueDocumentRefs(items []grcPolicyDocumentRef) []grcPolicyDocumentRef {
	seen := map[string]struct{}{}
	out := []grcPolicyDocumentRef{}
	for _, item := range items {
		key := firstNonEmpty(item.URN, item.ID, item.Title)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(firstNonEmpty(out[i].Title, out[i].ID, out[i].URN)) < strings.ToLower(firstNonEmpty(out[j].Title, out[j].ID, out[j].URN))
	})
	return out
}

func uniqueRiskRefs(items []grcPolicyRiskRef) []grcPolicyRiskRef {
	seen := map[string]struct{}{}
	out := []grcPolicyRiskRef{}
	for _, item := range items {
		key := firstNonEmpty(item.URN, item.ID, item.Title)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(firstNonEmpty(out[i].Title, out[i].ID, out[i].URN)) < strings.ToLower(firstNonEmpty(out[j].Title, out[j].ID, out[j].URN))
	})
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func firstNonEmptyWith(value string, fallback []string) string {
	values := append([]string{value}, fallback...)
	return firstNonEmpty(values...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func grcPolicyDeduplicateMappings(items []grcPolicyLifecycleMapping) []grcPolicyLifecycleMapping {
	seen := map[string]struct{}{}
	out := []grcPolicyLifecycleMapping{}
	for _, item := range items {
		key := item.SourceURN + "|" + item.Target.URN
		if key == "|" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SourceURN < out[j].SourceURN
	})
	return out
}
