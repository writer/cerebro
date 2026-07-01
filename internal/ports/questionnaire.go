package ports

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	QuestionnaireDirectionCustomerSecurityReview = "customer_security_review"
	QuestionnaireDirectionVendorReview           = "vendor_review"

	QuestionnaireStatusIntake           = "intake"
	QuestionnaireStatusProcessing       = "processing"
	QuestionnaireStatusNeedsInput       = "needs_input"
	QuestionnaireStatusReadyForApproval = "ready_for_approval"
	QuestionnaireStatusApproved         = "approved"
	QuestionnaireStatusRejected         = "rejected"

	QuestionnaireAnswerSupported     = "supported"
	QuestionnaireAnswerNeedsReview   = "needs_review"
	QuestionnaireAnswerPartial       = "partial"
	QuestionnaireAnswerBlocked       = "blocked"
	QuestionnaireAnswerNotApplicable = "not_applicable"

	QuestionnaireReviewReady       = "ready"
	QuestionnaireReviewNeedsReview = "needs_review"
	QuestionnaireReviewBlocked     = "blocked"
	QuestionnaireReviewApproved    = "approved"
	QuestionnaireReviewRejected    = "rejected"

	QuestionnaireDecisionApproved               = "approved"
	QuestionnaireDecisionApprovedWithConditions = "approved_with_conditions"
	QuestionnaireDecisionRejected               = "rejected"
	QuestionnaireDecisionNeedsInput             = "needs_input"

	QuestionnaireEventCreated      = "created"
	QuestionnaireEventProcessed    = "processed"
	QuestionnaireEventAssigned     = "assigned"
	QuestionnaireEventUpdated      = "updated"
	QuestionnaireEventDecided      = "decision_recorded"
	QuestionnaireEventCommented    = "commented"
	QuestionnaireEventVendorLinked = "vendor_linked"
)

var ErrQuestionnaireRunNotFound = errors.New("questionnaire run not found")

type QuestionnaireRunRecord struct {
	QuestionnaireRunIdentity
	QuestionnaireRunSource
	QuestionnaireRunWorkflow
	QuestionnaireRunContent
	QuestionnaireRunMetadata
}

type QuestionnaireRunIdentity struct {
	TenantID string `json:"tenant_id"`
	RunID    string `json:"run_id"`
	Title    string `json:"title,omitempty"`
}

type QuestionnaireRunSource struct {
	Direction      string `json:"direction"`
	Requester      string `json:"requester,omitempty"`
	CustomerName   string `json:"customer_name,omitempty"`
	VendorURN      string `json:"vendor_urn,omitempty"`
	VendorID       string `json:"vendor_id,omitempty"`
	SourceID       string `json:"source_id,omitempty"`
	RuntimeID      string `json:"runtime_id,omitempty"`
	UploadID       string `json:"upload_id,omitempty"`
	SourceFilename string `json:"source_filename,omitempty"`
	SourceFormat   string `json:"source_format,omitempty"`
}

type QuestionnaireRunWorkflow struct {
	Status             string `json:"status"`
	OwnerID            string `json:"owner_id,omitempty"`
	AssignedTeam       string `json:"assigned_team,omitempty"`
	Decision           string `json:"decision,omitempty"`
	DecisionReason     string `json:"decision_reason,omitempty"`
	ReadyAnswerCount   int    `json:"ready_answer_count,omitempty"`
	BlockedAnswerCount int    `json:"blocked_answer_count,omitempty"`
	ReviewAnswerCount  int    `json:"review_answer_count,omitempty"`
	MissingEvidence    int    `json:"missing_evidence_count,omitempty"`
	StaleEvidence      int    `json:"stale_evidence_count,omitempty"`
	UnassignedCount    int    `json:"unassigned_count,omitempty"`
}

type QuestionnaireRunContent struct {
	Questions   []QuestionnaireQuestion   `json:"questions,omitempty"`
	Answers     []QuestionnaireRunAnswer  `json:"answers,omitempty"`
	Assignments []QuestionnaireAssignment `json:"assignments,omitempty"`
	Decisions   []QuestionnaireDecision   `json:"decisions,omitempty"`
	Comments    []QuestionnaireComment    `json:"comments,omitempty"`
	Timeline    []QuestionnaireTimeline   `json:"timeline,omitempty"`
}

type QuestionnaireRunMetadata struct {
	Attributes map[string]string `json:"attributes,omitempty"`
	DueAt      *time.Time        `json:"due_at,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type QuestionnaireQuestion struct {
	ID                   string   `json:"id"`
	Question             string   `json:"question"`
	NormalizedQuestion   string   `json:"normalized_question,omitempty"`
	Section              string   `json:"section,omitempty"`
	RequiredAnswerFormat string   `json:"required_answer_format,omitempty"`
	MappedControls       []string `json:"mapped_controls,omitempty"`
	RequiredSlots        []string `json:"required_evidence_slots,omitempty"`
	OwnerID              string   `json:"owner_id,omitempty"`
	AnswerState          string   `json:"answer_state"`
	ReviewState          string   `json:"review_state"`
}

type QuestionnaireRunAnswer struct {
	ID               string                      `json:"id"`
	QuestionID       string                      `json:"question_id"`
	Question         string                      `json:"question,omitempty"`
	DraftAnswer      string                      `json:"draft_answer,omitempty"`
	AnswerState      string                      `json:"answer_state"`
	ReviewState      string                      `json:"review_state"`
	Confidence       string                      `json:"confidence,omitempty"`
	ConfidenceScore  int                         `json:"confidence_score,omitempty"`
	Controls         []string                    `json:"controls,omitempty"`
	EvidenceSlots    []QuestionnaireEvidenceSlot `json:"evidence_slots,omitempty"`
	Citations        []QuestionnaireCitation     `json:"citations,omitempty"`
	MissingEvidence  []QuestionnaireEvidenceGap  `json:"missing_evidence,omitempty"`
	Conflicts        []QuestionnaireEvidenceGap  `json:"conflicts,omitempty"`
	Freshness        QuestionnaireFreshness      `json:"freshness"`
	SourceAnswerID   string                      `json:"source_answer_id,omitempty"`
	ReviewerDecision string                      `json:"reviewer_decision,omitempty"`
	ReviewerReason   string                      `json:"reviewer_reason,omitempty"`
	Attributes       map[string]string           `json:"attributes,omitempty"`
}

type QuestionnaireEvidenceSlot struct {
	ID             string   `json:"id"`
	Label          string   `json:"label,omitempty"`
	State          string   `json:"state"`
	Required       bool     `json:"required"`
	CitationIDs    []string `json:"citation_ids,omitempty"`
	MissingReasons []string `json:"missing_reasons,omitempty"`
}

type QuestionnaireCitation struct {
	ID               string `json:"id"`
	Label            string `json:"label,omitempty"`
	Source           string `json:"source,omitempty"`
	ResourceURN      string `json:"resource_urn,omitempty"`
	EvidencePacketID string `json:"evidence_packet_id,omitempty"`
	EvidenceID       string `json:"evidence_id,omitempty"`
	EvidenceType     string `json:"evidence_type,omitempty"`
	ControlID        string `json:"control_id,omitempty"`
	FreshnessStatus  string `json:"freshness_status,omitempty"`
	ObservedAt       string `json:"observed_at,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
}

type QuestionnaireEvidenceGap struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Reason      string `json:"reason,omitempty"`
	SlotID      string `json:"slot_id,omitempty"`
	ControlID   string `json:"control_id,omitempty"`
	PacketID    string `json:"evidence_packet_id,omitempty"`
	ReviewState string `json:"review_state,omitempty"`
}

type QuestionnaireFreshness struct {
	Status     string `json:"status"`
	ObservedAt string `json:"observed_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type QuestionnaireAssignment struct {
	ID         string     `json:"id"`
	QuestionID string     `json:"question_id,omitempty"`
	GapID      string     `json:"gap_id,omitempty"`
	SlotID     string     `json:"slot_id,omitempty"`
	Team       string     `json:"team,omitempty"`
	OwnerID    string     `json:"owner_id,omitempty"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	DueAt      *time.Time `json:"due_at,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

type QuestionnaireDecision struct {
	ID         string     `json:"id"`
	QuestionID string     `json:"question_id,omitempty"`
	ActorID    string     `json:"actor_id,omitempty"`
	Decision   string     `json:"decision"`
	Reason     string     `json:"reason,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

type QuestionnaireComment struct {
	ID         string     `json:"id"`
	QuestionID string     `json:"question_id,omitempty"`
	ActorID    string     `json:"actor_id,omitempty"`
	Body       string     `json:"body"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
}

type QuestionnaireTimeline struct {
	ID         string            `json:"id"`
	EventType  string            `json:"event_type"`
	ActorID    string            `json:"actor_id,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  *time.Time        `json:"created_at,omitempty"`
}

type QuestionnaireRunEventRecord struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	RunID     string            `json:"run_id"`
	EventType string            `json:"event_type"`
	ActorID   string            `json:"actor_id,omitempty"`
	Summary   string            `json:"summary,omitempty"`
	Payload   map[string]string `json:"payload,omitempty"`
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
}

type QuestionnaireRunFilter struct {
	TenantID  string
	RunID     string
	Direction string
	Status    string
	VendorURN string
	Requester string
	Customer  string
	OwnerID   string
	Query     string
	Limit     uint32
}

type QuestionnaireRunEventFilter struct {
	TenantID string
	RunID    string
	Limit    uint32
}

type QuestionnaireRunSummary struct {
	TotalRuns           int
	VendorRuns          int
	DueRuns             int
	BlockedAnswers      int
	ReviewAnswers       int
	ReadyAnswers        int
	StaleEvidence       int
	MissingEvidence     int
	UnassignedQuestions int
}

type QuestionnaireRunStore interface {
	StateStore
	UpsertQuestionnaireRun(context.Context, QuestionnaireRunRecord, QuestionnaireRunEventRecord) (*QuestionnaireRunRecord, error)
	GetQuestionnaireRun(context.Context, QuestionnaireRunFilter) (*QuestionnaireRunRecord, error)
	ListQuestionnaireRuns(context.Context, QuestionnaireRunFilter) ([]*QuestionnaireRunRecord, error)
	SummarizeQuestionnaireRuns(context.Context, QuestionnaireRunFilter) (QuestionnaireRunSummary, error)
	ListQuestionnaireRunEvents(context.Context, QuestionnaireRunEventFilter) ([]*QuestionnaireRunEventRecord, error)
}

func IsQuestionnaireDirection(value string) bool {
	switch strings.TrimSpace(value) {
	case QuestionnaireDirectionCustomerSecurityReview, QuestionnaireDirectionVendorReview:
		return true
	default:
		return false
	}
}

func IsQuestionnaireStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case QuestionnaireStatusIntake,
		QuestionnaireStatusProcessing,
		QuestionnaireStatusNeedsInput,
		QuestionnaireStatusReadyForApproval,
		QuestionnaireStatusApproved,
		QuestionnaireStatusRejected:
		return true
	default:
		return false
	}
}

func IsQuestionnaireDecision(value string) bool {
	switch strings.TrimSpace(value) {
	case "",
		QuestionnaireDecisionApproved,
		QuestionnaireDecisionApprovedWithConditions,
		QuestionnaireDecisionRejected,
		QuestionnaireDecisionNeedsInput:
		return true
	default:
		return false
	}
}
