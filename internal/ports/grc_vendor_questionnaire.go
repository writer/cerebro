package ports

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	GRCVendorQuestionnaireStatusIntake           = "intake"
	GRCVendorQuestionnaireStatusUploaded         = "uploaded"
	GRCVendorQuestionnaireStatusProcessing       = "processing"
	GRCVendorQuestionnaireStatusNeedsInput       = "needs_input"
	GRCVendorQuestionnaireStatusReadyForApproval = "ready_for_approval"
	GRCVendorQuestionnaireStatusApproved         = "approved"
	GRCVendorQuestionnaireStatusRejected         = "rejected"
	GRCVendorQuestionnaireStatusConditional      = "conditional_approval"

	GRCVendorQuestionnaireDecisionNeedsReview           = "needs_review"
	GRCVendorQuestionnaireDecisionApprove               = "approve"
	GRCVendorQuestionnaireDecisionApproveWithConditions = "approve_with_conditions"
	GRCVendorQuestionnaireDecisionReject                = "reject"

	GRCVendorQuestionnaireEventCreated   = "created"
	GRCVendorQuestionnaireEventProcessed = "processed"
	GRCVendorQuestionnaireEventAssigned  = "assigned"
	GRCVendorQuestionnaireEventCommented = "commented"
	GRCVendorQuestionnaireEventApproved  = "approval_recorded"
)

var ErrGRCVendorQuestionnaireReviewNotFound = errors.New("grc vendor questionnaire review not found")

type GRCVendorQuestionnaireReviewRecord struct {
	GRCVendorQuestionnaireReviewIdentity
	GRCVendorQuestionnaireReviewSource
	GRCVendorQuestionnaireReviewWorkflow
	GRCVendorQuestionnaireReviewContent
	GRCVendorQuestionnaireReviewMetadata
}

type GRCVendorQuestionnaireReviewIdentity struct {
	TenantID  string `json:"tenant_id"`
	ReviewID  string `json:"review_id"`
	VendorURN string `json:"vendor_urn"`
	VendorID  string `json:"vendor_id,omitempty"`
	Title     string `json:"title,omitempty"`
}

type GRCVendorQuestionnaireReviewSource struct {
	SourceID          string `json:"source_id,omitempty"`
	RuntimeID         string `json:"runtime_id,omitempty"`
	UploadID          string `json:"upload_id,omitempty"`
	QuestionnaireURN  string `json:"questionnaire_urn,omitempty"`
	QuestionnaireType string `json:"questionnaire_type,omitempty"`
}

type GRCVendorQuestionnaireReviewWorkflow struct {
	Status             string `json:"status"`
	Decision           string `json:"decision,omitempty"`
	DecisionReason     string `json:"decision_reason,omitempty"`
	Confidence         string `json:"confidence,omitempty"`
	ReviewerUserID     string `json:"reviewer_user_id,omitempty"`
	CurrentOwnerUserID string `json:"current_owner_user_id,omitempty"`
	AssignedTeam       string `json:"assigned_team,omitempty"`
}

type GRCVendorQuestionnaireReviewContent struct {
	Assignments       []GRCVendorQuestionnaireAssignment `json:"assignments,omitempty"`
	EvidenceMatches   []GRCVendorQuestionnaireEvidence   `json:"evidence_matches,omitempty"`
	MissingQuestions  []GRCVendorQuestionnaireMissing    `json:"missing_questions,omitempty"`
	AnswerSuggestions []GRCVendorQuestionnaireAnswer     `json:"answer_suggestions,omitempty"`
	Approvals         []GRCVendorQuestionnaireApproval   `json:"approvals,omitempty"`
	Comments          []GRCVendorQuestionnaireComment    `json:"comments,omitempty"`
	Timeline          []GRCVendorQuestionnaireTimeline   `json:"timeline,omitempty"`
}

type GRCVendorQuestionnaireReviewMetadata struct {
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type GRCVendorQuestionnaireAssignment struct {
	ID        string     `json:"id,omitempty"`
	Team      string     `json:"team"`
	OwnerID   string     `json:"owner_id,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Status    string     `json:"status,omitempty"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type GRCVendorQuestionnaireEvidence struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`
	Source     string            `json:"source,omitempty"`
	URN        string            `json:"urn,omitempty"`
	ControlID  string            `json:"control_id,omitempty"`
	Confidence string            `json:"confidence,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GRCVendorQuestionnaireMissing struct {
	ID             string `json:"id"`
	Question       string `json:"question"`
	Reason         string `json:"reason,omitempty"`
	AssignedTeam   string `json:"assigned_team,omitempty"`
	RequiredBefore string `json:"required_before,omitempty"`
}

type GRCVendorQuestionnaireAnswer struct {
	ID         string            `json:"id"`
	Question   string            `json:"question"`
	Answer     string            `json:"answer"`
	State      string            `json:"state"`
	Confidence string            `json:"confidence,omitempty"`
	SourceIDs  []string          `json:"source_ids,omitempty"`
	Needs      []string          `json:"needs,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GRCVendorQuestionnaireApproval struct {
	ID        string     `json:"id,omitempty"`
	Team      string     `json:"team"`
	ActorID   string     `json:"actor_id,omitempty"`
	Decision  string     `json:"decision"`
	Reason    string     `json:"reason,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type GRCVendorQuestionnaireComment struct {
	ID        string     `json:"id,omitempty"`
	ActorID   string     `json:"actor_id,omitempty"`
	Body      string     `json:"body"`
	Scope     string     `json:"scope,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type GRCVendorQuestionnaireTimeline struct {
	ID         string            `json:"id,omitempty"`
	EventType  string            `json:"event_type"`
	ActorID    string            `json:"actor_id,omitempty"`
	Summary    string            `json:"summary"`
	CreatedAt  *time.Time        `json:"created_at,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GRCVendorQuestionnaireReviewEventRecord struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	ReviewID  string            `json:"review_id"`
	EventType string            `json:"event_type"`
	ActorID   string            `json:"actor_id,omitempty"`
	Summary   string            `json:"summary,omitempty"`
	Payload   map[string]string `json:"payload,omitempty"`
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
}

type GRCVendorQuestionnaireReviewFilter struct {
	TenantID  string
	ReviewID  string
	VendorURN string
	VendorID  string
	SourceID  string
	Status    string
	Limit     uint32
}

type GRCVendorQuestionnaireReviewEventFilter struct {
	TenantID string
	ReviewID string
	Limit    uint32
}

type GRCVendorQuestionnaireReviewStore interface {
	StateStore
	UpsertGRCVendorQuestionnaireReview(context.Context, GRCVendorQuestionnaireReviewRecord, GRCVendorQuestionnaireReviewEventRecord) (*GRCVendorQuestionnaireReviewRecord, error)
	GetGRCVendorQuestionnaireReview(context.Context, GRCVendorQuestionnaireReviewFilter) (*GRCVendorQuestionnaireReviewRecord, error)
	ListGRCVendorQuestionnaireReviews(context.Context, GRCVendorQuestionnaireReviewFilter) ([]*GRCVendorQuestionnaireReviewRecord, error)
	ListGRCVendorQuestionnaireReviewEvents(context.Context, GRCVendorQuestionnaireReviewEventFilter) ([]*GRCVendorQuestionnaireReviewEventRecord, error)
}

func IsGRCVendorQuestionnaireStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case GRCVendorQuestionnaireStatusIntake,
		GRCVendorQuestionnaireStatusUploaded,
		GRCVendorQuestionnaireStatusProcessing,
		GRCVendorQuestionnaireStatusNeedsInput,
		GRCVendorQuestionnaireStatusReadyForApproval,
		GRCVendorQuestionnaireStatusApproved,
		GRCVendorQuestionnaireStatusRejected,
		GRCVendorQuestionnaireStatusConditional:
		return true
	default:
		return false
	}
}

func IsGRCVendorQuestionnaireDecision(value string) bool {
	switch strings.TrimSpace(value) {
	case "",
		GRCVendorQuestionnaireDecisionNeedsReview,
		GRCVendorQuestionnaireDecisionApprove,
		GRCVendorQuestionnaireDecisionApproveWithConditions,
		GRCVendorQuestionnaireDecisionReject:
		return true
	default:
		return false
	}
}
