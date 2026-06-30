package grcvendorquestionnaire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
)

const maxGRCVendorQuestionnaireBodyBytes = 256 << 10
const defaultLimit uint32 = 100

type Scope struct {
	TenantID   string
	RuntimeID  string
	RuntimeIDs []string
	SourceID   string
	Limit      uint32
}

type ScopeResolver func(*http.Request) (Scope, error)
type VendorResolver func(*http.Request, Scope, string, string) (*grcvendor.VendorDetail, error)
type SignalsResolver func(*http.Request, Scope, string) ([]grcvendor.QuestionnaireFindingSignal, []grcvendor.QuestionnaireEvidenceSignal)
type SummaryResolver func(*http.Request, Scope, *ports.GRCVendorQuestionnaireReviewRecord, *grcvendor.VendorDetail, []grcvendor.QuestionnaireFindingSignal, []grcvendor.QuestionnaireEvidenceSignal) string
type TenantAuthorizer func(context.Context, string) error
type ActorResolver func(context.Context) string
type CacheBumper func(context.Context, string)
type ErrorWriter func(http.ResponseWriter, error)

type Options struct {
	Scope     ScopeResolver
	Vendor    VendorResolver
	Signals   SignalsResolver
	Summary   SummaryResolver
	Authorize TenantAuthorizer
	Actor     ActorResolver
	BumpCache CacheBumper
	WriteErr  ErrorWriter
}

type Handler struct {
	store     ports.GRCVendorQuestionnaireReviewStore
	scope     ScopeResolver
	vendor    VendorResolver
	signals   SignalsResolver
	summary   SummaryResolver
	authorize TenantAuthorizer
	actor     ActorResolver
	bumpCache CacheBumper
	writeErr  ErrorWriter
}

func NewHandler(store ports.StateStore, options Options) *Handler {
	return &Handler{
		store:     grcVendorQuestionnaireReviewStore(store),
		scope:     options.Scope,
		vendor:    options.Vendor,
		signals:   options.Signals,
		summary:   options.Summary,
		authorize: options.Authorize,
		actor:     options.Actor,
		bumpCache: options.BumpCache,
		writeErr:  options.WriteErr,
	}
}

func (h *Handler) resolveScope(r *http.Request) (Scope, error) {
	if h.scope == nil {
		return Scope{}, grcvendor.ErrRuntimeUnavailable
	}
	scope, err := h.scope(r)
	if err != nil {
		return Scope{}, err
	}
	if scope.Limit == 0 {
		scope.Limit = defaultLimit
	}
	return scope, nil
}

func (h *Handler) authorizeURN(ctx context.Context, urn string) error {
	urn = strings.TrimSpace(urn)
	if urn == "" || h.authorize == nil {
		return nil
	}
	return h.authorize(ctx, urn)
}

func (h *Handler) actorID(ctx context.Context) string {
	if h.actor == nil {
		return "anonymous"
	}
	if actor := strings.TrimSpace(h.actor(ctx)); actor != "" {
		return actor
	}
	return "anonymous"
}

func (h *Handler) bumpReviewCache(ctx context.Context, tenantID string) {
	if h.bumpCache != nil {
		h.bumpCache(ctx, tenantID)
	}
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	if h.writeErr != nil {
		h.writeErr(w, err)
		return
	}
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

type grcVendorQuestionnaireReviewsResponse struct {
	Summary     grcVendorQuestionnaireReviewSummary `json:"summary"`
	Reviews     []grcVendorQuestionnaireReviewView  `json:"reviews"`
	GeneratedAt time.Time                           `json:"generated_at"`
}

type grcVendorQuestionnaireReviewResponse struct {
	Review      grcVendorQuestionnaireReviewView                 `json:"review"`
	Events      []*ports.GRCVendorQuestionnaireReviewEventRecord `json:"events,omitempty"`
	GeneratedAt time.Time                                        `json:"generated_at"`
}

type grcVendorQuestionnaireReviewSummary struct {
	TotalReviews      int `json:"total_reviews"`
	IntakeReviews     int `json:"intake_reviews"`
	ProcessingReviews int `json:"processing_reviews"`
	ReadyReviews      int `json:"ready_reviews"`
	BlockedReviews    int `json:"blocked_reviews"`
	ApprovedReviews   int `json:"approved_reviews"`
	MissingAnswers    int `json:"missing_answers"`
	OpenAssignments   int `json:"open_assignments"`
	PendingApprovals  int `json:"pending_approvals"`
}

type grcVendorQuestionnaireReviewView struct {
	GRCVendorQuestionnaireReviewIdentityView
	GRCVendorQuestionnaireReviewStateView
	GRCVendorQuestionnaireReviewMetricView
	GRCVendorQuestionnaireReviewContentView
}

type GRCVendorQuestionnaireReviewIdentityView struct {
	ID             string     `json:"id"`
	ReviewID       string     `json:"review_id"`
	TenantID       string     `json:"tenant_id,omitempty"`
	VendorURN      string     `json:"vendor_urn"`
	VendorID       string     `json:"vendor_id,omitempty"`
	Title          string     `json:"title"`
	SourceFilename string     `json:"source_filename,omitempty"`
	Owner          string     `json:"owner,omitempty"`
	DueAt          *time.Time `json:"due_at,omitempty"`
}

type GRCVendorQuestionnaireReviewStateView struct {
	ReviewState            string     `json:"review_state"`
	UploadState            string     `json:"upload_state,omitempty"`
	ProcessState           string     `json:"process_state,omitempty"`
	EnrichmentState        string     `json:"enrichment_state,omitempty"`
	DecisionState          string     `json:"decision_state,omitempty"`
	DecisionRecommendation string     `json:"decision_recommendation,omitempty"`
	Status                 string     `json:"status,omitempty"`
	Decision               string     `json:"decision,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              *time.Time `json:"updated_at,omitempty"`
	ProcessedAt            *time.Time `json:"processed_at,omitempty"`
}

type GRCVendorQuestionnaireReviewMetricView struct {
	QuestionCount      int      `json:"question_count"`
	AnsweredCount      int      `json:"answered_count"`
	MissingAnswerCount int      `json:"missing_answer_count"`
	EvidenceMatchCount int      `json:"evidence_match_count"`
	RiskNotes          []string `json:"risk_notes,omitempty"`
	MissingAnswers     []string `json:"missing_answers,omitempty"`
}

type GRCVendorQuestionnaireReviewContentView struct {
	EvidenceMatches []grcVendorQuestionnaireEvidenceMatchView `json:"evidence_matches,omitempty"`
	Assignments     []grcVendorQuestionnaireAssignmentView    `json:"assignments,omitempty"`
	Comments        []grcVendorQuestionnaireCommentView       `json:"comments,omitempty"`
	Approvals       []grcVendorQuestionnaireApprovalView      `json:"approvals,omitempty"`
	Timeline        []grcVendorQuestionnaireTimelineEventView `json:"timeline,omitempty"`
	Attributes      map[string]string                         `json:"attributes,omitempty"`
}

type grcVendorQuestionnaireEvidenceMatchView struct {
	ID              string     `json:"id"`
	QuestionID      string     `json:"question_id"`
	SourceLabel     string     `json:"source_label"`
	SourceType      string     `json:"source_type,omitempty"`
	EvidenceURN     string     `json:"evidence_urn,omitempty"`
	ControlID       string     `json:"control_id,omitempty"`
	MatchState      string     `json:"match_state"`
	ConfidenceScore int        `json:"confidence_score,omitempty"`
	AnswerText      string     `json:"answer_text,omitempty"`
	ObservedAt      *time.Time `json:"observed_at,omitempty"`
}

type grcVendorQuestionnaireAssignmentView struct {
	ID         string     `json:"id"`
	QuestionID string     `json:"question_id,omitempty"`
	Owner      string     `json:"owner"`
	Status     string     `json:"status"`
	DueAt      *time.Time `json:"due_at,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

type grcVendorQuestionnaireCommentView struct {
	ID        string     `json:"id"`
	Author    string     `json:"author"`
	Body      string     `json:"body"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type grcVendorQuestionnaireApprovalView struct {
	ID        string     `json:"id"`
	Approver  string     `json:"approver"`
	State     string     `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type grcVendorQuestionnaireTimelineEventView struct {
	ID        string     `json:"id"`
	EventType string     `json:"event_type"`
	Actor     string     `json:"actor,omitempty"`
	Label     string     `json:"label"`
	Detail    string     `json:"detail,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type grcVendorQuestionnaireCreateRequest struct {
	TenantID           string            `json:"tenant_id,omitempty"`
	VendorURN          string            `json:"vendor_urn,omitempty"`
	VendorID           string            `json:"vendor_id,omitempty"`
	SourceID           string            `json:"source_id,omitempty"`
	RuntimeID          string            `json:"runtime_id,omitempty"`
	UploadID           string            `json:"upload_id,omitempty"`
	QuestionnaireURN   string            `json:"questionnaire_urn,omitempty"`
	QuestionnaireType  string            `json:"questionnaire_type,omitempty"`
	Title              string            `json:"title,omitempty"`
	SourceFilename     string            `json:"source_filename,omitempty"`
	QuestionCount      int               `json:"question_count,omitempty"`
	Status             string            `json:"status,omitempty"`
	ReviewerUserID     string            `json:"reviewer_user_id,omitempty"`
	CurrentOwnerUserID string            `json:"current_owner_user_id,omitempty"`
	AssignedTeam       string            `json:"assigned_team,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

type grcVendorQuestionnaireAssignmentRequest struct {
	TenantID   string                                 `json:"tenant_id,omitempty"`
	Assignment ports.GRCVendorQuestionnaireAssignment `json:"assignment"`
	QuestionID string                                 `json:"question_id,omitempty"`
	Owner      string                                 `json:"owner,omitempty"`
	Team       string                                 `json:"team,omitempty"`
	Status     string                                 `json:"status,omitempty"`
	DueAt      string                                 `json:"due_at,omitempty"`
	Reason     string                                 `json:"reason,omitempty"`
}

type grcVendorQuestionnaireCommentRequest struct {
	TenantID string                              `json:"tenant_id,omitempty"`
	Comment  ports.GRCVendorQuestionnaireComment `json:"comment"`
	Author   string                              `json:"author,omitempty"`
	Body     string                              `json:"body,omitempty"`
	Scope    string                              `json:"scope,omitempty"`
}

type grcVendorQuestionnaireApprovalRequest struct {
	TenantID string                               `json:"tenant_id,omitempty"`
	Approval ports.GRCVendorQuestionnaireApproval `json:"approval"`
	Approver string                               `json:"approver,omitempty"`
	State    string                               `json:"state,omitempty"`
	Reason   string                               `json:"reason,omitempty"`
	Team     string                               `json:"team,omitempty"`
}

type grcVendorQuestionnaireProcessRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

type grcVendorQuestionnaireMutation func(context.Context, *ports.GRCVendorQuestionnaireReviewRecord, time.Time) (map[string]string, error)

func (h *Handler) GRCVendorQuestionnaireReviews(w http.ResponseWriter, r *http.Request) {
	scope, err := h.resolveScope(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	vendorID := strings.TrimSpace(r.PathValue("vendorID"))
	vendorURN := strings.TrimSpace(r.URL.Query().Get("vendor_urn"))
	if vendorURN != "" {
		if err := h.authorizeURN(r.Context(), vendorURN); err != nil {
			h.writeError(w, err)
			return
		}
	}
	store := h.store
	if store == nil {
		h.writeError(w, grcvendor.ErrRuntimeUnavailable)
		return
	}
	if vendorURN == "" {
		detail, err := h.vendorForQuestionnaire(r, scope, vendorID, "")
		if err != nil {
			h.writeError(w, err)
			return
		}
		vendorURN = detail.Vendor.URN
	}
	records, err := store.ListGRCVendorQuestionnaireReviews(r.Context(), ports.GRCVendorQuestionnaireReviewFilter{
		TenantID:  scope.TenantID,
		VendorURN: vendorURN,
		SourceID:  scope.SourceID,
		Status:    strings.TrimSpace(r.URL.Query().Get("status")),
		Limit:     scope.Limit,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	views := grcVendorQuestionnaireReviewViews(records)
	writeJSON(w, http.StatusOK, grcVendorQuestionnaireReviewsResponse{
		Summary:     summarizeGRCVendorQuestionnaireReviewViews(views),
		Reviews:     views,
		GeneratedAt: time.Now().UTC(),
	})
}

func (h *Handler) CreateGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request) {
	var request grcVendorQuestionnaireCreateRequest
	if err := decodeGRCVendorQuestionnaireJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	scope, err := h.resolveScope(grcRequestWithTenant(r, request.TenantID))
	if err != nil {
		h.writeError(w, err)
		return
	}
	vendorID := firstNonEmpty(request.VendorID, r.PathValue("vendorID"))
	detail, err := h.vendorForQuestionnaire(r, scope, vendorID, request.VendorURN)
	if err != nil {
		h.writeError(w, err)
		return
	}
	store := h.store
	if store == nil {
		h.writeError(w, grcvendor.ErrRuntimeUnavailable)
		return
	}
	now := time.Now().UTC()
	attrs := copyGRCStringMap(request.Attributes)
	if request.SourceFilename != "" {
		attrs["source_filename"] = request.SourceFilename
	}
	if request.QuestionCount > 0 {
		attrs["question_count"] = strconv.Itoa(request.QuestionCount)
	}
	record := grcvendor.NewQuestionnaireReviewRecord(grcvendor.NewQuestionnaireReviewRequest{
		TenantID:           scope.TenantID,
		VendorURN:          detail.Vendor.URN,
		VendorID:           firstNonEmpty(request.VendorID, detail.Vendor.VendorID),
		SourceID:           firstNonEmpty(request.SourceID, scope.SourceID),
		RuntimeID:          firstNonEmpty(request.RuntimeID, scope.RuntimeID),
		UploadID:           request.UploadID,
		QuestionnaireURN:   request.QuestionnaireURN,
		QuestionnaireType:  request.QuestionnaireType,
		Title:              request.Title,
		Status:             request.Status,
		ReviewerUserID:     request.ReviewerUserID,
		CurrentOwnerUserID: firstNonEmpty(request.CurrentOwnerUserID, detail.Vendor.Owner),
		AssignedTeam:       request.AssignedTeam,
		Attributes:         attrs,
	}, now)
	event := grcvendor.QuestionnaireEvent(record, ports.GRCVendorQuestionnaireEventCreated, h.actorID(r.Context()), "Questionnaire review created", map[string]string{"vendor_urn": record.VendorURN}, now)
	created, err := store.UpsertGRCVendorQuestionnaireReview(r.Context(), record, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), scope.TenantID)
	writeJSON(w, http.StatusCreated, grcVendorQuestionnaireReviewResponse{Review: grcVendorQuestionnaireReviewViewFromRecord(created), GeneratedAt: now})
}

func (h *Handler) GetGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request) {
	record, events, err := h.reviewFromRequest(r.Context(), r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcVendorQuestionnaireReviewResponse{Review: grcVendorQuestionnaireReviewViewFromRecord(record), Events: events, GeneratedAt: time.Now().UTC()})
}

func (h *Handler) ProcessGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request) {
	var request grcVendorQuestionnaireProcessRequest
	if err := decodeGRCVendorQuestionnaireJSONAllowEmpty(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	scopedRequest := grcRequestWithTenant(r, request.TenantID)
	record, _, err := h.reviewFromRequestWithTenant(r.Context(), scopedRequest, request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	scope, err := h.resolveScope(scopedRequest)
	if err != nil {
		h.writeError(w, err)
		return
	}
	detail, err := h.vendorForQuestionnaire(r, scope, record.VendorID, record.VendorURN)
	if err != nil {
		h.writeError(w, err)
		return
	}
	findings, evidence := h.questionnaireSignals(r, scope, record.VendorURN)
	llmSummary := h.questionnaireLLMSummary(r, scope, record, detail, findings, evidence)
	now := time.Now().UTC()
	updated := grcvendor.BuildQuestionnaireReviewEnrichment(*record, detail.Vendor, detail.Relationships, findings, evidence, llmSummary, now)
	event := grcvendor.QuestionnaireEvent(updated, ports.GRCVendorQuestionnaireEventProcessed, h.actorID(r.Context()), "Questionnaire answers refreshed from vendor evidence", map[string]string{
		"decision":          updated.Decision,
		"status":            updated.Status,
		"evidence_matches":  fmt.Sprint(len(updated.EvidenceMatches)),
		"missing_questions": fmt.Sprint(len(updated.MissingQuestions)),
	}, now)
	store := h.store
	saved, err := store.UpsertGRCVendorQuestionnaireReview(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	events, err := store.ListGRCVendorQuestionnaireReviewEvents(r.Context(), ports.GRCVendorQuestionnaireReviewEventFilter{TenantID: saved.TenantID, ReviewID: saved.ReviewID, Limit: scope.Limit})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), scope.TenantID)
	writeJSON(w, http.StatusOK, grcVendorQuestionnaireReviewResponse{Review: grcVendorQuestionnaireReviewViewFromRecord(saved), Events: events, GeneratedAt: now})
}

func (h *Handler) AssignGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request) {
	var request grcVendorQuestionnaireAssignmentRequest
	if err := decodeGRCVendorQuestionnaireJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	h.updateGRCVendorQuestionnaireReview(w, r, request.TenantID, ports.GRCVendorQuestionnaireEventAssigned, "Questionnaire assignment added", func(ctx context.Context, record *ports.GRCVendorQuestionnaireReviewRecord, now time.Time) (map[string]string, error) {
		assignment := request.Assignment
		if assignment.OwnerID == "" {
			assignment.OwnerID = request.Owner
		}
		if assignment.Team == "" {
			assignment.Team = request.Team
		}
		if assignment.Reason == "" {
			assignment.Reason = request.Reason
		}
		if assignment.Status == "" {
			assignment.Status = request.Status
		}
		if assignment.DueAt == nil {
			assignment.DueAt = parseOptionalTime(request.DueAt)
		}
		if assignment.ID == "" {
			assignment.ID = "assignment-" + record.ReviewID + "-" + firstNonEmpty(request.QuestionID, assignment.Team, assignment.OwnerID, fmt.Sprint(len(record.Assignments)+1))
		}
		if assignment.Team == "" {
			assignment.Team = "security"
		}
		if assignment.Status == "" {
			assignment.Status = "open"
		}
		if assignment.CreatedAt == nil {
			assignment.CreatedAt = &now
		}
		record.Assignments = append(record.Assignments, assignment)
		record.Timeline = append(record.Timeline, grcvendor.QuestionnaireTimeline(ports.GRCVendorQuestionnaireEventAssigned, h.actorID(ctx), "Questionnaire assignment added", map[string]string{"team": assignment.Team}, now))
		return map[string]string{"team": assignment.Team, "owner_id": assignment.OwnerID}, nil
	})
}

func (h *Handler) CommentGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request) {
	var request grcVendorQuestionnaireCommentRequest
	if err := decodeGRCVendorQuestionnaireJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	h.updateGRCVendorQuestionnaireReview(w, r, request.TenantID, ports.GRCVendorQuestionnaireEventCommented, "Questionnaire comment added", func(ctx context.Context, record *ports.GRCVendorQuestionnaireReviewRecord, now time.Time) (map[string]string, error) {
		comment := request.Comment
		comment.ActorID = h.actorID(ctx)
		if comment.Body == "" {
			comment.Body = request.Body
		}
		if comment.Scope == "" {
			comment.Scope = request.Scope
		}
		if comment.ID == "" || grcVendorQuestionnaireCommentIDExists(record.Comments, comment.ID) {
			comment.ID = grcVendorQuestionnaireMutationID("comment", record.ReviewID, now, comment.ActorID, comment.Scope, comment.Body)
		}
		if comment.CreatedAt == nil {
			comment.CreatedAt = &now
		}
		record.Comments = append(record.Comments, comment)
		record.Timeline = append(record.Timeline, grcvendor.QuestionnaireTimeline(ports.GRCVendorQuestionnaireEventCommented, comment.ActorID, "Questionnaire comment added", map[string]string{"scope": comment.Scope}, now))
		return map[string]string{"comment_id": comment.ID, "scope": comment.Scope}, nil
	})
}

func (h *Handler) ApproveGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request) {
	var request grcVendorQuestionnaireApprovalRequest
	if err := decodeGRCVendorQuestionnaireJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	h.updateGRCVendorQuestionnaireReview(w, r, request.TenantID, ports.GRCVendorQuestionnaireEventApproved, "Questionnaire approval recorded", func(ctx context.Context, record *ports.GRCVendorQuestionnaireReviewRecord, now time.Time) (map[string]string, error) {
		approval := request.Approval
		approval.ActorID = h.actorID(ctx)
		if approval.Decision == "" {
			approval.Decision = request.State
		}
		if approval.Reason == "" {
			approval.Reason = request.Reason
		}
		if approval.Team == "" {
			approval.Team = request.Team
		}
		decision, err := grcVendorQuestionnaireApprovalDecision(approval.Decision)
		if err != nil {
			return nil, err
		}
		approval.Decision = decision
		if approval.ID == "" || grcVendorQuestionnaireApprovalIDExists(record.Approvals, approval.ID) {
			approval.ID = grcVendorQuestionnaireMutationID("approval", record.ReviewID, now, approval.ActorID, approval.Team, approval.Decision, approval.Reason)
		}
		if approval.CreatedAt == nil {
			approval.CreatedAt = &now
		}
		record.Approvals = append(record.Approvals, approval)
		switch approval.Decision {
		case "approved":
			record.Status = ports.GRCVendorQuestionnaireStatusApproved
			record.Decision = ports.GRCVendorQuestionnaireDecisionApprove
		case "approved_with_conditions":
			record.Status = ports.GRCVendorQuestionnaireStatusConditional
			record.Decision = ports.GRCVendorQuestionnaireDecisionApproveWithConditions
		case "rejected":
			record.Status = ports.GRCVendorQuestionnaireStatusRejected
			record.Decision = ports.GRCVendorQuestionnaireDecisionReject
		}
		record.Timeline = append(record.Timeline, grcvendor.QuestionnaireTimeline(ports.GRCVendorQuestionnaireEventApproved, approval.ActorID, "Questionnaire approval recorded", map[string]string{"team": approval.Team, "decision": approval.Decision}, now))
		return map[string]string{"team": approval.Team, "decision": approval.Decision}, nil
	})
}

func (h *Handler) updateGRCVendorQuestionnaireReview(w http.ResponseWriter, r *http.Request, tenantID string, eventType string, summary string, mutate grcVendorQuestionnaireMutation) {
	ctx := r.Context()
	record, _, err := h.reviewFromRequestWithTenant(ctx, r, tenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if mutate == nil {
		h.writeError(w, fmt.Errorf("%w: questionnaire mutation is required", grcvendor.ErrInvalidRequest))
		return
	}
	now := time.Now().UTC()
	payload, err := mutate(ctx, record, now)
	if err != nil {
		h.writeError(w, err)
		return
	}
	record.UpdatedAt = now
	event := grcvendor.QuestionnaireEvent(*record, eventType, h.actorID(ctx), summary, payload, now)
	store := h.store
	saved, err := store.UpsertGRCVendorQuestionnaireReview(ctx, *record, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	events, err := store.ListGRCVendorQuestionnaireReviewEvents(ctx, ports.GRCVendorQuestionnaireReviewEventFilter{TenantID: saved.TenantID, ReviewID: saved.ReviewID, Limit: defaultLimit})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(ctx, saved.TenantID)
	writeJSON(w, http.StatusOK, grcVendorQuestionnaireReviewResponse{Review: grcVendorQuestionnaireReviewViewFromRecord(saved), Events: events, GeneratedAt: now})
}

func grcVendorQuestionnaireApprovalDecision(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "approved":
		return "approved", nil
	case "approved_with_conditions":
		return "approved_with_conditions", nil
	case "rejected":
		return "rejected", nil
	default:
		return "", fmt.Errorf("%w: approval state must be approved, approved_with_conditions, or rejected", grcvendor.ErrInvalidRequest)
	}
}

func grcVendorQuestionnaireMutationID(prefix string, reviewID string, now time.Time, values ...string) string {
	seed := []string{strings.TrimSpace(reviewID), now.UTC().Format(time.RFC3339Nano)}
	for _, value := range values {
		seed = append(seed, strings.TrimSpace(value))
	}
	sum := sha256.Sum256([]byte(strings.Join(seed, "\x00")))
	return strings.TrimSpace(prefix) + "-" + strings.TrimSpace(reviewID) + "-" + hex.EncodeToString(sum[:])[:16]
}

func grcVendorQuestionnaireCommentIDExists(items []ports.GRCVendorQuestionnaireComment, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item.ID) == id {
			return true
		}
	}
	return false
}

func grcVendorQuestionnaireApprovalIDExists(items []ports.GRCVendorQuestionnaireApproval, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item.ID) == id {
			return true
		}
	}
	return false
}

func (h *Handler) reviewFromRequest(ctx context.Context, r *http.Request) (*ports.GRCVendorQuestionnaireReviewRecord, []*ports.GRCVendorQuestionnaireReviewEventRecord, error) {
	return h.reviewFromRequestWithTenant(ctx, r, "")
}

func (h *Handler) reviewFromRequestWithTenant(ctx context.Context, r *http.Request, tenantID string) (*ports.GRCVendorQuestionnaireReviewRecord, []*ports.GRCVendorQuestionnaireReviewEventRecord, error) {
	r = grcRequestWithTenant(r, tenantID)
	scope, err := h.resolveScope(r)
	if err != nil {
		return nil, nil, err
	}
	reviewID := strings.TrimSpace(r.PathValue("reviewID"))
	if reviewID == "" {
		reviewID = strings.TrimSpace(r.URL.Query().Get("review_id"))
	}
	if reviewID == "" {
		return nil, nil, fmt.Errorf("%w: review_id is required", grcvendor.ErrInvalidRequest)
	}
	store := h.store
	if store == nil {
		return nil, nil, grcvendor.ErrRuntimeUnavailable
	}
	record, err := store.GetGRCVendorQuestionnaireReview(ctx, ports.GRCVendorQuestionnaireReviewFilter{TenantID: scope.TenantID, ReviewID: reviewID})
	if err != nil {
		return nil, nil, err
	}
	if err := h.authorizeURN(ctx, record.VendorURN); err != nil {
		return nil, nil, err
	}
	events, err := store.ListGRCVendorQuestionnaireReviewEvents(ctx, ports.GRCVendorQuestionnaireReviewEventFilter{TenantID: scope.TenantID, ReviewID: reviewID, Limit: scope.Limit})
	if err != nil {
		return nil, nil, err
	}
	return record, events, nil
}

func (h *Handler) vendorForQuestionnaire(r *http.Request, scope Scope, vendorID string, vendorURN string) (*grcvendor.VendorDetail, error) {
	vendorURN = strings.TrimSpace(vendorURN)
	if vendorURN != "" {
		if err := h.authorizeURN(r.Context(), vendorURN); err != nil {
			return nil, err
		}
	}
	if h.vendor == nil {
		return nil, grcvendor.ErrRuntimeUnavailable
	}
	return h.vendor(r, scope, strings.TrimSpace(vendorID), vendorURN)
}

func (h *Handler) questionnaireSignals(r *http.Request, scope Scope, vendorURN string) ([]grcvendor.QuestionnaireFindingSignal, []grcvendor.QuestionnaireEvidenceSignal) {
	if h.signals == nil {
		return nil, nil
	}
	return h.signals(r, scope, vendorURN)
}

func (h *Handler) questionnaireLLMSummary(r *http.Request, scope Scope, record *ports.GRCVendorQuestionnaireReviewRecord, detail *grcvendor.VendorDetail, findings []grcvendor.QuestionnaireFindingSignal, evidence []grcvendor.QuestionnaireEvidenceSignal) string {
	if h.summary == nil || record == nil || detail == nil {
		return ""
	}
	return strings.TrimSpace(h.summary(r, scope, record, detail, findings, evidence))
}

func decodeGRCVendorQuestionnaireJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCVendorQuestionnaireBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode vendor questionnaire request: %w", grcvendor.ErrInvalidRequest, err)
	}
	return nil
}

func decodeGRCVendorQuestionnaireJSONAllowEmpty(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCVendorQuestionnaireBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("%w: decode vendor questionnaire request: %w", grcvendor.ErrInvalidRequest, err)
	}
	return nil
}

func grcRequestWithTenant(r *http.Request, tenantID string) *http.Request {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || strings.TrimSpace(r.URL.Query().Get("tenant_id")) != "" {
		return r
	}
	clone := new(http.Request)
	*clone = *r
	clonedURL := *r.URL
	query := clonedURL.Query()
	query.Set("tenant_id", tenantID)
	clonedURL.RawQuery = query.Encode()
	clone.URL = &clonedURL
	return clone
}

func grcVendorQuestionnaireReviewStore(store ports.StateStore) ports.GRCVendorQuestionnaireReviewStore {
	reviewStore, ok := store.(ports.GRCVendorQuestionnaireReviewStore)
	if !ok || isNilInterface(reviewStore) {
		return nil
	}
	return reviewStore
}

func grcVendorQuestionnaireReviewViews(records []*ports.GRCVendorQuestionnaireReviewRecord) []grcVendorQuestionnaireReviewView {
	views := make([]grcVendorQuestionnaireReviewView, 0, len(records))
	for _, record := range records {
		views = append(views, grcVendorQuestionnaireReviewViewFromRecord(record))
	}
	return views
}

func grcVendorQuestionnaireReviewViewFromRecord(record *ports.GRCVendorQuestionnaireReviewRecord) grcVendorQuestionnaireReviewView {
	if record == nil {
		return grcVendorQuestionnaireReviewView{}
	}
	questionCount := intStringAttribute(record.Attributes, "question_count")
	if questionCount <= 0 {
		questionCount = len(record.AnswerSuggestions) + len(record.MissingQuestions)
	}
	if questionCount <= 0 {
		questionCount = len(record.EvidenceMatches) + len(record.MissingQuestions)
	}
	answeredCount := 0
	for _, answer := range record.AnswerSuggestions {
		if answer.State == "supported" {
			answeredCount++
		}
	}
	if answeredCount == 0 && questionCount > 0 {
		answeredCount = questionCount - len(record.MissingQuestions)
		if answeredCount < 0 {
			answeredCount = 0
		}
	}
	updatedAt := record.UpdatedAt
	processedAt := grcQuestionnaireProcessedAt(record)
	missingAnswers := make([]string, 0, len(record.MissingQuestions))
	for _, item := range record.MissingQuestions {
		missingAnswers = append(missingAnswers, item.Question)
	}
	riskNotes := []string{}
	if record.DecisionReason != "" {
		riskNotes = append(riskNotes, record.DecisionReason)
	}
	if summary := strings.TrimSpace(record.Attributes["llm_summary"]); summary != "" {
		riskNotes = append(riskNotes, summary)
	}
	return grcVendorQuestionnaireReviewView{
		GRCVendorQuestionnaireReviewIdentityView: GRCVendorQuestionnaireReviewIdentityView{
			ID:             record.ReviewID,
			ReviewID:       record.ReviewID,
			TenantID:       record.TenantID,
			VendorURN:      record.VendorURN,
			VendorID:       record.VendorID,
			Title:          firstNonEmpty(record.Title, "Security questionnaire"),
			SourceFilename: firstNonEmpty(record.Attributes["source_filename"], record.Attributes["file_name"], record.UploadID),
			Owner:          firstNonEmpty(record.CurrentOwnerUserID, record.ReviewerUserID, record.AssignedTeam),
			DueAt:          firstDatePtrFromAttributes(record.Attributes, "due_at", "review_due_at"),
		},
		GRCVendorQuestionnaireReviewStateView: GRCVendorQuestionnaireReviewStateView{
			ReviewState:            reviewStateForQuestionnaireStatus(record.Status),
			UploadState:            uploadStateForQuestionnaire(record),
			ProcessState:           processStateForQuestionnaire(record),
			EnrichmentState:        enrichmentStateForQuestionnaire(record),
			DecisionState:          decisionStateForQuestionnaire(record.Decision, record.Status),
			DecisionRecommendation: record.DecisionReason,
			Status:                 record.Status,
			Decision:               record.Decision,
			CreatedAt:              record.CreatedAt,
			UpdatedAt:              &updatedAt,
			ProcessedAt:            processedAt,
		},
		GRCVendorQuestionnaireReviewMetricView: GRCVendorQuestionnaireReviewMetricView{
			QuestionCount:      questionCount,
			AnsweredCount:      answeredCount,
			MissingAnswerCount: len(record.MissingQuestions),
			EvidenceMatchCount: len(record.EvidenceMatches),
			RiskNotes:          riskNotes,
			MissingAnswers:     missingAnswers,
		},
		GRCVendorQuestionnaireReviewContentView: GRCVendorQuestionnaireReviewContentView{
			EvidenceMatches: grcVendorQuestionnaireEvidenceMatchViews(record.EvidenceMatches),
			Assignments:     grcVendorQuestionnaireAssignmentViews(record.Assignments),
			Comments:        grcVendorQuestionnaireCommentViews(record.Comments),
			Approvals:       grcVendorQuestionnaireApprovalViews(record.Approvals),
			Timeline:        grcVendorQuestionnaireTimelineViews(record.Timeline),
			Attributes:      record.Attributes,
		},
	}
}

func grcVendorQuestionnaireEvidenceMatchViews(items []ports.GRCVendorQuestionnaireEvidence) []grcVendorQuestionnaireEvidenceMatchView {
	views := make([]grcVendorQuestionnaireEvidenceMatchView, 0, len(items))
	for _, item := range items {
		views = append(views, grcVendorQuestionnaireEvidenceMatchView{
			ID:              item.ID,
			QuestionID:      firstNonEmpty(item.Attributes["question_id"], item.ID),
			SourceLabel:     firstNonEmpty(item.Label, item.ID),
			SourceType:      item.Source,
			EvidenceURN:     item.URN,
			ControlID:       item.ControlID,
			MatchState:      "matched",
			ConfidenceScore: confidenceScore(item.Confidence),
			AnswerText:      item.Reason,
		})
	}
	return views
}

func grcVendorQuestionnaireAssignmentViews(items []ports.GRCVendorQuestionnaireAssignment) []grcVendorQuestionnaireAssignmentView {
	views := make([]grcVendorQuestionnaireAssignmentView, 0, len(items))
	for _, item := range items {
		views = append(views, grcVendorQuestionnaireAssignmentView{
			ID:         firstNonEmpty(item.ID, "assignment-"+item.Team),
			QuestionID: "",
			Owner:      firstNonEmpty(item.OwnerID, item.Team),
			Status:     firstNonEmpty(item.Status, "open"),
			DueAt:      item.DueAt,
			Reason:     item.Reason,
			CreatedAt:  item.CreatedAt,
		})
	}
	return views
}

func grcVendorQuestionnaireCommentViews(items []ports.GRCVendorQuestionnaireComment) []grcVendorQuestionnaireCommentView {
	views := make([]grcVendorQuestionnaireCommentView, 0, len(items))
	for _, item := range items {
		views = append(views, grcVendorQuestionnaireCommentView{
			ID:        item.ID,
			Author:    item.ActorID,
			Body:      item.Body,
			CreatedAt: item.CreatedAt,
		})
	}
	return views
}

func grcVendorQuestionnaireApprovalViews(items []ports.GRCVendorQuestionnaireApproval) []grcVendorQuestionnaireApprovalView {
	views := make([]grcVendorQuestionnaireApprovalView, 0, len(items))
	for _, item := range items {
		views = append(views, grcVendorQuestionnaireApprovalView{
			ID:        item.ID,
			Approver:  item.ActorID,
			State:     item.Decision,
			Reason:    item.Reason,
			CreatedAt: item.CreatedAt,
		})
	}
	return views
}

func grcVendorQuestionnaireTimelineViews(items []ports.GRCVendorQuestionnaireTimeline) []grcVendorQuestionnaireTimelineEventView {
	views := make([]grcVendorQuestionnaireTimelineEventView, 0, len(items))
	for _, item := range items {
		views = append(views, grcVendorQuestionnaireTimelineEventView{
			ID:        item.ID,
			EventType: item.EventType,
			Actor:     item.ActorID,
			Label:     item.Summary,
			Detail:    firstNonEmpty(item.Attributes["detail"], item.Attributes["decision"], item.Attributes["status"]),
			CreatedAt: item.CreatedAt,
		})
	}
	return views
}

func summarizeGRCVendorQuestionnaireReviewViews(views []grcVendorQuestionnaireReviewView) grcVendorQuestionnaireReviewSummary {
	var summary grcVendorQuestionnaireReviewSummary
	summary.TotalReviews = len(views)
	for _, view := range views {
		summary.MissingAnswers += view.MissingAnswerCount
		for _, assignment := range view.Assignments {
			if assignment.Status == "" || assignment.Status == "open" {
				summary.OpenAssignments++
			}
		}
		if len(view.Approvals) == 0 && (view.DecisionState == "needs_followup" || view.ProcessState == "processed") {
			summary.PendingApprovals++
		}
		switch view.ReviewState {
		case "intake", "uploaded":
			summary.IntakeReviews++
		}
		switch view.ProcessState {
		case "processing":
			summary.ProcessingReviews++
		case "ready", "processed", "complete":
			summary.ReadyReviews++
		}
		switch view.DecisionState {
		case "needs_followup", "blocked":
			summary.BlockedReviews++
		case "approved", "accepted":
			summary.ApprovedReviews++
		}
	}
	return summary
}

func reviewStateForQuestionnaireStatus(status string) string {
	switch strings.TrimSpace(status) {
	case ports.GRCVendorQuestionnaireStatusIntake, ports.GRCVendorQuestionnaireStatusUploaded:
		return "intake"
	case ports.GRCVendorQuestionnaireStatusProcessing, ports.GRCVendorQuestionnaireStatusNeedsInput, ports.GRCVendorQuestionnaireStatusReadyForApproval:
		return "in_review"
	case ports.GRCVendorQuestionnaireStatusApproved, ports.GRCVendorQuestionnaireStatusConditional:
		return "approved"
	case ports.GRCVendorQuestionnaireStatusRejected:
		return "rejected"
	default:
		return firstNonEmpty(status, "intake")
	}
}

func uploadStateForQuestionnaire(record *ports.GRCVendorQuestionnaireReviewRecord) string {
	if record == nil {
		return ""
	}
	if record.QuestionnaireURN != "" || record.UploadID != "" {
		return "uploaded"
	}
	return "intake"
}

func processStateForQuestionnaire(record *ports.GRCVendorQuestionnaireReviewRecord) string {
	if record == nil {
		return ""
	}
	switch record.Status {
	case ports.GRCVendorQuestionnaireStatusProcessing:
		return "processing"
	case ports.GRCVendorQuestionnaireStatusIntake, ports.GRCVendorQuestionnaireStatusUploaded:
		return "not_started"
	default:
		if len(record.EvidenceMatches) > 0 || len(record.MissingQuestions) > 0 || len(record.AnswerSuggestions) > 0 {
			return "processed"
		}
		return "not_started"
	}
}

func enrichmentStateForQuestionnaire(record *ports.GRCVendorQuestionnaireReviewRecord) string {
	if record == nil {
		return ""
	}
	if record.Attributes["llm_summary_status"] == "available" {
		return "llm_reviewed"
	}
	if len(record.EvidenceMatches) > 0 || len(record.MissingQuestions) > 0 {
		return "evidence_matched"
	}
	return "pending"
}

func decisionStateForQuestionnaire(decision string, status string) string {
	switch strings.TrimSpace(decision) {
	case ports.GRCVendorQuestionnaireDecisionApprove:
		return "approved"
	case ports.GRCVendorQuestionnaireDecisionApproveWithConditions, ports.GRCVendorQuestionnaireDecisionNeedsReview:
		return "needs_followup"
	case ports.GRCVendorQuestionnaireDecisionReject:
		return "rejected"
	}
	if status == ports.GRCVendorQuestionnaireStatusApproved {
		return "approved"
	}
	return "not_started"
}

func grcQuestionnaireProcessedAt(record *ports.GRCVendorQuestionnaireReviewRecord) *time.Time {
	if record == nil {
		return nil
	}
	for index := len(record.Timeline) - 1; index >= 0; index-- {
		if record.Timeline[index].EventType == ports.GRCVendorQuestionnaireEventProcessed {
			return record.Timeline[index].CreatedAt
		}
	}
	return nil
}

func confidenceScore(value string) int {
	switch strings.TrimSpace(value) {
	case "high":
		return 90
	case "medium":
		return 65
	case "low":
		return 35
	default:
		return 50
	}
}

func intStringAttribute(attrs map[string]string, key string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(attrs[key]))
	return value
}

func firstDatePtrFromAttributes(attrs map[string]string, keys ...string) *time.Time {
	for _, key := range keys {
		value := strings.TrimSpace(attrs[key])
		if value == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02"} {
			parsed, err := time.Parse(layout, value)
			if err == nil {
				parsed = parsed.UTC()
				return &parsed
			}
		}
	}
	return nil
}

func parseOptionalTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			parsed = parsed.UTC()
			return &parsed
		}
	}
	return nil
}

func copyGRCStringMap(values map[string]string) map[string]string {
	copied := map[string]string{}
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			copied[key] = value
		}
	}
	return copied
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}
