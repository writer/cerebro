package questionnaire

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/evidencepackets"
	"github.com/writer/cerebro/internal/ports"
	questionnairedomain "github.com/writer/cerebro/internal/questionnaire"
)

const maxQuestionnaireBodyBytes = 512 << 10
const maxQuestionnaireCreateBodyBytes = 16 << 20
const defaultLimit uint32 = 100

var (
	ErrRuntimeUnavailable = errors.New("questionnaire runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid questionnaire request")
)

type Scope struct {
	TenantID   string
	RuntimeID  string
	RuntimeIDs []string
	SourceID   string
	VendorURN  string
	Limit      uint32
}

type ScopeResolver func(*http.Request) (Scope, error)
type EvidenceResolver func(*http.Request, Scope) ([]evidencepackets.QuestionnaireAnswer, error)
type TenantAuthorizer func(context.Context, string) error
type ActorResolver func(context.Context) string
type CacheBumper func(context.Context, string)
type ErrorWriter func(http.ResponseWriter, error)

type Options struct {
	Scope     ScopeResolver
	Evidence  EvidenceResolver
	Authorize TenantAuthorizer
	Actor     ActorResolver
	BumpCache CacheBumper
	WriteErr  ErrorWriter
}

type Handler struct {
	store     ports.QuestionnaireRunStore
	scope     ScopeResolver
	evidence  EvidenceResolver
	authorize TenantAuthorizer
	actor     ActorResolver
	bumpCache CacheBumper
	writeErr  ErrorWriter
}

func NewHandler(store ports.StateStore, options Options) *Handler {
	return &Handler{
		store:     questionnaireRunStore(store),
		scope:     options.Scope,
		evidence:  options.Evidence,
		authorize: options.Authorize,
		actor:     options.Actor,
		bumpCache: options.BumpCache,
		writeErr:  options.WriteErr,
	}
}

type runsResponse struct {
	Summary     runSummary `json:"summary"`
	Runs        []runView  `json:"runs"`
	GeneratedAt time.Time  `json:"generated_at"`
}

type runResponse struct {
	Run         runView                              `json:"run"`
	Events      []*ports.QuestionnaireRunEventRecord `json:"events,omitempty"`
	GeneratedAt time.Time                            `json:"generated_at"`
}

type runSummary struct {
	TotalRuns       int `json:"total_runs"`
	CustomerRuns    int `json:"customer_runs"`
	VendorRuns      int `json:"vendor_runs"`
	DueRuns         int `json:"due_runs"`
	BlockedAnswers  int `json:"blocked_answers"`
	ReviewAnswers   int `json:"review_answers"`
	ReadyAnswers    int `json:"ready_answers"`
	StaleEvidence   int `json:"stale_evidence"`
	MissingEvidence int `json:"missing_evidence"`
	Unassigned      int `json:"unassigned"`
}

type runView struct {
	runViewIdentity
	runViewParties
	runViewWorkflow
	runViewCounts
	runViewContent
	Attributes map[string]string `json:"attributes,omitempty"`
}

type runViewIdentity struct {
	ID        string    `json:"id"`
	RunID     string    `json:"run_id"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Title     string    `json:"title"`
	Direction string    `json:"direction"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type runViewParties struct {
	Requester      string `json:"requester,omitempty"`
	CustomerName   string `json:"customer_name,omitempty"`
	VendorURN      string `json:"vendor_urn,omitempty"`
	VendorID       string `json:"vendor_id,omitempty"`
	SourceFilename string `json:"source_filename,omitempty"`
	SourceFormat   string `json:"source_format,omitempty"`
	OwnerID        string `json:"owner_id,omitempty"`
	AssignedTeam   string `json:"assigned_team,omitempty"`
}

type runViewWorkflow struct {
	Status         string     `json:"status"`
	Decision       string     `json:"decision,omitempty"`
	DecisionReason string     `json:"decision_reason,omitempty"`
	DueAt          *time.Time `json:"due_at,omitempty"`
}

type runViewCounts struct {
	QuestionCount        int `json:"question_count"`
	AnswerCount          int `json:"answer_count"`
	ReadyAnswerCount     int `json:"ready_answer_count"`
	BlockedAnswerCount   int `json:"blocked_answer_count"`
	ReviewAnswerCount    int `json:"review_answer_count"`
	MissingEvidenceCount int `json:"missing_evidence_count"`
	StaleEvidenceCount   int `json:"stale_evidence_count"`
	UnassignedCount      int `json:"unassigned_count"`
}

type runViewContent struct {
	Questions   []ports.QuestionnaireQuestion   `json:"questions,omitempty"`
	Answers     []ports.QuestionnaireRunAnswer  `json:"answers,omitempty"`
	Assignments []ports.QuestionnaireAssignment `json:"assignments,omitempty"`
	Decisions   []ports.QuestionnaireDecision   `json:"decisions,omitempty"`
	Comments    []ports.QuestionnaireComment    `json:"comments,omitempty"`
	Timeline    []ports.QuestionnaireTimeline   `json:"timeline,omitempty"`
}

type createRequest struct {
	TenantID       string                        `json:"tenant_id,omitempty"`
	Direction      string                        `json:"direction,omitempty"`
	Title          string                        `json:"title,omitempty"`
	Requester      string                        `json:"requester,omitempty"`
	CustomerName   string                        `json:"customer_name,omitempty"`
	VendorURN      string                        `json:"vendor_urn,omitempty"`
	VendorID       string                        `json:"vendor_id,omitempty"`
	SourceID       string                        `json:"source_id,omitempty"`
	RuntimeID      string                        `json:"runtime_id,omitempty"`
	UploadID       string                        `json:"upload_id,omitempty"`
	SourceFilename string                        `json:"source_filename,omitempty"`
	SourceFormat   string                        `json:"source_format,omitempty"`
	OwnerID        string                        `json:"owner_id,omitempty"`
	AssignedTeam   string                        `json:"assigned_team,omitempty"`
	DueAt          string                        `json:"due_at,omitempty"`
	Questions      []ports.QuestionnaireQuestion `json:"questions,omitempty"`
	IntakeRows     []intakeRow                   `json:"intake_rows,omitempty"`
	IntakeText     string                        `json:"intake_text,omitempty"`
	IntakeFormat   string                        `json:"intake_format,omitempty"`
	IntakeFile     string                        `json:"intake_file_base64,omitempty"`
	IntakeMimeType string                        `json:"intake_content_type,omitempty"`
	PortalURL      string                        `json:"portal_url,omitempty"`
	PortalNotes    string                        `json:"portal_instructions,omitempty"`
	Attributes     map[string]string             `json:"attributes,omitempty"`
}

type intakeRow struct {
	ID                   string   `json:"id,omitempty"`
	Question             string   `json:"question,omitempty"`
	Section              string   `json:"section,omitempty"`
	RequiredAnswerFormat string   `json:"required_answer_format,omitempty"`
	MappedControls       []string `json:"mapped_controls,omitempty"`
	RequiredSlots        []string `json:"required_evidence_slots,omitempty"`
	OwnerID              string   `json:"owner_id,omitempty"`
}

type assignmentRequest struct {
	TenantID   string                         `json:"tenant_id,omitempty"`
	Assignment *ports.QuestionnaireAssignment `json:"assignment,omitempty"`
	QuestionID string                         `json:"question_id,omitempty"`
	OwnerID    string                         `json:"owner_id,omitempty"`
	Team       string                         `json:"team,omitempty"`
	Status     string                         `json:"status,omitempty"`
	DueAt      string                         `json:"due_at,omitempty"`
	Reason     string                         `json:"reason,omitempty"`
}

type decisionRequest struct {
	TenantID   string                       `json:"tenant_id,omitempty"`
	Decision   *ports.QuestionnaireDecision `json:"decision,omitempty"`
	QuestionID string                       `json:"question_id,omitempty"`
	State      string                       `json:"state,omitempty"`
	Reason     string                       `json:"reason,omitempty"`
}

type commentRequest struct {
	TenantID   string                      `json:"tenant_id,omitempty"`
	Comment    *ports.QuestionnaireComment `json:"comment,omitempty"`
	QuestionID string                      `json:"question_id,omitempty"`
	Body       string                      `json:"body,omitempty"`
}

type questionUpdateRequest struct {
	TenantID       string                       `json:"tenant_id,omitempty"`
	Question       *ports.QuestionnaireQuestion `json:"question,omitempty"`
	QuestionID     string                       `json:"question_id,omitempty"`
	RequiredSlots  []string                     `json:"required_evidence_slots,omitempty"`
	MappedControls []string                     `json:"mapped_controls,omitempty"`
	OwnerID        string                       `json:"owner_id,omitempty"`
	Reason         string                       `json:"reason,omitempty"`
	ClearSlots     bool                         `json:"clear_required_evidence_slots,omitempty"`
	ClearControls  bool                         `json:"clear_mapped_controls,omitempty"`
	ClearOwner     bool                         `json:"clear_owner,omitempty"`
}

type vendorLinkRequest struct {
	TenantID  string `json:"tenant_id,omitempty"`
	VendorURN string `json:"vendor_urn,omitempty"`
	VendorID  string `json:"vendor_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Unlink    bool   `json:"unlink,omitempty"`
}

type processRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

func (h *Handler) ListRuns(w http.ResponseWriter, r *http.Request) {
	scope, err := h.resolveScope(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := h.authorizeTenant(r.Context(), scope.TenantID); err != nil {
		h.writeError(w, err)
		return
	}
	if h.store == nil {
		h.writeError(w, ErrRuntimeUnavailable)
		return
	}
	filter := ports.QuestionnaireRunFilter{
		TenantID:  scope.TenantID,
		Direction: strings.TrimSpace(r.URL.Query().Get("direction")),
		Status:    strings.TrimSpace(r.URL.Query().Get("status")),
		VendorURN: strings.TrimSpace(r.URL.Query().Get("vendor_urn")),
		Requester: strings.TrimSpace(r.URL.Query().Get("requester")),
		Customer:  strings.TrimSpace(r.URL.Query().Get("customer_name")),
		OwnerID:   strings.TrimSpace(r.URL.Query().Get("owner_id")),
		Query:     strings.TrimSpace(r.URL.Query().Get("q")),
		Limit:     scope.Limit,
	}
	records, err := h.store.ListQuestionnaireRuns(r.Context(), filter)
	if err != nil {
		h.writeError(w, err)
		return
	}
	summary, err := h.store.SummarizeQuestionnaireRuns(r.Context(), filter)
	if err != nil {
		h.writeError(w, err)
		return
	}
	views := runViews(records, false)
	writeJSON(w, http.StatusOK, runsResponse{Summary: runSummaryFromStore(summary), Runs: views, GeneratedAt: time.Now().UTC()})
}

func (h *Handler) CreateRun(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if err := decodeJSONWithLimit(w, r, &request, maxQuestionnaireCreateBodyBytes); err != nil {
		h.writeError(w, err)
		return
	}
	scope, err := h.resolveScope(requestWithTenant(r, request.TenantID))
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := h.authorizeTenant(r.Context(), scope.TenantID); err != nil {
		h.writeError(w, err)
		return
	}
	if h.store == nil {
		h.writeError(w, ErrRuntimeUnavailable)
		return
	}
	if !ports.IsQuestionnaireDirection(request.Direction) {
		h.writeError(w, fmt.Errorf("%w: direction must be customer_security_review or vendor_review", ErrInvalidRequest))
		return
	}
	questions, err := questionsForCreate(request)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if len(questions) == 0 && !allowsPortalCaptureWithoutQuestions(request) {
		h.writeError(w, fmt.Errorf("%w: at least one question is required", ErrInvalidRequest))
		return
	}
	dueAt, err := parseOptionalTime(request.DueAt)
	if err != nil {
		h.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	uploadID := strings.TrimSpace(request.UploadID)
	if uploadID == "" {
		uploadID = fmt.Sprintf("intake-%d", now.UnixNano())
	}
	attributes := createRunAttributes(request, len(questions))
	record := questionnairedomain.NewRunRecord(questionnairedomain.NewRunRequest{
		TenantID:       scope.TenantID,
		Direction:      request.Direction,
		Title:          request.Title,
		Requester:      request.Requester,
		CustomerName:   request.CustomerName,
		VendorURN:      request.VendorURN,
		VendorID:       request.VendorID,
		SourceID:       firstNonEmpty(request.SourceID, scope.SourceID),
		RuntimeID:      firstNonEmpty(request.RuntimeID, scope.RuntimeID),
		UploadID:       uploadID,
		SourceFilename: request.SourceFilename,
		SourceFormat:   request.SourceFormat,
		OwnerID:        request.OwnerID,
		AssignedTeam:   request.AssignedTeam,
		DueAt:          dueAt,
		Questions:      questions,
		Attributes:     attributes,
	}, now)
	event := questionnairedomain.Event(record, ports.QuestionnaireEventCreated, h.actorID(r.Context()), "Questionnaire run created", map[string]string{"direction": record.Direction, "question_count": strconv.Itoa(len(record.Questions)), "source_format": record.SourceFormat}, now)
	created, err := h.store.UpsertQuestionnaireRun(r.Context(), record, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), scope.TenantID)
	writeJSON(w, http.StatusCreated, runResponse{Run: runViewFromRecord(created, false), GeneratedAt: now})
}

func (h *Handler) GetRun(w http.ResponseWriter, r *http.Request) {
	record, events, err := h.runFromRequest(r.Context(), r, "")
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(record, false), Events: events, GeneratedAt: time.Now().UTC()})
}

func (h *Handler) ProcessRun(w http.ResponseWriter, r *http.Request) {
	var request processRequest
	if err := decodeJSONAllowEmpty(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	record, _, err := h.runFromRequest(r.Context(), requestWithTenant(r, request.TenantID), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	scopedReq := requestWithRunScope(r, firstNonEmpty(request.TenantID, record.TenantID), record.SourceID, record.RuntimeID, record.VendorURN)
	scope, err := h.resolveScope(scopedReq)
	if err != nil {
		h.writeError(w, err)
		return
	}
	answers, err := h.evidenceAnswers(scopedReq, scope)
	if err != nil {
		h.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	updated := questionnairedomain.ProcessEvidenceAnswers(*record, answers, now)
	event := questionnairedomain.Event(updated, ports.QuestionnaireEventProcessed, h.actorID(r.Context()), "Questionnaire answers refreshed from evidence", map[string]string{"answer_count": strconv.Itoa(len(updated.Answers)), "status": updated.Status}, now)
	saved, err := h.store.UpsertQuestionnaireRun(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	events, err := h.store.ListQuestionnaireRunEvents(r.Context(), ports.QuestionnaireRunEventFilter{TenantID: saved.TenantID, RunID: saved.RunID, Limit: scope.Limit})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), saved.TenantID)
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(saved, false), Events: events, GeneratedAt: now})
}

func (h *Handler) AssignRun(w http.ResponseWriter, r *http.Request) {
	var request assignmentRequest
	if err := decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	record, _, err := h.runFromRequest(r.Context(), requestWithTenant(r, request.TenantID), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if request.Assignment != nil {
		h.writeError(w, fmt.Errorf("%w: assignment object is not accepted; use top-level fields", ErrInvalidRequest))
		return
	}
	assignment := ports.QuestionnaireAssignment{
		QuestionID: strings.TrimSpace(request.QuestionID),
		OwnerID:    strings.TrimSpace(request.OwnerID),
		Team:       strings.TrimSpace(request.Team),
		Status:     firstNonEmpty(request.Status, "open"),
		Reason:     strings.TrimSpace(request.Reason),
	}
	if err := validateQuestionReference(record, assignment.QuestionID, false); err != nil {
		h.writeError(w, err)
		return
	}
	if assignment.OwnerID == "" && assignment.Team == "" {
		h.writeError(w, fmt.Errorf("%w: owner_id or team is required", ErrInvalidRequest))
		return
	}
	if assignment.DueAt == nil {
		dueAt, err := parseOptionalTime(request.DueAt)
		if err != nil {
			h.writeError(w, err)
			return
		}
		assignment.DueAt = dueAt
	}
	now := time.Now().UTC()
	updated := questionnairedomain.AddAssignment(*record, assignment, h.actorID(r.Context()), now)
	event := questionnairedomain.Event(updated, ports.QuestionnaireEventAssigned, h.actorID(r.Context()), "Questionnaire answer assigned", map[string]string{"question_id": assignment.QuestionID, "owner_id": assignment.OwnerID}, now)
	saved, err := h.store.UpsertQuestionnaireRun(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), saved.TenantID)
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(saved, false), GeneratedAt: now})
}

func (h *Handler) UpdateQuestion(w http.ResponseWriter, r *http.Request) {
	var request questionUpdateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	record, _, err := h.runFromRequest(r.Context(), requestWithTenant(r, request.TenantID), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if request.Question != nil {
		h.writeError(w, fmt.Errorf("%w: question object is not accepted; use top-level fields", ErrInvalidRequest))
		return
	}
	if err := validateQuestionReference(record, request.QuestionID, true); err != nil {
		h.writeError(w, err)
		return
	}
	if len(request.RequiredSlots) == 0 && len(request.MappedControls) == 0 && strings.TrimSpace(request.OwnerID) == "" && !request.ClearSlots && !request.ClearControls && !request.ClearOwner {
		h.writeError(w, fmt.Errorf("%w: at least one question field is required", ErrInvalidRequest))
		return
	}
	now := time.Now().UTC()
	updated := questionnairedomain.UpdateQuestion(*record, questionnairedomain.UpdateQuestionRequest{
		QuestionID:     request.QuestionID,
		RequiredSlots:  request.RequiredSlots,
		MappedControls: request.MappedControls,
		OwnerID:        request.OwnerID,
		UpdateReason:   request.Reason,
		UpdatedBy:      h.actorID(r.Context()),
		ClearSlots:     request.ClearSlots,
		ClearControls:  request.ClearControls,
		ClearOwner:     request.ClearOwner,
	}, now)
	event := questionnairedomain.Event(updated, ports.QuestionnaireEventUpdated, h.actorID(r.Context()), "Questionnaire question updated", map[string]string{"question_id": strings.TrimSpace(request.QuestionID)}, now)
	saved, err := h.store.UpsertQuestionnaireRun(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), saved.TenantID)
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(saved, false), GeneratedAt: now})
}

func (h *Handler) LinkVendor(w http.ResponseWriter, r *http.Request) {
	var request vendorLinkRequest
	if err := decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	record, _, err := h.runFromRequest(r.Context(), requestWithTenant(r, request.TenantID), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if !request.Unlink && strings.TrimSpace(request.VendorURN) == "" {
		h.writeError(w, fmt.Errorf("%w: vendor_urn is required", ErrInvalidRequest))
		return
	}
	now := time.Now().UTC()
	actorID := h.actorID(r.Context())
	updated := questionnairedomain.LinkVendor(*record, questionnairedomain.LinkVendorRequest{
		VendorURN: request.VendorURN,
		VendorID:  request.VendorID,
		Reason:    request.Reason,
		ActorID:   actorID,
		Unlink:    request.Unlink,
	}, now)
	summary := "Questionnaire linked to vendor"
	if request.Unlink {
		summary = "Questionnaire vendor link removed"
	}
	event := questionnairedomain.Event(updated, ports.QuestionnaireEventVendorLinked, actorID, summary, map[string]string{
		"vendor_urn": strings.TrimSpace(request.VendorURN),
		"vendor_id":  strings.TrimSpace(request.VendorID),
		"reason":     strings.TrimSpace(request.Reason),
		"unlink":     strconv.FormatBool(request.Unlink),
	}, now)
	saved, err := h.store.UpsertQuestionnaireRun(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), saved.TenantID)
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(saved, false), GeneratedAt: now})
}

func (h *Handler) DecideRun(w http.ResponseWriter, r *http.Request) {
	var request decisionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	record, _, err := h.runFromRequest(r.Context(), requestWithTenant(r, request.TenantID), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if request.Decision != nil {
		h.writeError(w, fmt.Errorf("%w: decision object is not accepted; use top-level fields", ErrInvalidRequest))
		return
	}
	decision := ports.QuestionnaireDecision{
		QuestionID: strings.TrimSpace(request.QuestionID),
		Decision:   strings.TrimSpace(request.State),
		Reason:     strings.TrimSpace(request.Reason),
		ActorID:    h.actorID(r.Context()),
	}
	if !ports.IsQuestionnaireDecision(decision.Decision) || decision.Decision == "" {
		h.writeError(w, fmt.Errorf("%w: decision must be approved, approved_with_conditions, rejected, or needs_input", ErrInvalidRequest))
		return
	}
	if err := validateQuestionReference(record, decision.QuestionID, false); err != nil {
		h.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	updated := questionnairedomain.RecordDecision(*record, decision, now)
	event := questionnairedomain.Event(updated, ports.QuestionnaireEventDecided, decision.ActorID, "Questionnaire decision recorded", map[string]string{"question_id": decision.QuestionID, "decision": decision.Decision}, now)
	saved, err := h.store.UpsertQuestionnaireRun(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), saved.TenantID)
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(saved, false), GeneratedAt: now})
}

func (h *Handler) CommentRun(w http.ResponseWriter, r *http.Request) {
	var request commentRequest
	if err := decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	record, _, err := h.runFromRequest(r.Context(), requestWithTenant(r, request.TenantID), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if request.Comment != nil {
		h.writeError(w, fmt.Errorf("%w: comment object is not accepted; use top-level fields", ErrInvalidRequest))
		return
	}
	comment := ports.QuestionnaireComment{
		QuestionID: strings.TrimSpace(request.QuestionID),
		ActorID:    h.actorID(r.Context()),
		Body:       strings.TrimSpace(request.Body),
	}
	if strings.TrimSpace(comment.Body) == "" {
		h.writeError(w, fmt.Errorf("%w: comment body is required", ErrInvalidRequest))
		return
	}
	if err := validateQuestionReference(record, comment.QuestionID, false); err != nil {
		h.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	updated := questionnairedomain.AddComment(*record, comment, h.actorID(r.Context()), now)
	event := questionnairedomain.Event(updated, ports.QuestionnaireEventCommented, comment.ActorID, "Questionnaire comment added", map[string]string{"question_id": comment.QuestionID}, now)
	saved, err := h.store.UpsertQuestionnaireRun(r.Context(), updated, event)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.bumpReviewCache(r.Context(), saved.TenantID)
	writeJSON(w, http.StatusOK, runResponse{Run: runViewFromRecord(saved, false), GeneratedAt: now})
}

func (h *Handler) resolveScope(r *http.Request) (Scope, error) {
	if h.scope == nil {
		return Scope{}, ErrRuntimeUnavailable
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

func (h *Handler) authorizeTenant(ctx context.Context, tenantID string) error {
	if h.authorize == nil {
		return nil
	}
	return h.authorize(ctx, tenantID)
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
	switch {
	case errors.Is(err, ErrInvalidRequest):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ports.ErrQuestionnaireRunNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, ErrRuntimeUnavailable):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) evidenceAnswers(r *http.Request, scope Scope) ([]evidencepackets.QuestionnaireAnswer, error) {
	if h.evidence == nil {
		return nil, nil
	}
	return h.evidence(r, scope)
}

func (h *Handler) runFromRequest(ctx context.Context, r *http.Request, tenantID string) (*ports.QuestionnaireRunRecord, []*ports.QuestionnaireRunEventRecord, error) {
	if h.store == nil {
		return nil, nil, ErrRuntimeUnavailable
	}
	scope, err := h.resolveScope(r)
	if err != nil {
		return nil, nil, err
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		scope.TenantID = tenantID
	}
	if err := h.authorizeTenant(ctx, scope.TenantID); err != nil {
		return nil, nil, err
	}
	runID := strings.TrimSpace(r.PathValue("runID"))
	if runID == "" {
		runID = strings.TrimSpace(r.URL.Query().Get("run_id"))
	}
	record, err := h.store.GetQuestionnaireRun(ctx, ports.QuestionnaireRunFilter{TenantID: scope.TenantID, RunID: runID, Limit: 1})
	if err != nil {
		return nil, nil, err
	}
	events, err := h.store.ListQuestionnaireRunEvents(ctx, ports.QuestionnaireRunEventFilter{TenantID: record.TenantID, RunID: record.RunID, Limit: scope.Limit})
	if err != nil {
		return nil, nil, err
	}
	return record, events, nil
}

func runViews(records []*ports.QuestionnaireRunRecord, compact bool) []runView {
	views := make([]runView, 0, len(records))
	for _, record := range records {
		views = append(views, runViewFromRecord(record, compact))
	}
	return views
}

func runViewFromRecord(record *ports.QuestionnaireRunRecord, compact bool) runView {
	if record == nil {
		return runView{}
	}
	view := runView{
		runViewIdentity: runViewIdentity{
			ID:        record.RunID,
			RunID:     record.RunID,
			TenantID:  record.TenantID,
			Title:     record.Title,
			Direction: record.Direction,
			CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt,
		},
		runViewParties: runViewParties{
			Requester:      record.Requester,
			CustomerName:   record.CustomerName,
			VendorURN:      record.VendorURN,
			VendorID:       record.VendorID,
			SourceFilename: record.SourceFilename,
			SourceFormat:   record.SourceFormat,
			OwnerID:        record.OwnerID,
			AssignedTeam:   record.AssignedTeam,
		},
		runViewWorkflow: runViewWorkflow{
			Status:         record.Status,
			Decision:       record.Decision,
			DecisionReason: record.DecisionReason,
			DueAt:          record.DueAt,
		},
		runViewCounts: runViewCounts{
			QuestionCount:        len(record.Questions),
			AnswerCount:          len(record.Answers),
			ReadyAnswerCount:     record.ReadyAnswerCount,
			BlockedAnswerCount:   record.BlockedAnswerCount,
			ReviewAnswerCount:    record.ReviewAnswerCount,
			MissingEvidenceCount: record.MissingEvidence,
			StaleEvidenceCount:   record.StaleEvidence,
			UnassignedCount:      record.UnassignedCount,
		},
		Attributes: record.Attributes,
	}
	if !compact {
		view.Questions = record.Questions
		view.Answers = record.Answers
		view.Assignments = record.Assignments
		view.Decisions = record.Decisions
		view.Comments = record.Comments
		view.Timeline = record.Timeline
	}
	return view
}

func runSummaryFromStore(summary ports.QuestionnaireRunSummary) runSummary {
	return runSummary{
		TotalRuns:       summary.TotalRuns,
		CustomerRuns:    summary.TotalRuns - summary.VendorRuns,
		VendorRuns:      summary.VendorRuns,
		DueRuns:         summary.DueRuns,
		BlockedAnswers:  summary.BlockedAnswers,
		ReviewAnswers:   summary.ReviewAnswers,
		ReadyAnswers:    summary.ReadyAnswers,
		StaleEvidence:   summary.StaleEvidence,
		MissingEvidence: summary.MissingEvidence,
		Unassigned:      summary.UnassignedQuestions,
	}
}

func summarizeViews(views []runView) runSummary {
	var summary runSummary
	summary.TotalRuns = len(views)
	now := time.Now().UTC()
	for _, view := range views {
		if view.Direction == ports.QuestionnaireDirectionVendorReview {
			summary.VendorRuns++
		} else {
			summary.CustomerRuns++
		}
		if view.DueAt != nil && !view.DueAt.After(now) && questionnaireStatusIsOpenWork(view.Status) {
			summary.DueRuns++
		}
		if questionnaireStatusIsOpenWork(view.Status) {
			summary.BlockedAnswers += view.BlockedAnswerCount
			summary.ReviewAnswers += view.ReviewAnswerCount
			summary.ReadyAnswers += view.ReadyAnswerCount
			summary.StaleEvidence += view.StaleEvidenceCount
			summary.MissingEvidence += view.MissingEvidenceCount
			summary.Unassigned += view.UnassignedCount
		}
	}
	return summary
}

func questionnaireStatusIsOpenWork(status string) bool {
	return status != ports.QuestionnaireStatusApproved && status != ports.QuestionnaireStatusRejected
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	return decodeJSONWithLimit(w, r, target, maxQuestionnaireBodyBytes)
}

func decodeJSONWithLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode questionnaire request: %w", ErrInvalidRequest, err)
	}
	return nil
}

func decodeJSONAllowEmpty(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxQuestionnaireBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("%w: decode questionnaire request: %w", ErrInvalidRequest, err)
	}
	return nil
}

func requestWithTenant(r *http.Request, tenantID string) *http.Request {
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

func requestWithRunScope(r *http.Request, tenantID string, sourceID string, runtimeID string, vendorURN string) *http.Request {
	values := map[string]string{
		"tenant_id":  tenantID,
		"source_id":  sourceID,
		"runtime_id": runtimeID,
		"vendor_urn": vendorURN,
	}
	clone := new(http.Request)
	*clone = *r
	clonedURL := *r.URL
	query := clonedURL.Query()
	changed := false
	for key, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			query.Del(key)
			changed = true
			continue
		}
		query.Set(key, value)
		changed = true
	}
	if !changed {
		return r
	}
	clonedURL.RawQuery = query.Encode()
	clone.URL = &clonedURL
	return clone
}

func validateQuestionReference(record *ports.QuestionnaireRunRecord, questionID string, required bool) error {
	questionID = strings.TrimSpace(questionID)
	if questionID == "" {
		if required {
			return fmt.Errorf("%w: question_id is required", ErrInvalidRequest)
		}
		return nil
	}
	for _, question := range record.Questions {
		if strings.TrimSpace(question.ID) == questionID {
			return nil
		}
	}
	return fmt.Errorf("%w: question_id %q does not exist on this run", ErrInvalidRequest, questionID)
}

func questionnaireRunStore(store ports.StateStore) ports.QuestionnaireRunStore {
	runStore, ok := store.(ports.QuestionnaireRunStore)
	if !ok || isNilInterface(runStore) {
		return nil
	}
	return runStore
}

func parseOptionalTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			parsed = parsed.UTC()
			return &parsed, nil
		}
	}
	return nil, fmt.Errorf("%w: due_at must be RFC3339 or YYYY-MM-DD", ErrInvalidRequest)
}

func questionsForCreate(request createRequest) ([]ports.QuestionnaireQuestion, error) {
	questions := append([]ports.QuestionnaireQuestion{}, request.Questions...)
	for _, row := range request.IntakeRows {
		questions = append(questions, questionFromIntakeRow(row))
	}
	if strings.TrimSpace(request.IntakeFile) != "" {
		parsed, err := parseIntakeAttachment(request)
		if err != nil {
			return nil, err
		}
		questions = append(questions, parsed...)
	}
	if strings.TrimSpace(request.IntakeText) != "" {
		parsed, err := parseIntakeText(request.IntakeText, firstNonEmpty(request.IntakeFormat, request.SourceFormat))
		if err != nil {
			return nil, err
		}
		questions = append(questions, parsed...)
	}
	return questionnairedomain.NormalizeQuestionsForIntake(questions), nil
}

func allowsPortalCaptureWithoutQuestions(request createRequest) bool {
	format := canonicalIntakeFormat(firstNonEmpty(request.IntakeFormat, request.SourceFormat))
	return format == "portal" && strings.TrimSpace(request.PortalURL) != ""
}

func parseIntakeText(value string, format string) ([]ports.QuestionnaireQuestion, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	switch format {
	case "json":
		return parseJSONIntake(trimmed)
	case "csv", "tsv":
		return parseDelimitedIntake(trimmed, format)
	case "portal":
		return parsePortalIntake(trimmed)
	case "pdf":
		return parsePDFPromptText(trimmed)
	case "xlsx", "xlsm":
		return nil, fmt.Errorf("%w: xlsx intake requires intake_file_base64", ErrInvalidRequest)
	case "", "text", "txt", "plain":
		return parsePlainTextIntake(trimmed), nil
	default:
		return nil, fmt.Errorf("%w: intake_format must be csv, tsv, json, text, portal, pdf, or xlsx", ErrInvalidRequest)
	}
}

func parseJSONIntake(value string) ([]ports.QuestionnaireQuestion, error) {
	var questions []ports.QuestionnaireQuestion
	if err := json.Unmarshal([]byte(value), &questions); err == nil {
		return questionnairedomain.NormalizeQuestionsForIntake(questions), nil
	}
	var rows []intakeRow
	if err := json.Unmarshal([]byte(value), &rows); err == nil {
		return questionsFromIntakeRows(rows), nil
	}
	var envelope struct {
		Questions  []ports.QuestionnaireQuestion `json:"questions"`
		IntakeRows []intakeRow                   `json:"intake_rows"`
		Rows       []intakeRow                   `json:"rows"`
	}
	if err := json.Unmarshal([]byte(value), &envelope); err != nil {
		return nil, fmt.Errorf("%w: intake_text JSON must be an array or contain questions", ErrInvalidRequest)
	}
	questions = append(questions, envelope.Questions...)
	questions = append(questions, questionsFromIntakeRows(envelope.IntakeRows)...)
	questions = append(questions, questionsFromIntakeRows(envelope.Rows)...)
	return questionnairedomain.NormalizeQuestionsForIntake(questions), nil
}

func parseDelimitedIntake(value string, format string) ([]ports.QuestionnaireQuestion, error) {
	reader := csv.NewReader(strings.NewReader(value))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	if format == "tsv" || strings.Count(value, "\t") > strings.Count(value, ",") {
		reader.Comma = '\t'
	}
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%w: parse questionnaire rows: %w", ErrInvalidRequest, err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	header := normalizedHeaders(records[0])
	questionIndex := headerIndex(header, "question", "question_text", "prompt")
	if questionIndex < 0 {
		return nil, fmt.Errorf("%w: %s intake must include a question column", ErrInvalidRequest, firstNonEmpty(format, "csv"))
	}
	rows := []intakeRow{}
	for _, record := range records[1:] {
		if questionIndex >= len(record) || strings.TrimSpace(record[questionIndex]) == "" {
			continue
		}
		rows = append(rows, intakeRow{
			ID:                   columnValue(record, header, "id", "question_id"),
			Question:             record[questionIndex],
			Section:              columnValue(record, header, "section", "category"),
			RequiredAnswerFormat: columnValue(record, header, "required_answer_format", "answer_format", "format"),
			MappedControls:       splitList(columnValue(record, header, "mapped_controls", "controls", "control_ids")),
			RequiredSlots:        splitList(columnValue(record, header, "required_evidence_slots", "evidence_slots", "slots")),
			OwnerID:              columnValue(record, header, "owner_id", "owner", "assignee"),
		})
	}
	return questionsFromIntakeRows(rows), nil
}

func parsePlainTextIntake(value string) []ports.QuestionnaireQuestion {
	rows := []intakeRow{}
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "- ")
		line = strings.TrimPrefix(line, "* ")
		if line == "" {
			continue
		}
		rows = append(rows, intakeRow{Question: line})
	}
	return questionsFromIntakeRows(rows)
}

func parsePortalIntake(value string) ([]ports.QuestionnaireQuestion, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	rows := []intakeRow{}
	section := ""
	for _, line := range strings.Split(trimmed, "\n") {
		line = normalizePortalQuestionLine(line)
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "?") && len(line) <= 80 {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		if !looksLikeQuestionnairePrompt(line) {
			continue
		}
		rows = append(rows, intakeRow{Question: line, Section: section})
	}
	return questionsFromIntakeRows(rows), nil
}

func questionsFromIntakeRows(rows []intakeRow) []ports.QuestionnaireQuestion {
	questions := make([]ports.QuestionnaireQuestion, 0, len(rows))
	for _, row := range rows {
		questions = append(questions, questionFromIntakeRow(row))
	}
	return questionnairedomain.NormalizeQuestionsForIntake(questions)
}

func questionFromIntakeRow(row intakeRow) ports.QuestionnaireQuestion {
	return ports.QuestionnaireQuestion{
		ID:                   row.ID,
		Question:             row.Question,
		Section:              row.Section,
		RequiredAnswerFormat: row.RequiredAnswerFormat,
		MappedControls:       row.MappedControls,
		RequiredSlots:        row.RequiredSlots,
		OwnerID:              row.OwnerID,
	}
}

func normalizedHeaders(record []string) []string {
	headers := make([]string, 0, len(record))
	for _, value := range record {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.ReplaceAll(value, " ", "_")
		value = strings.ReplaceAll(value, "-", "_")
		headers = append(headers, value)
	}
	return headers
}

func headerIndex(headers []string, names ...string) int {
	for _, name := range names {
		for index, header := range headers {
			if header == name {
				return index
			}
		}
	}
	return -1
}

func columnValue(record []string, headers []string, names ...string) string {
	index := headerIndex(headers, names...)
	if index < 0 || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func splitList(value string) []string {
	value = strings.NewReplacer("|", ",", ";", ",").Replace(value)
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result
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
