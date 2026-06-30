package questionnaire

import (
	"context"
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
	ID                   string                          `json:"id"`
	RunID                string                          `json:"run_id"`
	TenantID             string                          `json:"tenant_id,omitempty"`
	Title                string                          `json:"title"`
	Direction            string                          `json:"direction"`
	Requester            string                          `json:"requester,omitempty"`
	CustomerName         string                          `json:"customer_name,omitempty"`
	VendorURN            string                          `json:"vendor_urn,omitempty"`
	VendorID             string                          `json:"vendor_id,omitempty"`
	SourceFilename       string                          `json:"source_filename,omitempty"`
	SourceFormat         string                          `json:"source_format,omitempty"`
	Status               string                          `json:"status"`
	OwnerID              string                          `json:"owner_id,omitempty"`
	AssignedTeam         string                          `json:"assigned_team,omitempty"`
	Decision             string                          `json:"decision,omitempty"`
	DecisionReason       string                          `json:"decision_reason,omitempty"`
	DueAt                *time.Time                      `json:"due_at,omitempty"`
	CreatedAt            time.Time                       `json:"created_at"`
	UpdatedAt            time.Time                       `json:"updated_at"`
	QuestionCount        int                             `json:"question_count"`
	AnswerCount          int                             `json:"answer_count"`
	ReadyAnswerCount     int                             `json:"ready_answer_count"`
	BlockedAnswerCount   int                             `json:"blocked_answer_count"`
	ReviewAnswerCount    int                             `json:"review_answer_count"`
	MissingEvidenceCount int                             `json:"missing_evidence_count"`
	StaleEvidenceCount   int                             `json:"stale_evidence_count"`
	UnassignedCount      int                             `json:"unassigned_count"`
	Questions            []ports.QuestionnaireQuestion   `json:"questions,omitempty"`
	Answers              []ports.QuestionnaireRunAnswer  `json:"answers,omitempty"`
	Assignments          []ports.QuestionnaireAssignment `json:"assignments,omitempty"`
	Decisions            []ports.QuestionnaireDecision   `json:"decisions,omitempty"`
	Comments             []ports.QuestionnaireComment    `json:"comments,omitempty"`
	Timeline             []ports.QuestionnaireTimeline   `json:"timeline,omitempty"`
	Attributes           map[string]string               `json:"attributes,omitempty"`
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
	Attributes     map[string]string             `json:"attributes,omitempty"`
}

type assignmentRequest struct {
	TenantID   string                        `json:"tenant_id,omitempty"`
	Assignment ports.QuestionnaireAssignment `json:"assignment"`
	QuestionID string                        `json:"question_id,omitempty"`
	OwnerID    string                        `json:"owner_id,omitempty"`
	Owner      string                        `json:"owner,omitempty"`
	Team       string                        `json:"team,omitempty"`
	Status     string                        `json:"status,omitempty"`
	DueAt      string                        `json:"due_at,omitempty"`
	Reason     string                        `json:"reason,omitempty"`
}

type decisionRequest struct {
	TenantID   string                      `json:"tenant_id,omitempty"`
	Decision   ports.QuestionnaireDecision `json:"decision"`
	QuestionID string                      `json:"question_id,omitempty"`
	ActorID    string                      `json:"actor_id,omitempty"`
	State      string                      `json:"state,omitempty"`
	Reason     string                      `json:"reason,omitempty"`
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
	records, err := h.store.ListQuestionnaireRuns(r.Context(), ports.QuestionnaireRunFilter{
		TenantID:  scope.TenantID,
		Direction: strings.TrimSpace(r.URL.Query().Get("direction")),
		Status:    strings.TrimSpace(r.URL.Query().Get("status")),
		VendorURN: strings.TrimSpace(r.URL.Query().Get("vendor_urn")),
		Requester: strings.TrimSpace(r.URL.Query().Get("requester")),
		Customer:  strings.TrimSpace(r.URL.Query().Get("customer_name")),
		OwnerID:   strings.TrimSpace(r.URL.Query().Get("owner_id")),
		Query:     strings.TrimSpace(r.URL.Query().Get("q")),
		Limit:     scope.Limit,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	views := runViews(records, true)
	writeJSON(w, http.StatusOK, runsResponse{Summary: summarizeViews(views), Runs: views, GeneratedAt: time.Now().UTC()})
}

func (h *Handler) CreateRun(w http.ResponseWriter, r *http.Request) {
	var request createRequest
	if err := decodeJSON(w, r, &request); err != nil {
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
	if len(questionnairedomain.NormalizeQuestionsForIntake(request.Questions)) == 0 {
		h.writeError(w, fmt.Errorf("%w: at least one question is required", ErrInvalidRequest))
		return
	}
	dueAt, err := parseOptionalTime(request.DueAt)
	if err != nil {
		h.writeError(w, err)
		return
	}
	now := time.Now().UTC()
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
		UploadID:       request.UploadID,
		SourceFilename: request.SourceFilename,
		SourceFormat:   request.SourceFormat,
		OwnerID:        request.OwnerID,
		AssignedTeam:   request.AssignedTeam,
		DueAt:          dueAt,
		Questions:      request.Questions,
		Attributes:     request.Attributes,
	}, now)
	event := questionnairedomain.Event(record, ports.QuestionnaireEventCreated, h.actorID(r.Context()), "Questionnaire run created", map[string]string{"direction": record.Direction}, now)
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
	scope, err := h.resolveScope(requestWithTenant(r, firstNonEmpty(request.TenantID, record.TenantID)))
	if err != nil {
		h.writeError(w, err)
		return
	}
	answers, err := h.evidenceAnswers(r, scope)
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
	assignment := request.Assignment
	assignment.QuestionID = firstNonEmpty(assignment.QuestionID, request.QuestionID)
	assignment.OwnerID = firstNonEmpty(assignment.OwnerID, request.OwnerID, request.Owner)
	assignment.Team = firstNonEmpty(assignment.Team, request.Team)
	assignment.Status = firstNonEmpty(assignment.Status, request.Status, "open")
	assignment.Reason = firstNonEmpty(assignment.Reason, request.Reason)
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
	decision := request.Decision
	decision.QuestionID = firstNonEmpty(decision.QuestionID, request.QuestionID)
	decision.Decision = firstNonEmpty(decision.Decision, request.State)
	decision.Reason = firstNonEmpty(decision.Reason, request.Reason)
	decision.ActorID = h.actorID(r.Context())
	if !ports.IsQuestionnaireDecision(decision.Decision) || decision.Decision == "" {
		h.writeError(w, fmt.Errorf("%w: decision must be approved, approved_with_conditions, rejected, or needs_input", ErrInvalidRequest))
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
	http.Error(w, err.Error(), http.StatusInternalServerError)
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
		ID:                   record.RunID,
		RunID:                record.RunID,
		TenantID:             record.TenantID,
		Title:                record.Title,
		Direction:            record.Direction,
		Requester:            record.Requester,
		CustomerName:         record.CustomerName,
		VendorURN:            record.VendorURN,
		VendorID:             record.VendorID,
		SourceFilename:       record.SourceFilename,
		SourceFormat:         record.SourceFormat,
		Status:               record.Status,
		OwnerID:              record.OwnerID,
		AssignedTeam:         record.AssignedTeam,
		Decision:             record.Decision,
		DecisionReason:       record.DecisionReason,
		DueAt:                record.DueAt,
		CreatedAt:            record.CreatedAt,
		UpdatedAt:            record.UpdatedAt,
		QuestionCount:        len(record.Questions),
		AnswerCount:          len(record.Answers),
		ReadyAnswerCount:     record.ReadyAnswerCount,
		BlockedAnswerCount:   record.BlockedAnswerCount,
		ReviewAnswerCount:    record.ReviewAnswerCount,
		MissingEvidenceCount: record.MissingEvidence,
		StaleEvidenceCount:   record.StaleEvidence,
		UnassignedCount:      record.UnassignedCount,
		Attributes:           record.Attributes,
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
		if view.DueAt != nil && !view.DueAt.After(now) && view.Status != ports.QuestionnaireStatusApproved {
			summary.DueRuns++
		}
		summary.BlockedAnswers += view.BlockedAnswerCount
		summary.ReviewAnswers += view.ReviewAnswerCount
		summary.ReadyAnswers += view.ReadyAnswerCount
		summary.StaleEvidence += view.StaleEvidenceCount
		summary.MissingEvidence += view.MissingEvidenceCount
		summary.Unassigned += view.UnassignedCount
	}
	return summary
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxQuestionnaireBodyBytes))
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
