package complianceassessmenthttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/ports"
)

const defaultMaxBodyBytes = int64(1 << 20)

type TenantResolver func(context.Context, string) (string, error)
type ActorResolver func(context.Context) string
type ForbiddenClassifier func(error) bool

type Handler struct {
	service       *complianceassessment.Service
	resolveTenant TenantResolver
	actorID       ActorResolver
	isForbidden   ForbiddenClassifier
	maxBodyBytes  int64
}

func NewHandler(service *complianceassessment.Service, resolveTenant TenantResolver, actorID ActorResolver, isForbidden ForbiddenClassifier, maxBodyBytes int64) *Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	return &Handler{service: service, resolveTenant: resolveTenant, actorID: actorID, isForbidden: isForbidden, maxBodyBytes: maxBodyBytes}
}

type assessmentPlanResponse struct {
	Plan complianceassessment.AssessmentPlanRevision `json:"plan"`
}

type publishAssessmentPlanRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
}

type requestAssessmentRunRequest struct {
	TenantID       string    `json:"tenant_id"`
	PlanRevisionID string    `json:"plan_revision_id"`
	PeriodStart    time.Time `json:"period_start"`
	PeriodEnd      time.Time `json:"period_end"`
	BaselineRunID  string    `json:"baseline_run_id,omitempty"`
}

type assessmentRunView struct {
	ID                  string                              `json:"id"`
	TenantID            string                              `json:"tenant_id"`
	ProgramID           string                              `json:"program_id"`
	ScopeRevisionID     string                              `json:"scope_revision_id"`
	PlanRevisionID      string                              `json:"plan_revision_id"`
	State               string                              `json:"state"`
	Version             uint64                              `json:"version"`
	PeriodStart         time.Time                           `json:"period_start"`
	PeriodEnd           time.Time                           `json:"period_end"`
	RequestedAt         time.Time                           `json:"requested_at"`
	RequestedBy         string                              `json:"requested_by"`
	JobID               string                              `json:"job_id,omitempty"`
	BaselineRunID       string                              `json:"baseline_run_id,omitempty"`
	InputManifest       *complianceassessment.InputManifest `json:"input_manifest,omitempty"`
	InputHash           string                              `json:"input_hash,omitempty"`
	AutomatedResultHash string                              `json:"automated_result_hash,omitempty"`
	ResultCount         uint64                              `json:"result_count,omitempty"`
	FailureCode         string                              `json:"failure_code,omitempty"`
	CollectionBarrierAt time.Time                           `json:"collection_barrier_at,omitempty"`
	CompletedAt         time.Time                           `json:"completed_at,omitempty"`
}

type assessmentRunResponse struct {
	Run     assessmentRunView `json:"run"`
	Created bool              `json:"created"`
}

type assessmentResultPageResponse struct {
	RunID               string                             `json:"run_id"`
	State               string                             `json:"state"`
	ResultCount         uint64                             `json:"result_count"`
	AutomatedResultHash string                             `json:"automated_result_hash"`
	Chunks              []complianceassessment.ResultChunk `json:"chunks"`
	NextSequence        uint32                             `json:"next_sequence,omitempty"`
	HasMore             bool                               `json:"has_more"`
}

func (h *Handler) CreatePlan(w http.ResponseWriter, r *http.Request) {
	service := h.service
	if service == nil {
		h.writeError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	var plan complianceassessment.AssessmentPlanRevision
	if err := h.decodeJSON(w, r, &plan); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), plan.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	plan.ID = ""
	plan.TenantID = tenantID
	plan.RevisionID = ""
	plan.Version = 0
	plan.PredecessorID = ""
	plan.Status = complianceassessment.PlanDraft
	plan.ContentDigest = ""
	plan.CreatedAt = time.Time{}
	plan.CreatedBy = ""
	plan.PublishedAt = time.Time{}
	plan.PublishedBy = ""
	if err := validateExecutablePlan(plan); err != nil {
		h.writeError(w, err)
		return
	}
	plan, err = service.RecordPlan(r.Context(), plan, h.actorID(r.Context()), 0)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, assessmentPlanResponse{Plan: plan})
}

func (h *Handler) GetPlan(w http.ResponseWriter, r *http.Request) {
	service := h.service
	if service == nil {
		h.writeError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	plan, err := service.GetPlan(r.Context(), tenantID, r.PathValue("planID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentPlanResponse{Plan: plan})
}

func (h *Handler) PublishPlan(w http.ResponseWriter, r *http.Request) {
	service := h.service
	if service == nil {
		h.writeError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	var request publishAssessmentPlanRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	draft, err := service.GetPlan(r.Context(), tenantID, r.PathValue("planID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := validateExecutablePlan(draft); err != nil {
		h.writeError(w, err)
		return
	}
	plan, err := service.PublishPlan(r.Context(), tenantID, r.PathValue("planID"), h.actorID(r.Context()), request.ExpectedVersion)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentPlanResponse{Plan: plan})
}

func (h *Handler) RequestRun(w http.ResponseWriter, r *http.Request) {
	service := h.service
	if service == nil {
		h.writeError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	var request requestAssessmentRunRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		h.writeError(w, fmt.Errorf("%w: Idempotency-Key header is required", complianceassessment.ErrInvalidResult))
		return
	}
	plan, err := service.GetPlan(r.Context(), tenantID, request.PlanRevisionID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := validateExecutablePlan(plan); err != nil {
		h.writeError(w, err)
		return
	}
	run, created, err := service.RequestRun(r.Context(), complianceassessment.RunRequest{
		TenantID: tenantID, PlanRevisionID: request.PlanRevisionID,
		PeriodStart: request.PeriodStart, PeriodEnd: request.PeriodEnd,
		BaselineRunID: request.BaselineRunID, IdempotencyKey: idempotencyKey,
		RequestedBy: h.actorID(r.Context()),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, assessmentRunResponse{Run: newAssessmentRunView(run), Created: created})
}

func (h *Handler) GetRun(w http.ResponseWriter, r *http.Request) {
	service := h.service
	if service == nil {
		h.writeError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	run, err := service.GetRun(r.Context(), tenantID, r.PathValue("runID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentRunResponse{Run: newAssessmentRunView(run)})
}

func (h *Handler) ListResults(w http.ResponseWriter, r *http.Request) {
	service := h.service
	if service == nil {
		h.writeError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	runID := strings.TrimSpace(r.PathValue("runID"))
	run, err := service.GetRun(r.Context(), tenantID, runID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if run.State != complianceassessment.RunComplete {
		h.writeError(w, fmt.Errorf("%w: assessment results are available only when the run is complete", complianceassessment.ErrAssessmentConflict))
		return
	}
	afterSequence, err := uint32QueryParam(r, "after_sequence")
	if err != nil {
		h.writeError(w, fmt.Errorf("%w: after_sequence must be an unsigned integer", complianceassessment.ErrInvalidResult))
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		h.writeError(w, fmt.Errorf("%w: limit must be an unsigned integer", complianceassessment.ErrInvalidResult))
		return
	}
	page, err := service.ListResultChunksPage(r.Context(), tenantID, runID, afterSequence, limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentResultPageResponse{
		RunID: runID, State: run.State, ResultCount: run.ResultCount, AutomatedResultHash: run.AutomatedResultHash,
		Chunks: page.Chunks, NextSequence: page.NextSequence, HasMore: page.HasMore,
	})
}

func validateExecutablePlan(plan complianceassessment.AssessmentPlanRevision) error {
	for _, task := range plan.Execution.Tasks {
		if task.Kind != complianceassessment.PlanTaskKindFindingEvaluation {
			return fmt.Errorf("%w: assessment task %q uses unsupported kind %q", complianceassessment.ErrInvalidResult, task.ID, task.Kind)
		}
	}
	return nil
}

func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode assessment request: %v", complianceassessment.ErrInvalidResult, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: assessment request must contain one JSON object", complianceassessment.ErrInvalidResult)
	}
	return nil
}

func uint32QueryParam(r *http.Request, key string) (uint32, error) {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newAssessmentRunView(run complianceassessment.AssessmentRun) assessmentRunView {
	return assessmentRunView{
		ID: run.ID, TenantID: run.TenantID, ProgramID: run.ProgramID,
		ScopeRevisionID: run.ScopeRevisionID, PlanRevisionID: run.PlanRevisionID,
		State: run.State, Version: run.Version, PeriodStart: run.PeriodStart, PeriodEnd: run.PeriodEnd,
		RequestedAt: run.RequestedAt, RequestedBy: run.RequestedBy, JobID: run.JobID,
		BaselineRunID: run.BaselineRunID, InputManifest: run.InputManifest, InputHash: run.InputHash,
		AutomatedResultHash: run.AutomatedResultHash, ResultCount: run.ResultCount,
		FailureCode: run.FailureCode, CollectionBarrierAt: run.CollectionBarrierAt, CompletedAt: run.CompletedAt,
	}
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case h.isForbidden != nil && h.isForbidden(err):
		status = http.StatusForbidden
	case errors.Is(err, complianceassessment.ErrPlanNotFound), errors.Is(err, complianceassessment.ErrRunNotFound):
		status = http.StatusNotFound
	case errors.Is(err, complianceassessment.ErrAssessmentConflict), errors.Is(err, ports.ErrJobIdempotencyConflict):
		status = http.StatusConflict
	case errors.Is(err, complianceassessment.ErrResultPagingUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, complianceassessment.ErrInvalidResult), errors.Is(err, complianceassessment.ErrInvalidManifest), errors.Is(err, complianceassessment.ErrIncompleteInput):
		status = http.StatusBadRequest
	}
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = strings.ToLower(http.StatusText(status))
	}
	http.Error(w, message, status)
}
