package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/ports"
)

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
	RunID        string                             `json:"run_id"`
	Chunks       []complianceassessment.ResultChunk `json:"chunks"`
	NextSequence uint32                             `json:"next_sequence,omitempty"`
	HasMore      bool                               `json:"has_more"`
}

func (a *App) handleCreateAssessmentPlan(w http.ResponseWriter, r *http.Request) {
	service := a.services.assessments
	if service == nil {
		writeAssessmentError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	var plan complianceassessment.AssessmentPlanRevision
	if err := decodeAssessmentJSON(w, r, &plan); err != nil {
		writeAssessmentError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), plan.TenantID)
	if err != nil {
		writeAssessmentError(w, err)
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
	plan, err = service.RecordPlan(r.Context(), plan, customDashboardActorID(r.Context()), 0)
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, assessmentPlanResponse{Plan: plan})
}

func (a *App) handleGetAssessmentPlan(w http.ResponseWriter, r *http.Request) {
	service := a.services.assessments
	if service == nil {
		writeAssessmentError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	plan, err := service.GetPlan(r.Context(), tenantID, r.PathValue("planID"))
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentPlanResponse{Plan: plan})
}

func (a *App) handlePublishAssessmentPlan(w http.ResponseWriter, r *http.Request) {
	service := a.services.assessments
	if service == nil {
		writeAssessmentError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	var request publishAssessmentPlanRequest
	if err := decodeAssessmentJSON(w, r, &request); err != nil {
		writeAssessmentError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	plan, err := service.PublishPlan(r.Context(), tenantID, r.PathValue("planID"), customDashboardActorID(r.Context()), request.ExpectedVersion)
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentPlanResponse{Plan: plan})
}

func (a *App) handleRequestAssessmentRun(w http.ResponseWriter, r *http.Request) {
	service := a.services.assessments
	if service == nil {
		writeAssessmentError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	var request requestAssessmentRunRequest
	if err := decodeAssessmentJSON(w, r, &request); err != nil {
		writeAssessmentError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		writeAssessmentError(w, fmt.Errorf("%w: Idempotency-Key header is required", complianceassessment.ErrInvalidResult))
		return
	}
	run, created, err := service.RequestRun(r.Context(), complianceassessment.RunRequest{
		TenantID: tenantID, PlanRevisionID: request.PlanRevisionID,
		PeriodStart: request.PeriodStart, PeriodEnd: request.PeriodEnd,
		BaselineRunID: request.BaselineRunID, IdempotencyKey: idempotencyKey,
		RequestedBy: customDashboardActorID(r.Context()),
	})
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, assessmentRunResponse{Run: newAssessmentRunView(run), Created: created})
}

func (a *App) handleGetAssessmentRun(w http.ResponseWriter, r *http.Request) {
	service := a.services.assessments
	if service == nil {
		writeAssessmentError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	run, err := service.GetRun(r.Context(), tenantID, r.PathValue("runID"))
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentRunResponse{Run: newAssessmentRunView(run)})
}

func (a *App) handleListAssessmentResults(w http.ResponseWriter, r *http.Request) {
	service := a.services.assessments
	if service == nil {
		writeAssessmentError(w, complianceassessment.ErrResultPagingUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	runID := strings.TrimSpace(r.PathValue("runID"))
	if _, err := service.GetRun(r.Context(), tenantID, runID); err != nil {
		writeAssessmentError(w, err)
		return
	}
	afterSequence, err := uint32QueryParam(r, "after_sequence")
	if err != nil {
		writeAssessmentError(w, fmt.Errorf("%w: after_sequence must be an unsigned integer", complianceassessment.ErrInvalidResult))
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeAssessmentError(w, fmt.Errorf("%w: limit must be an unsigned integer", complianceassessment.ErrInvalidResult))
		return
	}
	page, err := service.ListResultChunksPage(r.Context(), tenantID, runID, afterSequence, limit)
	if err != nil {
		writeAssessmentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentResultPageResponse{
		RunID: runID, Chunks: page.Chunks, NextSequence: page.NextSequence, HasMore: page.HasMore,
	})
}

func decodeAssessmentJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode assessment request: %v", complianceassessment.ErrInvalidResult, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: assessment request must contain one JSON object", complianceassessment.ErrInvalidResult)
	}
	return nil
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

func writeAssessmentError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
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
	http.Error(w, safeHTTPErrorMessage(status, err), status)
}
