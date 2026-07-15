package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceremediation"
)

const maxComplianceRemediationBodyBytes = 128 << 10

type remediationPlanCreateRequest struct {
	ID                   string                                           `json:"id"`
	TenantID             string                                           `json:"tenant_id"`
	ProgramID            string                                           `json:"program_id"`
	ScopeRevisionID      string                                           `json:"scope_revision_id"`
	RiskID               string                                           `json:"risk_id"`
	WorkItemID           string                                           `json:"work_item_id"`
	Treatment            complianceassessment.RiskTreatment               `json:"treatment"`
	OwnerID              string                                           `json:"owner_id"`
	TargetAt             time.Time                                        `json:"target_at"`
	CompensatingControls []string                                         `json:"compensating_controls,omitempty"`
	RetestRequired       bool                                             `json:"retest_required"`
	Milestones           []complianceassessment.RemediationMilestoneInput `json:"milestones"`
}

func (a *App) remediationService() *complianceremediation.Service {
	if a == nil {
		return nil
	}
	return a.services.remediation
}

func (a *App) handleDeriveComplianceWork(w http.ResponseWriter, r *http.Request) {
	service := a.remediationService()
	if service == nil {
		writeComplianceRemediationError(w, complianceremediation.ErrUnavailable)
		return
	}
	var request complianceremediation.DeriveWorkInput
	if err := decodeComplianceRemediationRequest(w, r, &request); err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	request.TenantID = tenantID
	record, err := service.DeriveWork(r.Context(), request, customDashboardActorID(r.Context()))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (a *App) handleGetComplianceWorkItem(w http.ResponseWriter, r *http.Request) {
	service := a.remediationService()
	if service == nil {
		writeComplianceRemediationError(w, complianceremediation.ErrUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	record, err := service.GetWorkItem(r.Context(), tenantID, r.PathValue("workItemID"))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *App) handleComplianceWorkCommand(w http.ResponseWriter, r *http.Request) {
	service := a.remediationService()
	if service == nil {
		writeComplianceRemediationError(w, complianceremediation.ErrUnavailable)
		return
	}
	var command complianceremediation.WorkCommand
	if err := decodeComplianceRemediationRequest(w, r, &command); err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	command.ActorID = customDashboardActorID(r.Context())
	record, err := service.ApplyWorkCommand(r.Context(), tenantID, r.PathValue("workItemID"), command)
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *App) handleCreateComplianceRemediationPlan(w http.ResponseWriter, r *http.Request) {
	service := a.remediationService()
	if service == nil {
		writeComplianceRemediationError(w, complianceremediation.ErrUnavailable)
		return
	}
	var request remediationPlanCreateRequest
	if err := decodeComplianceRemediationRequest(w, r, &request); err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	plan, err := service.CreateRemediationPlan(r.Context(), complianceassessment.RemediationPlanInput{
		ID: request.ID, TenantID: tenantID, ProgramID: request.ProgramID, ScopeRevisionID: request.ScopeRevisionID,
		RiskID: request.RiskID, WorkItemID: request.WorkItemID, Treatment: request.Treatment,
		OwnerID: request.OwnerID, TargetAt: request.TargetAt, CompensatingControls: request.CompensatingControls,
		RetestRequired: request.RetestRequired, Milestones: request.Milestones,
	}, customDashboardActorID(r.Context()))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, plan)
}

func (a *App) handleGetComplianceRemediationPlan(w http.ResponseWriter, r *http.Request) {
	service := a.remediationService()
	if service == nil {
		writeComplianceRemediationError(w, complianceremediation.ErrUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	plan, err := service.GetRemediationPlan(r.Context(), tenantID, r.PathValue("planID"))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *App) handleComplianceRemediationCommand(w http.ResponseWriter, r *http.Request) {
	service := a.remediationService()
	if service == nil {
		writeComplianceRemediationError(w, complianceremediation.ErrUnavailable)
		return
	}
	var command complianceremediation.RemediationCommand
	if err := decodeComplianceRemediationRequest(w, r, &command); err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	command.ActorID = customDashboardActorID(r.Context())
	plan, err := service.ApplyRemediationCommand(r.Context(), tenantID, r.PathValue("planID"), command)
	if err != nil {
		writeComplianceRemediationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func decodeComplianceRemediationRequest(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxComplianceRemediationBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode request: %w", complianceremediation.ErrInvalidRequest, err)
	}
	return nil
}

func writeComplianceRemediationError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		status = http.StatusForbidden
	case errors.Is(err, complianceremediation.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, complianceremediation.ErrUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, complianceassessment.ErrVersionConflict):
		status = http.StatusConflict
	case errors.Is(err, complianceremediation.ErrInvalidRequest),
		errors.Is(err, complianceassessment.ErrInvalidWorkItem),
		errors.Is(err, complianceassessment.ErrInvalidRemediation),
		errors.Is(err, complianceassessment.ErrInvalidResult),
		errors.Is(err, complianceassessment.ErrInvalidTransition),
		errors.Is(err, complianceassessment.ErrIndependentReview):
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]string{"error": strings.ToLower(strings.ReplaceAll(http.StatusText(status), " ", "_"))})
}
