package compliancemonitorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliancemonitor"
	"github.com/writer/cerebro/internal/ports"
)

const defaultMaxBodyBytes = int64(1 << 20)

type TenantResolver func(context.Context, string) (string, error)
type ActorResolver func(context.Context) string
type ForbiddenClassifier func(error) bool

type Handler struct {
	service       *compliancemonitor.Service
	resolveTenant TenantResolver
	actorID       ActorResolver
	isForbidden   ForbiddenClassifier
	maxBodyBytes  int64
}

func NewHandler(service *compliancemonitor.Service, resolveTenant TenantResolver, actorID ActorResolver, isForbidden ForbiddenClassifier, maxBodyBytes int64) *Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	return &Handler{service: service, resolveTenant: resolveTenant, actorID: actorID, isForbidden: isForbidden, maxBodyBytes: maxBodyBytes}
}

type monitorInput struct {
	TenantID                 string    `json:"tenant_id"`
	ProgramID                string    `json:"program_id"`
	PlanRevisionID           string    `json:"plan_revision_id"`
	TriggerKind              string    `json:"trigger_kind"`
	IntervalSeconds          int64     `json:"interval_seconds"`
	ExpectedCoverage         string    `json:"expected_coverage,omitempty"`
	MaximumEvidenceAgeSecond int64     `json:"maximum_evidence_age_seconds"`
	GracePeriodSeconds       int64     `json:"grace_period_seconds"`
	DebounceSeconds          int64     `json:"debounce_seconds"`
	EscalationOwner          string    `json:"escalation_owner,omitempty"`
	Enabled                  bool      `json:"enabled"`
	NextRunAt                time.Time `json:"next_run_at,omitempty"`
}

type updateMonitorRequest struct {
	ExpectedVersion uint64       `json:"expected_version"`
	Monitor         monitorInput `json:"monitor"`
}

type monitorView struct {
	ID                       string    `json:"id"`
	TenantID                 string    `json:"tenant_id"`
	ProgramID                string    `json:"program_id"`
	PlanRevisionID           string    `json:"plan_revision_id"`
	TriggerKind              string    `json:"trigger_kind"`
	IntervalSeconds          int64     `json:"interval_seconds"`
	ExpectedCoverage         string    `json:"expected_coverage,omitempty"`
	MaximumEvidenceAgeSecond int64     `json:"maximum_evidence_age_seconds"`
	GracePeriodSeconds       int64     `json:"grace_period_seconds"`
	DebounceSeconds          int64     `json:"debounce_seconds"`
	EscalationOwner          string    `json:"escalation_owner,omitempty"`
	Enabled                  bool      `json:"enabled"`
	Version                  uint64    `json:"version"`
	NextRunAt                time.Time `json:"next_run_at,omitempty"`
	LastSuccessAt            time.Time `json:"last_success_at,omitempty"`
	ConsecutiveFailures      uint32    `json:"consecutive_failures"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type monitorResponse struct {
	Monitor monitorView `json:"monitor"`
}

type monitorListResponse struct {
	Monitors []monitorView `json:"monitors"`
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var input monitorInput
	if err := h.decodeJSON(w, r, &input); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeMonitor(w, r, "", input, 0, http.StatusCreated)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var request updateMonitorRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeMonitor(w, r, r.PathValue("monitorID"), request.Monitor, request.ExpectedVersion, http.StatusOK)
}

func (h *Handler) writeMonitor(w http.ResponseWriter, r *http.Request, monitorID string, input monitorInput, expectedVersion uint64, status int) {
	if h == nil || h.service == nil {
		h.writeError(w, compliancemonitor.ErrServiceUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), input.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	maxSeconds := int64(math.MaxInt64 / int64(time.Second))
	if input.MaximumEvidenceAgeSecond < 0 || input.MaximumEvidenceAgeSecond > maxSeconds || input.GracePeriodSeconds < 0 || input.GracePeriodSeconds > maxSeconds || input.DebounceSeconds < 0 || input.DebounceSeconds > maxSeconds {
		h.writeError(w, errors.New("compliance monitor duration seconds are out of range"))
		return
	}
	monitor := &ports.ComplianceMonitor{
		ID: strings.TrimSpace(monitorID), TenantID: tenantID, ProgramID: input.ProgramID, PlanRevisionID: input.PlanRevisionID,
		TriggerKind: input.TriggerKind, IntervalSeconds: input.IntervalSeconds, ExpectedCoverage: input.ExpectedCoverage,
		MaximumEvidenceAge: time.Duration(input.MaximumEvidenceAgeSecond) * time.Second,
		GracePeriod:        time.Duration(input.GracePeriodSeconds) * time.Second, DebounceWindow: time.Duration(input.DebounceSeconds) * time.Second,
		EscalationOwner: input.EscalationOwner, Enabled: input.Enabled, NextRunAt: input.NextRunAt,
	}
	stored, err := h.service.UpdateMonitor(r.Context(), monitor, expectedVersion, h.actorID(r.Context()), time.Now().UTC())
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, status, monitorResponse{Monitor: newMonitorView(stored)})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		h.writeError(w, compliancemonitor.ErrServiceUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	monitor, err := h.service.GetMonitor(r.Context(), tenantID, r.PathValue("monitorID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, monitorResponse{Monitor: newMonitorView(monitor)})
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		h.writeError(w, compliancemonitor.ErrServiceUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	limit := uint64(100)
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err = strconv.ParseUint(raw, 10, 32)
		if err != nil || limit == 0 || limit > 500 {
			h.writeError(w, errors.New("compliance monitor limit must be between 1 and 500"))
			return
		}
	}
	monitors, err := h.service.ListMonitors(r.Context(), ports.ComplianceMonitorFilter{TenantID: tenantID, AfterID: r.URL.Query().Get("after_id"), Limit: uint32(limit)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	views := make([]monitorView, 0, len(monitors))
	for _, monitor := range monitors {
		if monitor != nil {
			views = append(views, newMonitorView(monitor))
		}
	}
	writeJSON(w, http.StatusOK, monitorListResponse{Monitors: views})
}

func newMonitorView(monitor *ports.ComplianceMonitor) monitorView {
	if monitor == nil {
		return monitorView{}
	}
	return monitorView{
		ID: monitor.ID, TenantID: monitor.TenantID, ProgramID: monitor.ProgramID, PlanRevisionID: monitor.PlanRevisionID,
		TriggerKind: monitor.TriggerKind, IntervalSeconds: monitor.IntervalSeconds, ExpectedCoverage: monitor.ExpectedCoverage,
		MaximumEvidenceAgeSecond: int64(monitor.MaximumEvidenceAge / time.Second), GracePeriodSeconds: int64(monitor.GracePeriod / time.Second),
		DebounceSeconds: int64(monitor.DebounceWindow / time.Second), EscalationOwner: monitor.EscalationOwner, Enabled: monitor.Enabled,
		Version: monitor.Version, NextRunAt: monitor.NextRunAt, LastSuccessAt: monitor.LastSuccessAt,
		ConsecutiveFailures: monitor.ConsecutiveFailures, CreatedAt: monitor.CreatedAt, UpdatedAt: monitor.UpdatedAt,
	}
}

func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode compliance monitor request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("compliance monitor request must contain one JSON object")
	}
	return nil
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case h != nil && h.isForbidden != nil && h.isForbidden(err):
		status = http.StatusForbidden
	case errors.Is(err, ports.ErrComplianceMonitorNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ports.ErrComplianceMonitorConflict), errors.Is(err, ports.ErrComplianceMonitorOverlap):
		status = http.StatusConflict
	case errors.Is(err, compliancemonitor.ErrServiceUnavailable):
		status = http.StatusServiceUnavailable
	case strings.Contains(err.Error(), "compliance monitor"), strings.Contains(err.Error(), "decode"):
		status = http.StatusBadRequest
	}
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = strings.ToLower(http.StatusText(status))
	}
	http.Error(w, message, status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
