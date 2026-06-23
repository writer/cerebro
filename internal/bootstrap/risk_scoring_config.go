package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

type riskScoringConfigRequest struct {
	TenantID        string                                   `json:"tenant_id"`
	Thresholds      ports.RiskScoringLevelThresholds         `json:"thresholds"`
	Signals         riskScoringSignalThresholdsRequest       `json:"signals"`
	RelationWeights map[string]int                           `json:"relation_weights"`
	FactorWeights   map[string]ports.RiskScoringFactorWeight `json:"factor_weights"`
}

type riskScoringSignalThresholdsRequest struct {
	EPSSHigh                    *float64 `json:"epss_high"`
	EPSSElevated                *float64 `json:"epss_elevated"`
	CVSSCritical                *float64 `json:"cvss_critical"`
	CVSSHigh                    *float64 `json:"cvss_high"`
	PrivateNetworkLikelihoodCap *int     `json:"private_network_likelihood_cap"`
}

type riskScoringConfigResponse struct {
	Config    riskScoringConfigView `json:"config"`
	Persisted bool                  `json:"persisted"`
}

type riskScoringConfigView struct {
	TenantID        string                                   `json:"tenant_id"`
	Thresholds      ports.RiskScoringLevelThresholds         `json:"thresholds"`
	Signals         ports.RiskScoringSignalThresholds        `json:"signals"`
	RelationWeights map[string]int                           `json:"relation_weights"`
	FactorWeights   map[string]ports.RiskScoringFactorWeight `json:"factor_weights"`
	ModelVersion    string                                   `json:"model_version"`
	CreatedAt       string                                   `json:"created_at,omitempty"`
	UpdatedAt       string                                   `json:"updated_at,omitempty"`
}

func (a *App) handleGetRiskScoringConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	if tenantID == "" {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: tenant_id is required", findings.ErrInvalidRequest))
		return
	}
	config, persisted, err := a.effectiveRiskScoringConfig(r.Context(), tenantID)
	if err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, riskScoringConfigResponse{Config: newRiskScoringConfigView(config, persisted), Persisted: persisted})
}

func (a *App) handlePutRiskScoringConfig(w http.ResponseWriter, r *http.Request) {
	store := riskScoringConfigStore(a.deps.StateStore)
	if store == nil {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: risk scoring config store is not configured", findings.ErrRuntimeUnavailable))
		return
	}
	var request riskScoringConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: decode risk scoring config: %w", findings.ErrInvalidRequest, err))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	if tenantID == "" {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: tenant_id is required", findings.ErrInvalidRequest))
		return
	}
	config, err := request.riskScoringConfig(tenantID)
	if err != nil {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: %w", findings.ErrInvalidRequest, err))
		return
	}
	if err := store.PutRiskScoringConfig(r.Context(), &config); err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	stored, err := store.GetRiskScoringConfig(r.Context(), tenantID)
	if err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	normalized, err := findings.NormalizeCompleteRiskScoringConfig(*stored)
	if err != nil {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: %w", findings.ErrInvalidRequest, err))
		return
	}
	writeJSON(w, http.StatusOK, riskScoringConfigResponse{Config: newRiskScoringConfigView(normalized, true), Persisted: true})
}

func (a *App) handleDeleteRiskScoringConfig(w http.ResponseWriter, r *http.Request) {
	store := riskScoringConfigStore(a.deps.StateStore)
	if store == nil {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: risk scoring config store is not configured", findings.ErrRuntimeUnavailable))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	if tenantID == "" {
		writeRiskScoringConfigError(w, fmt.Errorf("%w: tenant_id is required", findings.ErrInvalidRequest))
		return
	}
	if err := store.DeleteRiskScoringConfig(r.Context(), tenantID); err != nil {
		writeRiskScoringConfigError(w, err)
		return
	}
	config := findings.DefaultRiskScoringConfig(tenantID)
	writeJSON(w, http.StatusOK, riskScoringConfigResponse{Config: newRiskScoringConfigView(config, false), Persisted: false})
}

func (a *App) effectiveRiskScoringConfig(ctx context.Context, tenantID string) (ports.RiskScoringConfig, bool, error) {
	config := findings.DefaultRiskScoringConfig(tenantID)
	store := riskScoringConfigStore(a.deps.StateStore)
	if store == nil {
		return config, false, nil
	}
	stored, err := store.GetRiskScoringConfig(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ports.ErrRiskScoringConfigNotFound) {
			return config, false, nil
		}
		return ports.RiskScoringConfig{}, false, err
	}
	normalized, err := findings.NormalizeCompleteRiskScoringConfig(*stored)
	if err != nil {
		return ports.RiskScoringConfig{}, false, fmt.Errorf("%w: %w", findings.ErrInvalidRequest, err)
	}
	return normalized, true, nil
}

func newRiskScoringConfigView(config ports.RiskScoringConfig, persisted bool) riskScoringConfigView {
	modelVersion := findings.FindingRiskModelVersion
	if persisted {
		modelVersion = findings.RiskScoringConfigModelVersion(config)
	}
	view := riskScoringConfigView{
		TenantID:        strings.TrimSpace(config.TenantID),
		Thresholds:      config.Thresholds,
		Signals:         config.Signals,
		RelationWeights: config.RelationWeights,
		FactorWeights:   config.FactorWeights,
		ModelVersion:    modelVersion,
	}
	if !config.CreatedAt.IsZero() {
		view.CreatedAt = config.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !config.UpdatedAt.IsZero() {
		view.UpdatedAt = config.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return view
}

func (request riskScoringConfigRequest) riskScoringConfig(tenantID string) (ports.RiskScoringConfig, error) {
	config := findings.DefaultRiskScoringConfig(tenantID)
	if request.Thresholds.Critical != 0 {
		config.Thresholds.Critical = request.Thresholds.Critical
	}
	if request.Thresholds.High != 0 {
		config.Thresholds.High = request.Thresholds.High
	}
	if request.Thresholds.Medium != 0 {
		config.Thresholds.Medium = request.Thresholds.Medium
	}
	if request.Signals.EPSSHigh != nil {
		config.Signals.EPSSHigh = *request.Signals.EPSSHigh
	}
	if request.Signals.EPSSElevated != nil {
		config.Signals.EPSSElevated = *request.Signals.EPSSElevated
	}
	if request.Signals.CVSSCritical != nil {
		config.Signals.CVSSCritical = *request.Signals.CVSSCritical
	}
	if request.Signals.CVSSHigh != nil {
		config.Signals.CVSSHigh = *request.Signals.CVSSHigh
	}
	if request.Signals.PrivateNetworkLikelihoodCap != nil {
		config.Signals.PrivateNetworkLikelihoodCap = *request.Signals.PrivateNetworkLikelihoodCap
	}
	config.RelationWeights = request.RelationWeights
	config.FactorWeights = request.FactorWeights
	return findings.NormalizeCompleteRiskScoringConfig(config)
}

func riskScoringConfigStore(store ports.StateStore) ports.RiskScoringConfigStore {
	configStore, _ := store.(ports.RiskScoringConfigStore)
	return configStore
}

func writeRiskScoringConfigError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, findings.ErrInvalidRequest), errors.Is(err, errInvalidHTTPRequest):
		status = http.StatusBadRequest
	case errors.Is(err, errTenantForbidden):
		status = http.StatusForbidden
	case errors.Is(err, findings.ErrRuntimeUnavailable):
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]string{"error": safeHTTPErrorMessage(status, err)})
}
