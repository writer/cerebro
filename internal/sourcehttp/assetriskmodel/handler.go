// Package assetriskmodel serves the tenant asset risk model and the attack
// paths it scores.
package assetriskmodel

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

	"github.com/writer/cerebro/internal/assetrisk"
	"github.com/writer/cerebro/internal/ports"
)

const maxBodyBytes = 128 << 10

var (
	errInvalidRequest   = errors.New("invalid asset risk request")
	errStoreUnavailable = errors.New("asset risk model store is not configured")
	errTenantForbidden  = errors.New("tenant access denied")
)

// TenantResolver returns the authorized tenant for a requested tenant ID.
// Any error it returns is treated as an authorization failure.
type TenantResolver func(context.Context, string) (string, error)

// Handler serves the model and path scoring routes.
type Handler struct {
	store   ports.AssetRiskModelStore
	graph   assetrisk.Graph
	resolve TenantResolver
}

// NewHandler builds a handler from optional StateStore and graph capabilities.
func NewHandler(store ports.StateStore, graph ports.EntityCatalogStore, resolve TenantResolver) Handler {
	modelStore, _ := store.(ports.AssetRiskModelStore)
	handler := Handler{store: modelStore, resolve: resolve}
	if graph != nil {
		handler.graph = graph
	}
	return handler
}

// ModelResponse is the wire shape for model reads and writes.
type ModelResponse struct {
	Model     ModelView `json:"model"`
	Persisted bool      `json:"persisted"`
}

// ModelView is one tenant's effective model.
type ModelView struct {
	TenantID        string                             `json:"tenant_id"`
	AssetValue      ports.AssetRiskValueModel          `json:"asset_value"`
	Vulnerability   ports.AssetRiskVulnerabilityModel  `json:"vulnerability"`
	Exposure        ports.AssetRiskExposureModel       `json:"exposure"`
	Countermeasures []ports.AssetRiskCountermeasure    `json:"countermeasures"`
	Relations       map[string]ports.AssetRiskRelation `json:"relations"`
	Traversal       ports.AssetRiskTraversal           `json:"traversal"`
	Thresholds      ports.RiskScoringLevelThresholds   `json:"thresholds"`
	ModelVersion    string                             `json:"model_version"`
	CreatedAt       string                             `json:"created_at,omitempty"`
	UpdatedAt       string                             `json:"updated_at,omitempty"`
}

// PathsResponse is the scored attack surface from one root.
type PathsResponse struct {
	ModelVersion string `json:"model_version"`
	*assetrisk.PathResult
}

// GetModel returns the saved model or the built-in model.
func (h Handler) GetModel(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	model, persisted, err := h.effective(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ModelResponse{Model: newModelView(model, persisted), Persisted: persisted})
}

// PutModel validates and saves a tenant model. Sections omitted from the body
// keep their built-in defaults.
func (h Handler) PutModel(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, errStoreUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, maxBodyBytes), maxBodyBytes+1))
	if err != nil {
		writeError(w, fmt.Errorf("%w: read asset risk model: %w", errInvalidRequest, err))
		return
	}
	var envelope struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		writeError(w, fmt.Errorf("%w: decode asset risk model: %w", errInvalidRequest, err))
		return
	}
	tenantID, err := h.tenant(r.Context(), envelope.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	model, err := assetrisk.DecodeModel(tenantID, body)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.PutAssetRiskModel(r.Context(), &model); err != nil {
		writeError(w, err)
		return
	}
	stored, persisted, err := h.effective(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ModelResponse{Model: newModelView(stored, persisted), Persisted: persisted})
}

// DeleteModel removes the tenant model so the built-in model applies.
func (h Handler) DeleteModel(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, errStoreUnavailable)
		return
	}
	tenantID, err := h.tenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.DeleteAssetRiskModel(r.Context(), tenantID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ModelResponse{Model: newModelView(assetrisk.DefaultModel(tenantID), false), Persisted: false})
}

// GetPaths scores the riskiest attack paths from one root entity.
func (h Handler) GetPaths(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	tenantID, err := h.tenant(r.Context(), query.Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	request := assetrisk.PathRequest{TenantID: tenantID, RootURN: strings.TrimSpace(query.Get("root_urn"))}
	if request.RootURN == "" {
		writeError(w, fmt.Errorf("%w: root_urn is required", errInvalidRequest))
		return
	}
	if request.AssumeCompromised, err = optionalBool(query.Get("assume_compromised")); err != nil {
		writeError(w, err)
		return
	}
	if request.MaxDepth, err = optionalPositiveInt(query.Get("max_depth"), "max_depth"); err != nil {
		writeError(w, err)
		return
	}
	if request.Limit, err = optionalPositiveInt(query.Get("limit"), "limit"); err != nil {
		writeError(w, err)
		return
	}
	model, persisted, err := h.effective(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := assetrisk.ScorePaths(r.Context(), h.graph, model, request)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, PathsResponse{ModelVersion: assetrisk.Version(model, persisted), PathResult: result})
}

func (h Handler) effective(ctx context.Context, tenantID string) (ports.AssetRiskModel, bool, error) {
	defaults := assetrisk.DefaultModel(tenantID)
	if h.store == nil {
		return defaults, false, nil
	}
	stored, err := h.store.GetAssetRiskModel(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ports.ErrAssetRiskModelNotFound) {
			return defaults, false, nil
		}
		return ports.AssetRiskModel{}, false, err
	}
	model, err := assetrisk.NormalizeModel(*stored)
	if err != nil {
		return ports.AssetRiskModel{}, false, err
	}
	return model, true, nil
}

func (h Handler) tenant(ctx context.Context, requested string) (string, error) {
	tenantID := strings.TrimSpace(requested)
	if h.resolve != nil {
		resolved, err := h.resolve(ctx, requested)
		if err != nil {
			return "", fmt.Errorf("%w: %w", errTenantForbidden, err)
		}
		tenantID = strings.TrimSpace(resolved)
	}
	if tenantID == "" {
		return "", fmt.Errorf("%w: tenant_id is required", errInvalidRequest)
	}
	return tenantID, nil
}

func newModelView(model ports.AssetRiskModel, persisted bool) ModelView {
	view := ModelView{
		TenantID:        strings.TrimSpace(model.TenantID),
		AssetValue:      model.AssetValue,
		Vulnerability:   model.Vulnerability,
		Exposure:        model.Exposure,
		Countermeasures: model.Countermeasures,
		Relations:       model.Relations,
		Traversal:       model.Traversal,
		Thresholds:      model.Thresholds,
		ModelVersion:    assetrisk.Version(model, persisted),
	}
	if view.Countermeasures == nil {
		view.Countermeasures = []ports.AssetRiskCountermeasure{}
	}
	if !model.CreatedAt.IsZero() {
		view.CreatedAt = model.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !model.UpdatedAt.IsZero() {
		view.UpdatedAt = model.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return view
}

func optionalBool(raw string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: assume_compromised must be true or false", errInvalidRequest)
	}
	return value, nil
}

func optionalPositiveInt(raw string, name string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%w: %s must be a positive integer", errInvalidRequest, name)
	}
	return value, nil
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "internal server error"
	switch {
	case errors.Is(err, errInvalidRequest), errors.Is(err, assetrisk.ErrInvalidModel), errors.Is(err, assetrisk.ErrInvalidPathRequest):
		status = http.StatusBadRequest
		message = err.Error()
	case errors.Is(err, errTenantForbidden):
		status = http.StatusForbidden
		message = "tenant access denied"
	case errors.Is(err, assetrisk.ErrRootNotFound):
		status = http.StatusNotFound
		message = "root entity not found"
	case errors.Is(err, errStoreUnavailable), errors.Is(err, assetrisk.ErrGraphUnavailable):
		status = http.StatusServiceUnavailable
		message = err.Error()
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
