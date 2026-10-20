// Package frameworksettings serves the tenant-wide selection of compliance
// frameworks that findings are measured against.
package frameworksettings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

const maxBodyBytes = 64 << 10

var (
	errInvalidRequest   = errors.New("invalid framework settings request")
	errStoreUnavailable = errors.New("compliance framework settings store is not configured")
	errTenantForbidden  = errors.New("tenant access denied")
)

// TenantResolver returns the authorized tenant for a requested tenant ID.
// Any error it returns is treated as an authorization failure.
type TenantResolver func(context.Context, string) (string, error)

// Handler serves GET and PUT for framework settings.
type Handler struct {
	store   ports.ComplianceFrameworkSettingsStore
	resolve TenantResolver
}

// NewHandler builds a handler from the optional StateStore capability.
func NewHandler(store ports.StateStore, resolve TenantResolver) Handler {
	settingsStore, _ := store.(ports.ComplianceFrameworkSettingsStore)
	return Handler{store: settingsStore, resolve: resolve}
}

type request struct {
	TenantID          string   `json:"tenant_id"`
	EnabledFrameworks []string `json:"enabled_frameworks"`
}

// Response is the wire shape for both GET and PUT.
type Response struct {
	Settings  View `json:"settings"`
	Persisted bool `json:"persisted"`
}

// View is one tenant's framework selection.
type View struct {
	TenantID          string   `json:"tenant_id"`
	EnabledFrameworks []string `json:"enabled_frameworks"`
	CreatedAt         string   `json:"created_at,omitempty"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
}

// Get returns the saved selection or the default selection.
func (h Handler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	settings, persisted, err := h.effective(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Response{Settings: newView(settings), Persisted: persisted})
}

// Put replaces the tenant's selection with canonical catalog names.
func (h Handler) Put(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, errStoreUnavailable)
		return
	}
	var body request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
		writeError(w, fmt.Errorf("%w: decode framework settings: %w", errInvalidRequest, err))
		return
	}
	if body.EnabledFrameworks == nil {
		writeError(w, fmt.Errorf("%w: enabled_frameworks is required", errInvalidRequest))
		return
	}
	tenantID, err := h.tenant(r.Context(), body.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	catalog, err := compliance.LoadBuiltinControlCatalog()
	if err != nil {
		writeError(w, fmt.Errorf("load control catalog: %w", err))
		return
	}
	enabled, err := compliance.ResolveEnabledFrameworks(catalog, body.EnabledFrameworks)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.PutComplianceFrameworkSettings(r.Context(), &ports.ComplianceFrameworkSettings{TenantID: tenantID, EnabledFrameworks: enabled}); err != nil {
		writeError(w, err)
		return
	}
	stored, err := h.store.GetComplianceFrameworkSettings(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Response{Settings: newView(*stored), Persisted: true})
}

// effective returns the saved selection, or the default selection when the
// tenant has never saved one or no store is configured.
func (h Handler) effective(ctx context.Context, tenantID string) (ports.ComplianceFrameworkSettings, bool, error) {
	defaults := ports.ComplianceFrameworkSettings{
		TenantID:          tenantID,
		EnabledFrameworks: append([]string(nil), compliance.DefaultEnabledFrameworkNames...),
	}
	if h.store == nil {
		return defaults, false, nil
	}
	stored, err := h.store.GetComplianceFrameworkSettings(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ports.ErrComplianceFrameworkSettingsNotFound) {
			return defaults, false, nil
		}
		return ports.ComplianceFrameworkSettings{}, false, err
	}
	return *stored, true, nil
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

func newView(settings ports.ComplianceFrameworkSettings) View {
	enabled := settings.EnabledFrameworks
	if enabled == nil {
		enabled = []string{}
	}
	view := View{TenantID: strings.TrimSpace(settings.TenantID), EnabledFrameworks: enabled}
	if !settings.CreatedAt.IsZero() {
		view.CreatedAt = settings.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !settings.UpdatedAt.IsZero() {
		view.UpdatedAt = settings.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return view
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "internal server error"
	switch {
	case errors.Is(err, errInvalidRequest), errors.Is(err, compliance.ErrUnknownFramework):
		status = http.StatusBadRequest
		message = err.Error()
	case errors.Is(err, errTenantForbidden):
		status = http.StatusForbidden
		message = "tenant access denied"
	case errors.Is(err, errStoreUnavailable):
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
