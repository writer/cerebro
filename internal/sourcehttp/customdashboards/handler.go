package customdashboards

import (
	"context"
	"crypto/rand"
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

	"github.com/writer/cerebro/internal/ports"
)

const (
	maxBodyBytes               = 1 << 20
	maxNameBytes               = 200
	maxDescriptionBytes        = 1000
	defaultCustomDashboardName = "Custom dashboard"
)

var (
	ErrUnavailable    = errors.New("custom dashboards are not configured")
	ErrInvalidRequest = errors.New("invalid custom dashboard request")
)

type TenantResolver func(context.Context, string) (string, error)
type TenantAuthorizer func(context.Context, string) error
type ActorResolver func(context.Context) string

type Handler struct {
	store     ports.CustomDashboardStore
	resolve   TenantResolver
	authorize TenantAuthorizer
	actor     ActorResolver
}

func NewHandler(store ports.StateStore, resolve TenantResolver, authorize TenantAuthorizer, actor ActorResolver) *Handler {
	dashboardStore, ok := store.(ports.CustomDashboardStore)
	if !ok || isNilInterface(dashboardStore) {
		dashboardStore = nil
	}
	return &Handler{store: dashboardStore, resolve: resolve, authorize: authorize, actor: actor}
}

type View struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	OrganizationID string          `json:"organization_id,omitempty"`
	WorkspaceID    string          `json:"workspace_id,omitempty"`
	OwnerUserID    string          `json:"owner_user_id,omitempty"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	Visibility     string          `json:"visibility"`
	SchemaVersion  int             `json:"schema_version"`
	Layout         json.RawMessage `json:"layout"`
	Widgets        json.RawMessage `json:"widgets"`
	Filters        json.RawMessage `json:"filters"`
	CreatedBy      string          `json:"created_by,omitempty"`
	UpdatedBy      string          `json:"updated_by,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

type Response struct {
	Dashboard View `json:"dashboard"`
}

type ListResponse struct {
	Dashboards []View `json:"dashboards"`
}

type createRequest struct {
	TenantID       string          `json:"tenant_id"`
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Visibility     string          `json:"visibility"`
	SchemaVersion  int             `json:"schema_version"`
	Layout         json.RawMessage `json:"layout"`
	Widgets        json.RawMessage `json:"widgets"`
	Filters        json.RawMessage `json:"filters"`
}

type updateRequest struct {
	OrganizationID *string          `json:"organization_id"`
	WorkspaceID    *string          `json:"workspace_id"`
	Name           *string          `json:"name"`
	Description    *string          `json:"description"`
	Visibility     *string          `json:"visibility"`
	SchemaVersion  *int             `json:"schema_version"`
	Layout         *json.RawMessage `json:"layout"`
	Widgets        *json.RawMessage `json:"widgets"`
	Filters        *json.RawMessage `json:"filters"`
}

type cloneRequest struct {
	Name string `json:"name"`
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, ErrUnavailable)
		return
	}
	var request createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&request); err != nil {
		writeError(w, fmt.Errorf("%w: decode custom dashboard: %w", ErrInvalidRequest, err))
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	if tenantID == "" {
		writeError(w, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest))
		return
	}
	name, description, visibility, layout, widgets, filters, err := NormalizeContent(request.Name, request.Description, request.Visibility, request.Layout, request.Widgets, request.Filters)
	if err != nil {
		writeError(w, err)
		return
	}
	actor := h.actorID(r.Context())
	dashboard := &ports.CustomDashboard{
		ID:             NewID(),
		TenantID:       tenantID,
		OrganizationID: strings.TrimSpace(request.OrganizationID),
		WorkspaceID:    strings.TrimSpace(request.WorkspaceID),
		OwnerUserID:    actor,
		Name:           name,
		Description:    description,
		Visibility:     visibility,
		SchemaVersion:  normalizeSchemaVersion(request.SchemaVersion),
		LayoutJSON:     string(layout),
		WidgetsJSON:    string(widgets),
		FiltersJSON:    string(filters),
		CreatedBy:      actor,
		UpdatedBy:      actor,
	}
	if err := h.store.PutCustomDashboard(r.Context(), dashboard); err != nil {
		writeError(w, err)
		return
	}
	stored, err := h.store.GetCustomDashboard(r.Context(), dashboard.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, Response{Dashboard: NewView(stored)})
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, ErrUnavailable)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeError(w, fmt.Errorf("%w: %w", ErrInvalidRequest, err))
		return
	}
	dashboards, err := h.store.ListCustomDashboards(r.Context(), ports.CustomDashboardFilter{
		TenantID:       tenantID,
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		WorkspaceID:    strings.TrimSpace(r.URL.Query().Get("workspace_id")),
		OwnerUserID:    strings.TrimSpace(r.URL.Query().Get("owner_user_id")),
		Limit:          limit,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	views := make([]View, 0, len(dashboards))
	for _, dashboard := range dashboards {
		views = append(views, NewView(dashboard))
	}
	writeJSON(w, http.StatusOK, ListResponse{Dashboards: views})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	dashboard, err := h.dashboardFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Response{Dashboard: NewView(dashboard)})
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, ErrUnavailable)
		return
	}
	existing, err := h.dashboardFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var request updateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&request); err != nil {
		writeError(w, fmt.Errorf("%w: decode custom dashboard: %w", ErrInvalidRequest, err))
		return
	}
	name, description, visibility := existing.Name, existing.Description, existing.Visibility
	if request.Name != nil {
		name = *request.Name
	}
	if request.Description != nil {
		description = *request.Description
	}
	if request.Visibility != nil {
		visibility = *request.Visibility
	}
	layout, widgets, filters := json.RawMessage(existing.LayoutJSON), json.RawMessage(existing.WidgetsJSON), json.RawMessage(existing.FiltersJSON)
	if request.Layout != nil {
		layout = *request.Layout
	}
	if request.Widgets != nil {
		widgets = *request.Widgets
	}
	if request.Filters != nil {
		filters = *request.Filters
	}
	name, description, visibility, layout, widgets, filters, err = NormalizeContent(name, description, visibility, layout, widgets, filters)
	if err != nil {
		writeError(w, err)
		return
	}
	existing.Name, existing.Description, existing.Visibility = name, description, visibility
	existing.LayoutJSON, existing.WidgetsJSON, existing.FiltersJSON = string(layout), string(widgets), string(filters)
	if request.OrganizationID != nil {
		existing.OrganizationID = strings.TrimSpace(*request.OrganizationID)
	}
	if request.WorkspaceID != nil {
		existing.WorkspaceID = strings.TrimSpace(*request.WorkspaceID)
	}
	if request.SchemaVersion != nil {
		existing.SchemaVersion = normalizeSchemaVersion(*request.SchemaVersion)
	}
	existing.UpdatedBy = h.actorID(r.Context())
	if err := h.store.PutCustomDashboard(r.Context(), existing); err != nil {
		writeError(w, err)
		return
	}
	stored, err := h.store.GetCustomDashboard(r.Context(), existing.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Response{Dashboard: NewView(stored)})
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, ErrUnavailable)
		return
	}
	existing, err := h.dashboardFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.DeleteCustomDashboard(r.Context(), existing.ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Clone(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, ErrUnavailable)
		return
	}
	existing, err := h.dashboardFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var request cloneRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, fmt.Errorf("%w: decode custom dashboard clone: %w", ErrInvalidRequest, err))
		return
	}
	actor := h.actorID(r.Context())
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = strings.TrimSpace(existing.Name)
		if name == "" {
			name = defaultCustomDashboardName
		} else {
			name = "Copy of " + name
		}
	}
	clone := *existing
	clone.ID, clone.Name, clone.OwnerUserID = NewID(), name, actor
	clone.CreatedBy, clone.UpdatedBy = actor, actor
	if err := h.store.PutCustomDashboard(r.Context(), &clone); err != nil {
		writeError(w, err)
		return
	}
	stored, err := h.store.GetCustomDashboard(r.Context(), clone.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, Response{Dashboard: NewView(stored)})
}

func (h *Handler) dashboardFromRequest(r *http.Request) (*ports.CustomDashboard, error) {
	if h.store == nil {
		return nil, ErrUnavailable
	}
	dashboard, err := h.store.GetCustomDashboard(r.Context(), r.PathValue("dashboardID"))
	if err != nil {
		return nil, err
	}
	if err := h.authorizeTenant(r.Context(), dashboard.TenantID); err != nil {
		return nil, ports.ErrCustomDashboardNotFound
	}
	if !dashboard.ArchivedAt.IsZero() {
		return nil, ports.ErrCustomDashboardNotFound
	}
	return dashboard, nil
}

func NormalizeContent(name string, description string, visibility string, layout json.RawMessage, widgets json.RawMessage, filters json.RawMessage) (string, string, string, json.RawMessage, json.RawMessage, json.RawMessage, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return "", "", "", nil, nil, nil, fmt.Errorf("%w: name is required", ErrInvalidRequest)
	}
	if len(trimmedName) > maxNameBytes {
		return "", "", "", nil, nil, nil, fmt.Errorf("%w: name must be at most %d bytes", ErrInvalidRequest, maxNameBytes)
	}
	trimmedDescription := strings.TrimSpace(description)
	if len(trimmedDescription) > maxDescriptionBytes {
		return "", "", "", nil, nil, nil, fmt.Errorf("%w: description must be at most %d bytes", ErrInvalidRequest, maxDescriptionBytes)
	}
	normalizedVisibility, err := normalizeVisibility(visibility)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	normalizedLayout, err := normalizeJSON(layout, "layout", "object", []byte("{}"))
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	normalizedWidgets, err := normalizeJSON(widgets, "widgets", "array", []byte("[]"))
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	normalizedFilters, err := normalizeJSON(filters, "filters", "object", []byte("{}"))
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	return trimmedName, trimmedDescription, normalizedVisibility, normalizedLayout, normalizedWidgets, normalizedFilters, nil
}

func NewView(dashboard *ports.CustomDashboard) View {
	return View{
		ID:             dashboard.ID,
		TenantID:       dashboard.TenantID,
		OrganizationID: dashboard.OrganizationID,
		WorkspaceID:    dashboard.WorkspaceID,
		OwnerUserID:    dashboard.OwnerUserID,
		Name:           dashboard.Name,
		Description:    dashboard.Description,
		Visibility:     dashboard.Visibility,
		SchemaVersion:  dashboard.SchemaVersion,
		Layout:         json.RawMessage(dashboard.LayoutJSON),
		Widgets:        json.RawMessage(dashboard.WidgetsJSON),
		Filters:        json.RawMessage(dashboard.FiltersJSON),
		CreatedBy:      dashboard.CreatedBy,
		UpdatedBy:      dashboard.UpdatedBy,
		CreatedAt:      dashboard.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      dashboard.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func NewID() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Sprintf("dashboard-%d", time.Now().UnixNano())
	}
	return "dashboard-" + hex.EncodeToString(random[:])
}

func (h *Handler) resolveTenant(ctx context.Context, requested string) (string, error) {
	if h.resolve == nil {
		return strings.TrimSpace(requested), nil
	}
	return h.resolve(ctx, requested)
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

func normalizeVisibility(visibility string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(visibility))
	if value == "" {
		value = "private"
	}
	switch value {
	case "private", "workspace", "organization":
		return value, nil
	default:
		return "", fmt.Errorf("%w: visibility must be private, workspace, or organization", ErrInvalidRequest)
	}
}

func normalizeJSON(raw json.RawMessage, field string, kind string, fallback json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || string(raw) == "null" {
		return append(json.RawMessage(nil), fallback...), nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("%w: %s must be valid JSON", ErrInvalidRequest, field)
	}
	switch kind {
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return nil, fmt.Errorf("%w: %s must be a JSON object", ErrInvalidRequest, field)
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return nil, fmt.Errorf("%w: %s must be a JSON array", ErrInvalidRequest, field)
		}
	}
	return append(json.RawMessage(nil), raw...), nil
}

func normalizeSchemaVersion(version int) int {
	if version <= 0 {
		return 1
	}
	return version
}

func uint32QueryParam(r *http.Request, key string) (uint32, error) {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", key)
	}
	return uint32(parsed), nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ports.ErrCustomDashboardNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ErrInvalidRequest):
		status = http.StatusBadRequest
	case strings.Contains(strings.ToLower(err.Error()), "tenant"):
		status = http.StatusForbidden
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
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
