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
	"unicode/utf8"

	"github.com/writer/cerebro/internal/grccatalog"
	"github.com/writer/cerebro/internal/ports"
)

const (
	maxBodyBytes               = 1 << 20
	maxNameBytes               = 200
	maxDescriptionBytes        = 1000
	maxWidgets                 = 50
	currentSchemaVersion       = 1
	defaultCustomDashboardName = "Custom dashboard"

	visibilityPrivate      = "private"
	visibilityWorkspace    = "workspace"
	visibilityOrganization = "organization"
)

var (
	ErrUnavailable    = errors.New("custom dashboards are not configured")
	ErrInvalidRequest = errors.New("invalid custom dashboard request")
	ErrForbidden      = errors.New("custom dashboard access is forbidden")
)

// knownWidgetTypes is the catalog of widget kinds the renderer understands.
// Writes are rejected for unknown types so dashboards stay forward-compatible
// with the documented schema_version.
var knownWidgetTypes = map[string]struct{}{
	"trend_metric_cards":      {},
	"trend_chart":             {},
	"trend_aging_table":       {},
	"trend_period_comparison": {},
	"summary_metrics":         {},
	"findings_table":          {},
	"framework_progress":      {},
	"connector_health":        {},
	"markdown_note":           {},
}

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
	schemaVersion, err := validateSchemaVersion(request.SchemaVersion)
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
		SchemaVersion:  schemaVersion,
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
	viewer := h.actorID(r.Context())
	views := make([]View, 0, len(dashboards))
	for _, dashboard := range dashboards {
		if !canView(viewer, dashboard) {
			continue
		}
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
		schemaVersion, err := validateSchemaVersion(*request.SchemaVersion)
		if err != nil {
			writeError(w, err)
			return
		}
		existing.SchemaVersion = schemaVersion
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
	name, err := cloneName(request.Name, existing.Name)
	if err != nil {
		writeError(w, err)
		return
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
	if !canView(h.actorID(r.Context()), dashboard) {
		return nil, ports.ErrCustomDashboardNotFound
	}
	return dashboard, nil
}

// canView enforces dashboard visibility within an already tenant-authorized
// request. Private dashboards are restricted to their owner; workspace and
// organization dashboards remain visible to any authorized tenant member.
func canView(viewer string, dashboard *ports.CustomDashboard) bool {
	if dashboard.Visibility != visibilityPrivate {
		return true
	}
	owner := strings.TrimSpace(dashboard.OwnerUserID)
	return owner != "" && owner == strings.TrimSpace(viewer)
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
	normalizedWidgets, err := normalizeWidgets(widgets)
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
	tenantID, err := h.resolve(ctx, requested)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrForbidden, err)
	}
	return tenantID, nil
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
		value = visibilityPrivate
	}
	switch value {
	case visibilityPrivate, visibilityWorkspace, visibilityOrganization:
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

// cloneName resolves the name for a cloned dashboard. An explicit request name
// is validated against the same length limit as Create/Update; an auto-derived
// "Copy of ..." fallback is clamped so it can never exceed that limit.
func cloneName(requested string, existingName string) (string, error) {
	name := strings.TrimSpace(requested)
	if name != "" {
		if len(name) > maxNameBytes {
			return "", fmt.Errorf("%w: name must be at most %d bytes", ErrInvalidRequest, maxNameBytes)
		}
		return name, nil
	}
	base := strings.TrimSpace(existingName)
	if base == "" {
		return defaultCustomDashboardName, nil
	}
	return clampToBytes("Copy of "+base, maxNameBytes), nil
}

// clampToBytes truncates value to at most limit bytes without splitting a
// multi-byte UTF-8 rune.
func clampToBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	truncated := value[:limit]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return strings.TrimSpace(truncated)
}

// validateSchemaVersion rejects schema versions the server does not yet
// understand so clients cannot persist dashboards this build cannot render.
func validateSchemaVersion(version int) (int, error) {
	if version == 0 {
		return currentSchemaVersion, nil
	}
	if version < 0 || version > currentSchemaVersion {
		return 0, fmt.Errorf("%w: schema_version %d is not supported (max %d)", ErrInvalidRequest, version, currentSchemaVersion)
	}
	return version, nil
}

// normalizeWidgets validates that widgets is a JSON array of well-formed widget
// definitions: each entry needs a unique id and a type from the known catalog.
func normalizeWidgets(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || string(raw) == "null" {
		return json.RawMessage("[]"), nil
	}
	var widgets []json.RawMessage
	if err := json.Unmarshal(raw, &widgets); err != nil {
		return nil, fmt.Errorf("%w: widgets must be a JSON array", ErrInvalidRequest)
	}
	if len(widgets) > maxWidgets {
		return nil, fmt.Errorf("%w: at most %d widgets are allowed", ErrInvalidRequest, maxWidgets)
	}
	seen := make(map[string]struct{}, len(widgets))
	for index, entry := range widgets {
		var widget struct {
			ID    string          `json:"id"`
			Type  string          `json:"type"`
			Query json.RawMessage `json:"query"`
		}
		if err := json.Unmarshal(entry, &widget); err != nil {
			return nil, fmt.Errorf("%w: widget %d must be a JSON object", ErrInvalidRequest, index)
		}
		id := strings.TrimSpace(widget.ID)
		if id == "" {
			return nil, fmt.Errorf("%w: widget %d is missing an id", ErrInvalidRequest, index)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: widget id %q is duplicated", ErrInvalidRequest, id)
		}
		seen[id] = struct{}{}
		widgetType := strings.TrimSpace(widget.Type)
		if _, ok := knownWidgetTypes[widgetType]; !ok {
			return nil, fmt.Errorf("%w: widget %q has unsupported type %q", ErrInvalidRequest, id, widgetType)
		}
		if err := validateWidgetQuery(id, widget.Query); err != nil {
			return nil, err
		}
	}
	return append(json.RawMessage(nil), raw...), nil
}

// validateWidgetQuery validates a widget's optional query against the GRC
// report catalog. It is lenient about legacy or descriptive query fields:
// validation only applies once a widget binds a catalog source_id, so existing
// dashboards that carry no source binding remain valid.
func validateWidgetQuery(widgetID string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var query struct {
		SourceID string            `json:"source_id"`
		Params   map[string]string `json:"params"`
		Limit    uint32            `json:"limit"`
	}
	if err := json.Unmarshal(raw, &query); err != nil {
		return fmt.Errorf("%w: widget %q has an invalid query", ErrInvalidRequest, widgetID)
	}
	if strings.TrimSpace(query.SourceID) == "" {
		return nil
	}
	if err := grccatalog.ValidateWidgetQuery(grccatalog.WidgetQuery{SourceID: query.SourceID, Params: query.Params, Limit: query.Limit}); err != nil {
		return fmt.Errorf("%w: widget %q query: %s", ErrInvalidRequest, widgetID, err.Error())
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
	case errors.Is(err, ErrForbidden):
		status = http.StatusForbidden
	}
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = strings.ToLower(http.StatusText(status))
		if message == "" {
			message = "internal server error"
		}
	}
	writeJSON(w, status, map[string]string{"error": message})
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
