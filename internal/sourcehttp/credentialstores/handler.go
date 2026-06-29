package credentialstores

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	domain "github.com/writer/cerebro/internal/credentialstores"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceops"
)

const (
	defaultLimit = 500
	maxLimit     = 1000
)

type Dependencies struct {
	Config               config.Config
	StateStore           ports.StateStore
	TransitKey           *connectorcredentials.TransitKey
	SourceService        *sourceops.Service
	EffectiveTenant      func(context.Context, string) (string, error)
	RequiresTenantFilter func(context.Context) bool
	TenantAllowed        func(context.Context, string) bool
	WriteError           func(http.ResponseWriter, error)
}

type Handler struct {
	deps Dependencies
}

type detailResponse struct {
	GeneratedAt           string             `json:"generated_at"`
	TenantID              string             `json:"tenant_id,omitempty"`
	RuntimeStoreStatus    string             `json:"runtime_store_status"`
	CredentialStoreStatus string             `json:"credential_store_status"`
	Store                 domain.Operational `json:"store"`
	Audit                 []auditEvent       `json:"audit,omitempty"`
}

type auditEvent struct {
	ID           string `json:"id"`
	CredentialID string `json:"credential_id"`
	TenantID     string `json:"tenant_id"`
	SourceID     string `json:"source_id"`
	RuntimeID    string `json:"runtime_id"`
	EventType    string `json:"event_type"`
	Actor        string `json:"actor,omitempty"`
	Status       string `json:"status,omitempty"`
	Detail       string `json:"detail,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

func New(deps Dependencies) *Handler {
	return &Handler{deps: deps}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.effectiveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response, err := h.operations(r.Context(), tenantID, limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	if storeID == "" {
		h.writeError(w, connectorcredentials.ErrInvalidRequest)
		return
	}
	tenantID, err := h.effectiveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	response, err := h.operations(r.Context(), tenantID, limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	for _, store := range response.Stores {
		if store.Store.ID != storeID {
			continue
		}
		writeJSON(w, http.StatusOK, detailResponse{
			GeneratedAt:           response.GeneratedAt,
			TenantID:              response.TenantID,
			RuntimeStoreStatus:    response.RuntimeStoreStatus,
			CredentialStoreStatus: response.CredentialStoreStatus,
			Store:                 store,
			Audit:                 h.auditEvents(r.Context(), store.Bindings, 50),
		})
		return
	}
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func (h *Handler) operations(ctx context.Context, tenantID string, limit int) (domain.ListResponse, error) {
	runtimes, runtimeStoreStatus, err := h.runtimes(ctx, tenantID, limit)
	if err != nil {
		return domain.ListResponse{}, err
	}
	records, credentialStoreStatus, err := h.credentialRecords(ctx, tenantID, limit)
	if err != nil {
		return domain.ListResponse{}, err
	}
	return domain.BuildOperations(domain.BuildInput{
		GeneratedAt:           time.Now().UTC(),
		TenantID:              tenantID,
		RuntimeStoreStatus:    runtimeStoreStatus,
		CredentialStoreStatus: credentialStoreStatus,
		Stores:                h.catalog(),
		Runtimes:              runtimes,
		Credentials:           records,
		SourceNames:           h.sourceNames(),
		RequiresTenantFilter:  h.requiresTenantFilter(ctx),
		TenantAllowed: func(candidate string) bool {
			return h.tenantAllowed(ctx, candidate)
		},
	}), nil
}

func (h *Handler) catalog() []domain.StoreMetadata {
	return domain.Catalog(domain.CatalogInput{
		CredentialKeyConfigured:  strings.TrimSpace(h.deps.Config.ConnectorCredentials.Key) != "",
		CredentialStoreAvailable: connectorCredentialStore(h.deps.StateStore) != nil,
		TransitAvailable:         h.deps.TransitKey != nil,
		SecretStoreConfiguration: h.deps.Config.ConnectorSecretStores,
	})
}

func (h *Handler) runtimes(ctx context.Context, tenantID string, limit int) ([]*cerebrov1.SourceRuntime, string, error) {
	store := sourceRuntimeStore(h.deps.StateStore)
	if store == nil {
		return nil, "unavailable", nil
	}
	lister, ok := store.(ports.SourceRuntimeListStore)
	if !ok {
		return nil, "unavailable", nil
	}
	runtimes, err := lister.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{
		TenantID: strings.TrimSpace(tenantID),
		Limit:    uint32(limit), // #nosec G115 -- queryLimit clamps list requests to maxLimit.
	})
	if err != nil {
		return nil, "unavailable", err
	}
	return runtimes, "ready", nil
}

func (h *Handler) credentialRecords(ctx context.Context, tenantID string, limit int) ([]*ports.ConnectorCredentialRecord, string, error) {
	store := connectorCredentialStore(h.deps.StateStore)
	if store == nil {
		return nil, "unavailable", nil
	}
	records, err := store.ListConnectorCredentials(ctx, ports.ConnectorCredentialFilter{
		TenantID: strings.TrimSpace(tenantID),
		Limit:    limit,
	})
	if err != nil {
		return nil, "unavailable", err
	}
	return records, "ready", nil
}

func (h *Handler) sourceNames() map[string]string {
	names := map[string]string{}
	if h.deps.SourceService == nil {
		return names
	}
	for _, source := range h.deps.SourceService.List().GetSources() {
		if source == nil {
			continue
		}
		names[source.GetId()] = firstNonEmpty(source.GetName(), source.GetId())
	}
	return names
}

func (h *Handler) auditEvents(ctx context.Context, bindings []domain.Binding, limit int) []auditEvent {
	store := connectorCredentialStore(h.deps.StateStore)
	if store == nil || limit <= 0 {
		return nil
	}
	seen := map[string]struct{}{}
	events := []auditEvent{}
	for _, binding := range bindings {
		credentialID := strings.TrimSpace(binding.CredentialID)
		if credentialID == "" {
			continue
		}
		if _, ok := seen[credentialID]; ok {
			continue
		}
		seen[credentialID] = struct{}{}
		records, err := store.ListConnectorCredentialAuditEvents(ctx, credentialID, limit-len(events))
		if err != nil {
			return events
		}
		events = append(events, auditEvents(records)...)
		if len(events) >= limit {
			break
		}
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt > events[j].CreatedAt
	})
	if len(events) > limit {
		return events[:limit]
	}
	return events
}

func auditEvents(records []*ports.ConnectorCredentialAuditRecord) []auditEvent {
	events := make([]auditEvent, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		events = append(events, auditEvent{
			ID:           record.ID,
			CredentialID: record.CredentialID,
			TenantID:     record.TenantID,
			SourceID:     record.SourceID,
			RuntimeID:    record.RuntimeID,
			EventType:    record.EventType,
			Actor:        record.Actor,
			Status:       record.Status,
			Detail:       record.Detail,
			CreatedAt:    connectorcredentials.TimestampOrZero(record.CreatedAt),
		})
	}
	return events
}

func (h *Handler) effectiveTenant(ctx context.Context, requested string) (string, error) {
	if h.deps.EffectiveTenant == nil {
		return strings.TrimSpace(requested), nil
	}
	return h.deps.EffectiveTenant(ctx, requested)
}

func (h *Handler) requiresTenantFilter(ctx context.Context) bool {
	return h.deps.RequiresTenantFilter != nil && h.deps.RequiresTenantFilter(ctx)
}

func (h *Handler) tenantAllowed(ctx context.Context, tenantID string) bool {
	return h.deps.TenantAllowed == nil || h.deps.TenantAllowed(ctx, tenantID)
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	if h.deps.WriteError != nil {
		h.deps.WriteError(w, err)
		return
	}
	status := http.StatusInternalServerError
	if errors.Is(err, connectorcredentials.ErrInvalidRequest) {
		status = http.StatusBadRequest
	}
	http.Error(w, http.StatusText(status), status)
}

func queryLimit(r *http.Request) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get("limit"))
	if value == "" {
		return defaultLimit, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, connectorcredentials.ErrInvalidRequest
	}
	if parsed == 0 {
		return defaultLimit, nil
	}
	if parsed > maxLimit {
		return maxLimit, nil
	}
	return parsed, nil
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func sourceRuntimeStore(store ports.StateStore) ports.SourceRuntimeStore {
	runtimeStore, ok := store.(ports.SourceRuntimeStore)
	if !ok || isNilInterface(runtimeStore) {
		return nil
	}
	return runtimeStore
}

func connectorCredentialStore(store ports.StateStore) ports.ConnectorCredentialStore {
	credentialStore, ok := store.(ports.ConnectorCredentialStore)
	if !ok || isNilInterface(credentialStore) {
		return nil
	}
	return credentialStore
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
