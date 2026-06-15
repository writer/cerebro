package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type connectorCatalogEntry struct {
	SourceID               string   `json:"source_id"`
	Name                   string   `json:"name"`
	Description            string   `json:"description"`
	EmittedKinds           []string `json:"emitted_kinds"`
	Status                 string   `json:"status"`
	ConfiguredRuntimes     int      `json:"configured_runtimes"`
	HealthyRuntimes        int      `json:"healthy_runtimes"`
	NeedsAttentionRuntimes int      `json:"needs_attention_runtimes"`
}

type connectorLibraryResponse struct {
	Connectors          []connectorCatalogEntry `json:"connectors"`
	TenantID            string                  `json:"tenant_id,omitempty"`
	RuntimeStore        string                  `json:"runtime_store"`
	CredentialTransport connectorTransportView  `json:"credential_transport"`
	CredentialVault     connectorVaultView      `json:"credential_vault"`
}

type connectorTransportView struct {
	Available bool   `json:"available"`
	Algorithm string `json:"algorithm"`
	KeyURL    string `json:"key_url"`
}

type connectorVaultView struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}

type connectorConnectionRequest struct {
	RuntimeID            string                                `json:"runtime_id"`
	TenantID             string                                `json:"tenant_id"`
	Config               map[string]string                     `json:"config"`
	EncryptedCredentials connectorcredentials.EncryptedPayload `json:"encrypted_credentials"`
}

type connectorConnectionResponse struct {
	SourceID   string                  `json:"source_id"`
	Runtime    json.RawMessage         `json:"runtime"`
	Credential connectorCredentialView `json:"credential"`
}

type connectorCredentialView struct {
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant_id"`
	SourceID  string   `json:"source_id"`
	RuntimeID string   `json:"runtime_id"`
	KeyID     string   `json:"key_id"`
	Fields    []string `json:"fields"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

func (a *App) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimes, runtimeStoreStatus := a.connectorRuntimeCatalog(r, tenantID)
	counts := connectorRuntimeCounts(runtimes)
	sources := a.sourceService().List().GetSources()
	entries := make([]connectorCatalogEntry, 0, len(sources))
	for _, source := range sources {
		entry := connectorCatalogEntry{
			SourceID:     source.GetId(),
			Name:         source.GetName(),
			Description:  source.GetDescription(),
			EmittedKinds: append([]string{}, source.GetEmittedKinds()...),
			Status:       "available",
		}
		if count := counts[source.GetId()]; count.total > 0 {
			entry.ConfiguredRuntimes = count.total
			entry.HealthyRuntimes = count.healthy
			entry.NeedsAttentionRuntimes = count.total - count.healthy
			switch {
			case count.healthy == count.total:
				entry.Status = "connected"
			case count.healthy > 0:
				entry.Status = "degraded"
			default:
				entry.Status = "needs_attention"
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	transport := connectorTransportView{
		Available: a.connectorTransitKey != nil,
		KeyURL:    "/connectors/credential-key",
	}
	if a.connectorTransitKey != nil {
		transport.Algorithm = a.connectorTransitKey.PublicKey().Algorithm
	}
	writeJSON(w, http.StatusOK, connectorLibraryResponse{
		Connectors:          entries,
		TenantID:            tenantID,
		RuntimeStore:        runtimeStoreStatus,
		CredentialTransport: transport,
		CredentialVault:     connectorVaultStatus(a.cfg.ConnectorCredentials, a.deps.StateStore),
	})
}

func (a *App) handleConnectorCredentialKey(w http.ResponseWriter, _ *http.Request) {
	if a == nil || a.connectorTransitKey == nil {
		writeConnectorError(w, connectorcredentials.ErrUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.connectorTransitKey.PublicKey())
}

func (a *App) handleCreateConnectorConnection(w http.ResponseWriter, r *http.Request) {
	request := connectorConnectionRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	tenantID := strings.TrimSpace(request.TenantID)
	if runtimeID == "" {
		writeConnectorError(w, fmt.Errorf("%w: runtime_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if tenantID == "" {
		writeConnectorError(w, fmt.Errorf("%w: tenant_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	runtimeConfig, err := connectorRuntimeConfig(request.Config)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	runtime := &cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: sourceID,
		TenantId: tenantID,
		Config:   runtimeConfig,
	}
	if err := authorizePutSourceRuntimeTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), runtime); err != nil {
		writeConnectorError(w, err)
		return
	}
	if a == nil || a.connectorTransitKey == nil {
		writeConnectorError(w, connectorcredentials.ErrUnavailable)
		return
	}
	decrypted, err := a.connectorTransitKey.Decrypt(request.EncryptedCredentials)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	fields, err := connectorcredentials.ParseCredentialFields(decrypted)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	vault, err := connectorCredentialVault(a.cfg.ConnectorCredentials, a.deps.StateStore)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	record, err := vault.Put(r.Context(), connectorcredentials.PlainCredential{
		TenantID:  tenantID,
		SourceID:  sourceID,
		RuntimeID: runtimeID,
		Fields:    fields,
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	for _, field := range connectorcredentials.SortedFieldNames(fields) {
		runtime.Config[field] = connectorcredentials.Reference(record.ID, field)
	}
	response, err := a.runtimeService().Put(r.Context(), &cerebrov1.PutSourceRuntimeRequest{Runtime: runtime})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimePayload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(response.GetRuntime())
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorConnectionResponse{
		SourceID: sourceID,
		Runtime:  json.RawMessage(runtimePayload),
		Credential: connectorCredentialView{
			ID:        record.ID,
			TenantID:  record.TenantID,
			SourceID:  record.SourceID,
			RuntimeID: record.RuntimeID,
			KeyID:     record.KeyID,
			Fields:    connectorcredentials.SortedFieldNames(fields),
			CreatedAt: connectorcredentials.TimestampOrZero(record.CreatedAt),
			UpdatedAt: connectorcredentials.TimestampOrZero(record.UpdatedAt),
		},
	})
}

func (a *App) connectorRuntimeCatalog(r *http.Request, tenantID string) ([]*cerebrov1.SourceRuntime, string) {
	if a == nil || sourceRuntimeStore(a.deps.StateStore) == nil {
		return nil, "unavailable"
	}
	runtimes, err := a.runtimeService().List(r.Context(), ports.SourceRuntimeFilter{TenantID: tenantID, Limit: 500})
	if err != nil {
		return nil, "unavailable"
	}
	return runtimes, "ready"
}

type connectorRuntimeCount struct {
	total   int
	healthy int
}

func connectorRuntimeCounts(runtimes []*cerebrov1.SourceRuntime) map[string]connectorRuntimeCount {
	counts := make(map[string]connectorRuntimeCount)
	for _, runtime := range runtimes {
		sourceID := strings.TrimSpace(runtime.GetSourceId())
		if sourceID == "" {
			continue
		}
		count := counts[sourceID]
		count.total++
		if connectorRuntimeHealthy(runtime) {
			count.healthy++
		}
		counts[sourceID] = count
	}
	return counts
}

func connectorRuntimeHealthy(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	status := strings.TrimSpace(runtime.GetConfig()["__cerebro_runtime_status"])
	if status != "" {
		return status == "completed" || status == "healthy"
	}
	return runtime.GetLastSyncedAt() != nil
}

func connectorRuntimeConfig(input map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(input))
	for key, value := range input {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if sourceconfig.SensitiveKey(trimmedKey) && strings.TrimSpace(value) != "" && !sourceconfig.IsCredentialReference(value) {
			return nil, fmt.Errorf("%w: sensitive config %q must be supplied in encrypted_credentials", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		config[trimmedKey] = value
	}
	return config, nil
}

func connectorCredentialVault(credentialConfig config.ConnectorCredentialConfig, store ports.StateStore) (*connectorcredentials.Vault, error) {
	credentialStore := connectorCredentialStore(store)
	if credentialStore == nil {
		return nil, connectorcredentials.ErrUnavailable
	}
	return connectorcredentials.NewVault(credentialStore, credentialConfig.Key)
}

func connectorCredentialStore(store ports.StateStore) ports.ConnectorCredentialStore {
	credentialStore, ok := store.(ports.ConnectorCredentialStore)
	if !ok || isNilInterface(credentialStore) {
		return nil
	}
	return credentialStore
}

func connectorVaultStatus(credentialConfig config.ConnectorCredentialConfig, store ports.StateStore) connectorVaultView {
	if connectorCredentialStore(store) == nil {
		return connectorVaultView{Available: false, Detail: "state store unavailable"}
	}
	if strings.TrimSpace(credentialConfig.Key) == "" {
		return connectorVaultView{Available: false, Detail: "credential key unavailable"}
	}
	return connectorVaultView{Available: true}
}

func readConnectorJSON(r *http.Request, value any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("%w: request body is required", connectorcredentials.ErrInvalidRequest)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProtoJSONBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read request body: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	if len(body) > maxProtoJSONBodyBytes {
		return fmt.Errorf("%w: request JSON body exceeds maximum size", connectorcredentials.ErrInvalidRequest)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("%w: request body is required", connectorcredentials.ErrInvalidRequest)
	}
	if err := json.Unmarshal(body, value); err != nil {
		return fmt.Errorf("%w: decode request JSON: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	return nil
}

func writeConnectorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ports.ErrConnectorCredentialNotFound),
		errors.Is(err, ports.ErrSourceRuntimeNotFound),
		errors.Is(err, sourceops.ErrSourceNotFound):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case errors.Is(err, connectorcredentials.ErrInvalidRequest),
		errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, errInvalidHTTPRequest):
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case errors.Is(err, connectorcredentials.ErrUnavailable),
		errors.Is(err, sourceruntime.ErrRuntimeUnavailable):
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	case errors.Is(err, errTenantForbidden):
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func connectorTimestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
