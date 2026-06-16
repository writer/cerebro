package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const connectorDefinitionMaxLimit = 500

type connectorDefinitionListResponse struct {
	GeneratedAt  string                            `json:"generated_at"`
	TenantID     string                            `json:"tenant_id,omitempty"`
	RuntimeStore string                            `json:"runtime_store"`
	Definitions  []connectordefinitions.Definition `json:"definitions"`
}

type connectorDefinitionResponse struct {
	GeneratedAt string                          `json:"generated_at"`
	Definition  connectordefinitions.Definition `json:"definition"`
}

type connectorDefinitionValidationResponse struct {
	GeneratedAt string                                `json:"generated_at"`
	Definition  connectordefinitions.Definition       `json:"definition"`
	Validation  connectordefinitions.ValidationResult `json:"validation"`
	Promotion   connectordefinitions.PromotionState   `json:"promotion"`
}

type connectorDefinitionPromotionResponse struct {
	GeneratedAt string                               `json:"generated_at"`
	Result      connectordefinitions.PromotionResult `json:"result"`
}

func (a *App) handleListConnectorDefinitions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	store := connectorDefinitionStore(a.deps.StateStore)
	runtimeStoreStatus := "unavailable"
	if store != nil {
		runtimeStoreStatus = "ready"
	}
	if store == nil {
		writeConnectorError(w, sourceruntime.ErrRuntimeUnavailable)
		return
	}
	limit, err := connectorDefinitionLimit(r)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	records, err := store.ListConnectorDefinitions(r.Context(), ports.ConnectorDefinitionFilter{
		TenantID: tenantID,
		Stage:    strings.TrimSpace(r.URL.Query().Get("stage")),
		Limit:    limit,
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	definitions := make([]connectordefinitions.Definition, 0, len(records))
	for _, record := range records {
		definition, err := connectorDefinitionFromRecord(record)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		if err := authorizeTenantID(r.Context(), definition.TenantID); err != nil {
			writeConnectorError(w, err)
			return
		}
		definitions = append(definitions, definition)
	}
	writeJSON(w, http.StatusOK, connectorDefinitionListResponse{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		TenantID:     tenantID,
		RuntimeStore: runtimeStoreStatus,
		Definitions:  definitions,
	})
}

func (a *App) handleValidateConnectorDefinition(w http.ResponseWriter, r *http.Request) {
	definition := connectordefinitions.Definition{}
	if err := readConnectorJSON(r, &definition); err != nil {
		writeConnectorError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), definition.TenantID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	definition.TenantID = tenantID
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		writeConnectorError(w, fmt.Errorf("%w: %w", connectorcredentials.ErrInvalidRequest, err))
		return
	}
	writeJSON(w, http.StatusOK, connectorDefinitionValidationResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Definition:  normalized,
		Validation:  normalized.Validation,
		Promotion:   normalized.Promotion,
	})
}

func (a *App) handleCreateConnectorDefinition(w http.ResponseWriter, r *http.Request) {
	definition := connectordefinitions.Definition{}
	if err := readConnectorJSON(r, &definition); err != nil {
		writeConnectorError(w, err)
		return
	}
	saved, err := a.saveConnectorDefinition(r.Context(), definition, "")
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorDefinitionResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Definition:  saved,
	})
}

func (a *App) handleGetConnectorDefinition(w http.ResponseWriter, r *http.Request) {
	definitionID := strings.TrimSpace(r.PathValue("definitionID"))
	if definitionID == "" {
		writeConnectorError(w, fmt.Errorf("%w: definition_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	store := connectorDefinitionStore(a.deps.StateStore)
	if store == nil {
		writeConnectorError(w, sourceruntime.ErrRuntimeUnavailable)
		return
	}
	record, err := store.GetConnectorDefinition(r.Context(), definitionID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	definition, err := connectorDefinitionFromRecord(record)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), definition.TenantID); err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorDefinitionResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Definition:  definition,
	})
}

func (a *App) handlePutConnectorDefinition(w http.ResponseWriter, r *http.Request) {
	definitionID := strings.TrimSpace(r.PathValue("definitionID"))
	if definitionID == "" {
		writeConnectorError(w, fmt.Errorf("%w: definition_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	definition := connectordefinitions.Definition{}
	if err := readConnectorJSON(r, &definition); err != nil {
		writeConnectorError(w, err)
		return
	}
	saved, err := a.saveConnectorDefinition(r.Context(), definition, definitionID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorDefinitionResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Definition:  saved,
	})
}

func (a *App) handlePromoteConnectorDefinition(w http.ResponseWriter, r *http.Request) {
	definitionID := strings.TrimSpace(r.PathValue("definitionID"))
	if definitionID == "" {
		writeConnectorError(w, fmt.Errorf("%w: definition_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	request := connectordefinitions.PromotionRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	store := connectorDefinitionStore(a.deps.StateStore)
	if store == nil {
		writeConnectorError(w, sourceruntime.ErrRuntimeUnavailable)
		return
	}
	record, err := store.GetConnectorDefinition(r.Context(), definitionID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	definition, err := connectorDefinitionFromRecord(record)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), definition.TenantID); err != nil {
		writeConnectorError(w, err)
		return
	}
	result, err := connectordefinitions.Promote(definition, request)
	if err != nil {
		writeConnectorError(w, fmt.Errorf("%w: %w", connectorcredentials.ErrInvalidRequest, err))
		return
	}
	if result.Promoted {
		saved, err := a.saveConnectorDefinition(r.Context(), result.Definition, definitionID)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		result.Definition = saved
	}
	writeJSON(w, http.StatusOK, connectorDefinitionPromotionResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Result:      result,
	})
}

func (a *App) saveConnectorDefinition(ctx context.Context, definition connectordefinitions.Definition, pathDefinitionID string) (connectordefinitions.Definition, error) {
	tenantID, err := effectiveTenantFilter(ctx, definition.TenantID)
	if err != nil {
		return connectordefinitions.Definition{}, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: tenant_id is required", connectorcredentials.ErrInvalidRequest)
	}
	definition.TenantID = tenantID
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	if pathDefinitionID != "" && normalized.ID != pathDefinitionID {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: definition id does not match path", connectorcredentials.ErrInvalidRequest)
	}
	if !connectorDefinitionHasRequiredIdentity(normalized) {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: definition id, source_id, and display_name are required", connectorcredentials.ErrInvalidRequest)
	}
	if err := authorizeTenantID(ctx, normalized.TenantID); err != nil {
		return connectordefinitions.Definition{}, err
	}
	store := connectorDefinitionStore(a.deps.StateStore)
	if store == nil {
		return connectordefinitions.Definition{}, sourceruntime.ErrRuntimeUnavailable
	}
	version := 1
	existing, err := store.GetConnectorDefinition(ctx, normalized.ID)
	switch {
	case err == nil:
		if err := authorizeTenantID(ctx, existing.TenantID); err != nil {
			return connectordefinitions.Definition{}, err
		}
		if existing.TenantID != normalized.TenantID {
			return connectordefinitions.Definition{}, errTenantForbidden
		}
		version = existing.CurrentVersion + 1
	case errors.Is(err, ports.ErrConnectorDefinitionNotFound):
	default:
		return connectordefinitions.Definition{}, err
	}
	normalized.CurrentVersion = version
	payload, err := json.Marshal(normalized)
	if err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("marshal connector definition: %w", err)
	}
	record, err := store.PutConnectorDefinition(ctx, &ports.ConnectorDefinitionRecord{
		ID:             normalized.ID,
		TenantID:       normalized.TenantID,
		SourceID:       normalized.SourceID,
		DisplayName:    normalized.DisplayName,
		Runtime:        normalized.Runtime,
		Stage:          normalized.Stage,
		CurrentVersion: normalized.CurrentVersion,
		DefinitionJSON: payload,
	})
	if err != nil {
		return connectordefinitions.Definition{}, err
	}
	return connectorDefinitionFromRecord(record)
}

func connectorDefinitionFromRecord(record *ports.ConnectorDefinitionRecord) (connectordefinitions.Definition, error) {
	if record == nil {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: definition record is required", connectorcredentials.ErrInvalidRequest)
	}
	definition := connectordefinitions.Definition{}
	if err := json.Unmarshal(record.DefinitionJSON, &definition); err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("decode connector definition %q: %w", record.ID, err)
	}
	definition.ID = record.ID
	definition.TenantID = record.TenantID
	definition.SourceID = record.SourceID
	definition.DisplayName = record.DisplayName
	definition.Runtime = record.Runtime
	definition.Stage = record.Stage
	definition.CurrentVersion = record.CurrentVersion
	if !record.CreatedAt.IsZero() {
		definition.CreatedAt = record.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !record.UpdatedAt.IsZero() {
		definition.UpdatedAt = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("normalize connector definition %q: %w", record.ID, err)
	}
	normalized.CurrentVersion = record.CurrentVersion
	normalized.CreatedAt = definition.CreatedAt
	normalized.UpdatedAt = definition.UpdatedAt
	return normalized, nil
}

func connectorDefinitionStore(store ports.StateStore) ports.ConnectorDefinitionStore {
	definitionStore, ok := store.(ports.ConnectorDefinitionStore)
	if !ok {
		return nil
	}
	return definitionStore
}

func connectorDefinitionLimit(r *http.Request) (uint32, error) {
	if r == nil || r.URL == nil {
		return connectorDefinitionMaxLimit, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get("limit"))
	if value == "" {
		return connectorDefinitionMaxLimit, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 || parsed > connectorDefinitionMaxLimit {
		return 0, fmt.Errorf("%w: limit must be between 1 and %d", connectorcredentials.ErrInvalidRequest, connectorDefinitionMaxLimit)
	}
	return uint32(parsed), nil
}

func connectorDefinitionHasRequiredIdentity(definition connectordefinitions.Definition) bool {
	return strings.TrimSpace(definition.ID) != "" &&
		strings.TrimSpace(definition.TenantID) != "" &&
		strings.TrimSpace(definition.SourceID) != "" &&
		strings.TrimSpace(definition.DisplayName) != ""
}
