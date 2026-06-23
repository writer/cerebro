package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type connectorDepositRequest struct {
	TenantID       string            `json:"tenant_id,omitempty"`
	RuntimeID      string            `json:"runtime_id"`
	FamilyID       string            `json:"family_id,omitempty"`
	BatchID        string            `json:"batch_id,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	OccurredAt     string            `json:"occurred_at,omitempty"`
	FullState      bool              `json:"full_state,omitempty"`
	Record         json.RawMessage   `json:"record,omitempty"`
	Records        []json.RawMessage `json:"records,omitempty"`
}

type connectorDepositResponse struct {
	SourceID          string                        `json:"source_id"`
	RuntimeID         string                        `json:"runtime_id"`
	TenantID          string                        `json:"tenant_id"`
	FamilyID          string                        `json:"family_id"`
	RecordsAccepted   uint32                        `json:"records_accepted"`
	RecordsRejected   uint32                        `json:"records_rejected"`
	EventsAppended    uint32                        `json:"events_appended"`
	EntitiesProjected uint32                        `json:"entities_projected"`
	LinksProjected    uint32                        `json:"links_projected"`
	Errors            []connectorDepositRecordError `json:"errors,omitempty"`
}

type connectorDepositRecordError struct {
	Index         int    `json:"index"`
	SourceEventID string `json:"source_event_id,omitempty"`
	Detail        string `json:"detail"`
}

func (a *App) handleDepositConnectorRecords(w http.ResponseWriter, r *http.Request) {
	request := connectorDepositRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		writeConnectorError(w, fmt.Errorf("%w: runtime_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), runtimeID); err != nil {
		writeConnectorError(w, err)
		return
	}
	occurredAt, err := connectorDepositOccurredAt(request.OccurredAt)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	response, err := a.runtimeService().Deposit(r.Context(), sourceruntime.DepositRequest{
		RuntimeID:       runtimeID,
		SourceID:        sourceID,
		TenantID:        tenantID,
		FamilyID:        request.FamilyID,
		BatchID:         request.BatchID,
		IdempotencyKey:  request.IdempotencyKey,
		OccurredAt:      occurredAt,
		Records:         connectorDepositRecords(request),
		FullStateMarker: request.FullState,
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorDepositResponseFromRuntime(response))
}

func connectorDepositOccurredAt(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: occurred_at must be RFC3339", connectorcredentials.ErrInvalidRequest)
	}
	return parsed.UTC(), nil
}

func connectorDepositRecords(request connectorDepositRequest) []json.RawMessage {
	records := make([]json.RawMessage, 0, len(request.Records)+1)
	if len(request.Record) > 0 {
		records = append(records, request.Record)
	}
	for _, record := range request.Records {
		if len(record) > 0 {
			records = append(records, record)
		}
	}
	return records
}

func connectorDepositResponseFromRuntime(response *sourceruntime.DepositResponse) connectorDepositResponse {
	if response == nil {
		return connectorDepositResponse{}
	}
	errors := make([]connectorDepositRecordError, 0, len(response.Errors))
	for _, err := range response.Errors {
		errors = append(errors, connectorDepositRecordError{
			Index:         err.Index,
			SourceEventID: err.SourceEventID,
			Detail:        err.Detail,
		})
	}
	return connectorDepositResponse{
		SourceID:          response.SourceID,
		RuntimeID:         response.RuntimeID,
		TenantID:          response.TenantID,
		FamilyID:          response.FamilyID,
		RecordsAccepted:   response.RecordsAccepted,
		RecordsRejected:   response.RecordsRejected,
		EventsAppended:    response.EventsAppended,
		EntitiesProjected: response.EntitiesProjected,
		LinksProjected:    response.LinksProjected,
		Errors:            errors,
	}
}
