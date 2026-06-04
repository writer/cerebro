package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/runtimeresponse"
)

type runtimeCapabilitiesResponse struct {
	Capabilities []runtimeresponse.Capability `json:"capabilities"`
}

type runtimeBlocklistResponse struct {
	Entry *ports.RuntimeBlocklistEntry `json:"entry"`
}

type runtimeBlocklistListResponse struct {
	Entries []*ports.RuntimeBlocklistEntry `json:"entries"`
}

func (a *App) runtimeResponseService() *runtimeresponse.Service {
	return runtimeresponse.New(runtimeBlocklistStore(a.deps.StateStore))
}

func (a *App) handleRuntimeResponseCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, runtimeCapabilitiesResponse{Capabilities: a.runtimeResponseService().Capabilities()})
}

func (a *App) handleExecuteRuntimeResponse(w http.ResponseWriter, r *http.Request) {
	var request runtimeresponse.ExecuteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeRuntimeResponseError(w, fmt.Errorf("%w: decode runtime response request: %w", runtimeresponse.ErrInvalidRequest, err))
		return
	}
	if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	entry, err := a.runtimeResponseService().Execute(r.Context(), request)
	if err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, runtimeBlocklistResponse{Entry: entry})
}

func (a *App) handleListRuntimeBlocklist(w http.ResponseWriter, r *http.Request) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	filter := ports.RuntimeBlocklistFilter{
		TenantID:       strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		Type:           strings.TrimSpace(r.URL.Query().Get("type")),
		IncludeRevoked: false,
		Limit:          limit,
	}
	if includeRevoked := strings.TrimSpace(r.URL.Query().Get("include_revoked")); includeRevoked != "" {
		parsed, err := boolQueryParam(r, "include_revoked")
		if err != nil {
			writeRuntimeResponseError(w, err)
			return
		}
		filter.IncludeRevoked = parsed
	}
	if err := authorizeTenantID(r.Context(), filter.TenantID); err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	entries, err := a.runtimeResponseService().List(r.Context(), filter)
	if err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runtimeBlocklistListResponse{Entries: entries})
}

func (a *App) handleRevokeRuntimeBlocklistEntry(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	entry, err := a.runtimeResponseService().Revoke(r.Context(), tenantID, r.PathValue("entryID"))
	if err != nil {
		writeRuntimeResponseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runtimeBlocklistResponse{Entry: entry})
}

func writeRuntimeResponseError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, runtimeresponse.ErrInvalidRequest), errors.Is(err, errInvalidHTTPRequest):
		status = http.StatusBadRequest
	case errors.Is(err, runtimeresponse.ErrUnsupportedAction):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, runtimeresponse.ErrRuntimeUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ports.ErrRuntimeBlocklistEntryNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errTenantForbidden):
		status = http.StatusForbidden
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
