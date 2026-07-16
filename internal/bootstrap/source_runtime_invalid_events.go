package bootstrap

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcequarantine"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type sourceRuntimeInvalidEventsResponse struct {
	GeneratedAt string                            `json:"generated_at"`
	Events      []sourceRuntimeInvalidEventRecord `json:"events"`
}

type sourceRuntimeInvalidEventRecord = sourcequarantine.View

func (a *App) handleListSourceRuntimeInvalidEvents(w http.ResponseWriter, r *http.Request) {
	runtimeID := strings.TrimSpace(r.PathValue("runtimeID"))
	if runtimeID == "" {
		writeSourceRuntimeError(w, sourceruntime.ErrInvalidRequest)
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), runtimeID); err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	store := sourceRuntimeStore(a.deps.StateStore)
	if store == nil {
		writeSourceRuntimeError(w, sourceruntime.ErrRuntimeUnavailable)
		return
	}
	runtime, err := store.GetSourceRuntime(r.Context(), runtimeID)
	if errors.Is(err, ports.ErrSourceRuntimeNotFound) {
		writeJSON(w, http.StatusOK, sourceRuntimeInvalidEventsResponse{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		return
	}
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	if requiresTenantFilter(r.Context()) && !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
		writeJSON(w, http.StatusOK, sourceRuntimeInvalidEventsResponse{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		return
	}
	if quarantineStore, ok := a.deps.StateStore.(ports.SourceRuntimeQuarantineStore); ok {
		limit, state, valid := sourcequarantine.ParseListFilter(r.URL.Query().Get("limit"), r.URL.Query().Get("state"))
		if !valid {
			writeSourceRuntimeError(w, sourceruntime.ErrInvalidRequest)
			return
		}
		records, err := quarantineStore.ListSourceRuntimeQuarantines(r.Context(), ports.SourceRuntimeQuarantineFilter{
			TenantID:  runtime.GetTenantId(),
			RuntimeID: runtime.GetId(),
			State:     state,
			Limit:     limit,
		})
		if err != nil {
			writeSourceRuntimeError(w, err)
			return
		}
		response := sourceRuntimeInvalidEventsResponse{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Events:      make([]sourceRuntimeInvalidEventRecord, 0, len(records)),
		}
		for _, record := range records {
			response.Events = append(response.Events, sourcequarantine.FromDurable(record))
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	record, ok := sourcequarantine.FromLegacy(runtime)
	response := sourceRuntimeInvalidEventsResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if ok {
		response.Events = []sourceRuntimeInvalidEventRecord{record}
	}
	writeJSON(w, http.StatusOK, response)
}
