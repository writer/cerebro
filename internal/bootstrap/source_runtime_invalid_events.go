package bootstrap

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type sourceRuntimeInvalidEventsResponse struct {
	GeneratedAt string                            `json:"generated_at"`
	Events      []sourceRuntimeInvalidEventRecord `json:"events"`
}

type sourceRuntimeInvalidEventRecord struct {
	RuntimeID       string   `json:"runtime_id"`
	SourceID        string   `json:"source_id"`
	TenantID        string   `json:"tenant_id"`
	FailureCategory string   `json:"failure_category"`
	Fields          []string `json:"fields,omitempty"`
	Status          string   `json:"status"`
	Retryable       bool     `json:"retryable"`
	ObservedAt      string   `json:"observed_at,omitempty"`
	OccurredAt      string   `json:"occurred_at,omitempty"`
	SourceEventID   string   `json:"source_event_id,omitempty"`
	Diagnostic      string   `json:"diagnostic,omitempty"`
}

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
	record, ok := invalidEventRecordFromRuntime(runtime)
	response := sourceRuntimeInvalidEventsResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if ok {
		response.Events = []sourceRuntimeInvalidEventRecord{record}
	}
	writeJSON(w, http.StatusOK, response)
}

func invalidEventRecordFromRuntime(runtime interface {
	GetId() string
	GetSourceId() string
	GetTenantId() string
	GetConfig() map[string]string
}) (sourceRuntimeInvalidEventRecord, bool) {
	if runtime == nil {
		return sourceRuntimeInvalidEventRecord{}, false
	}
	config := runtime.GetConfig()
	category := strings.TrimSpace(config[runtimeLastFailureCategoryConfigKey])
	field := strings.TrimSpace(config[runtimeLastInvalidFieldConfigKey])
	if category == "" && field == "" {
		return sourceRuntimeInvalidEventRecord{}, false
	}
	record := sourceRuntimeInvalidEventRecord{
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		SourceID:        strings.TrimSpace(runtime.GetSourceId()),
		TenantID:        strings.TrimSpace(runtime.GetTenantId()),
		FailureCategory: category,
		Status:          firstNonEmptyString(config[runtimeLastInvalidStatusConfigKey], "terminal"),
		Retryable:       strings.EqualFold(strings.TrimSpace(config[runtimeLastInvalidRetryableConfigKey]), "true"),
		ObservedAt:      strings.TrimSpace(config[runtimeLastInvalidObservedAtConfigKey]),
		OccurredAt:      strings.TrimSpace(config[runtimeLastInvalidOccurredAtConfigKey]),
		SourceEventID:   strings.TrimSpace(config[runtimeLastInvalidEventIDConfigKey]),
		Diagnostic:      strings.TrimSpace(config[runtimeLastInvalidDiagnosticConfigKey]),
	}
	if field != "" {
		record.Fields = []string{field}
	}
	return record, true
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
