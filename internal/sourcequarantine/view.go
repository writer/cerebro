// Package sourcequarantine defines safe operator views and list semantics for
// durable source-event quarantine records.
package sourcequarantine

import (
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultListLimit = 50
	maxListLimit     = 500

	legacyFailureCategoryKey = "__cerebro_runtime_last_failure_category"
	legacyEventIDKey         = "__cerebro_runtime_last_invalid_event_id"
	legacyFieldKey           = "__cerebro_runtime_last_invalid_field"
	legacyStatusKey          = "__cerebro_runtime_last_invalid_status"
	legacyObservedAtKey      = "__cerebro_runtime_last_invalid_observed_at"
	legacyOccurredAtKey      = "__cerebro_runtime_last_invalid_occurred_at"
	legacyDiagnosticKey      = "__cerebro_runtime_last_invalid_diagnostic"
	legacyRetryableKey       = "__cerebro_runtime_last_invalid_retryable"
)

// View excludes the stored event payload and attributes.
type View struct {
	ID                       string   `json:"id,omitempty"`
	RuntimeID                string   `json:"runtime_id"`
	SourceID                 string   `json:"source_id"`
	TenantID                 string   `json:"tenant_id"`
	FailureCategory          string   `json:"failure_category"`
	Fields                   []string `json:"fields,omitempty"`
	Status                   string   `json:"status"`
	Retryable                bool     `json:"retryable"`
	ObservedAt               string   `json:"observed_at,omitempty"`
	OccurredAt               string   `json:"occurred_at,omitempty"`
	SourceEventID            string   `json:"source_event_id,omitempty"`
	Diagnostic               string   `json:"diagnostic,omitempty"`
	QueueState               string   `json:"queue_state,omitempty"`
	EventKind                string   `json:"event_kind,omitempty"`
	EventSHA256              string   `json:"event_sha256,omitempty"`
	OccurrenceCount          uint64   `json:"occurrence_count,omitempty"`
	FirstObservedAt          string   `json:"first_observed_at,omitempty"`
	LastObservedAt           string   `json:"last_observed_at,omitempty"`
	AdmissionABIVersion      uint32   `json:"admission_abi_version,omitempty"`
	AdmissionContractsSHA256 string   `json:"admission_contracts_sha256,omitempty"`
	AdmissionResultSHA256    string   `json:"admission_result_sha256,omitempty"`
}

// ParseListFilter accepts public queue states and a bounded result limit.
func ParseListFilter(limitRaw, stateRaw string) (uint32, string, bool) {
	limit := uint64(defaultListLimit)
	if raw := strings.TrimSpace(limitRaw); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || parsed == 0 || parsed > maxListLimit {
			return 0, "", false
		}
		limit = parsed
	}
	state := strings.TrimSpace(stateRaw)
	if state == "" {
		state = ports.SourceRuntimeQuarantineStatePending
	}
	switch state {
	case ports.SourceRuntimeQuarantineStatePending,
		ports.SourceRuntimeQuarantineStateResolved,
		ports.SourceRuntimeQuarantineStateDiscarded:
		return uint32(limit), state, true
	default:
		return 0, "", false
	}
}

// FromDurable returns a payload-free operator view.
func FromDurable(record ports.SourceRuntimeQuarantineRecord) View {
	result := View{
		ID:                       record.ID,
		RuntimeID:                record.RuntimeID,
		SourceID:                 record.SourceID,
		TenantID:                 record.TenantID,
		FailureCategory:          record.FailureCategory,
		Status:                   "terminal",
		OccurredAt:               formatTime(record.OccurredAt),
		SourceEventID:            record.EventID,
		Diagnostic:               diagnostic(record.FailureCategory, record.FailureField),
		QueueState:               record.State,
		EventKind:                record.EventKind,
		EventSHA256:              record.EventSHA256,
		OccurrenceCount:          record.OccurrenceCount,
		FirstObservedAt:          formatTime(record.FirstObservedAt),
		LastObservedAt:           formatTime(record.LastObservedAt),
		ObservedAt:               formatTime(record.LastObservedAt),
		AdmissionABIVersion:      record.AdmissionABIVersion,
		AdmissionContractsSHA256: record.AdmissionContractsSHA256,
		AdmissionResultSHA256:    record.AdmissionResultSHA256,
	}
	if record.FailureField != "" {
		result.Fields = []string{record.FailureField}
	}
	return result
}

// FromLegacy adapts the single diagnostic stored on source-runtime config.
func FromLegacy(runtime interface {
	GetId() string
	GetSourceId() string
	GetTenantId() string
	GetConfig() map[string]string
}) (View, bool) {
	if runtime == nil {
		return View{}, false
	}
	config := runtime.GetConfig()
	category := strings.TrimSpace(config[legacyFailureCategoryKey])
	field := strings.TrimSpace(config[legacyFieldKey])
	if category == "" && field == "" {
		return View{}, false
	}
	result := View{
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		SourceID:        strings.TrimSpace(runtime.GetSourceId()),
		TenantID:        strings.TrimSpace(runtime.GetTenantId()),
		FailureCategory: category,
		Status:          firstNonEmpty(config[legacyStatusKey], "terminal"),
		Retryable:       strings.EqualFold(strings.TrimSpace(config[legacyRetryableKey]), "true"),
		ObservedAt:      strings.TrimSpace(config[legacyObservedAtKey]),
		OccurredAt:      strings.TrimSpace(config[legacyOccurredAtKey]),
		SourceEventID:   strings.TrimSpace(config[legacyEventIDKey]),
		Diagnostic:      strings.TrimSpace(config[legacyDiagnosticKey]),
	}
	if field != "" {
		result.Fields = []string{field}
	}
	return result, true
}

func diagnostic(category, field string) string {
	switch category {
	case "missing_required_attribute":
		return "Missing required attribute " + field
	case "missing_required_payload_field":
		return "Missing required payload field " + field
	default:
		return "Event failed source admission: " + category
	}
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
