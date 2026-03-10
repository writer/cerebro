package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ReportExecutionModeSync  = "sync"
	ReportExecutionModeAsync = "async"

	ReportRunStatusQueued    = "queued"
	ReportRunStatusRunning   = "running"
	ReportRunStatusSucceeded = "succeeded"
	ReportRunStatusFailed    = "failed"
	ReportRunStatusCanceled  = "canceled"
)

// ReportParameterValue holds one typed parameter binding for a report run.
type ReportParameterValue struct {
	Name           string     `json:"name"`
	StringValue    string     `json:"string_value,omitempty"`
	IntegerValue   *int64     `json:"integer_value,omitempty"`
	NumberValue    *float64   `json:"number_value,omitempty"`
	BooleanValue   *bool      `json:"boolean_value,omitempty"`
	TimestampValue *time.Time `json:"timestamp_value,omitempty"`
}

// ReportTimeSlice captures the most important temporal selectors used by report runs.
type ReportTimeSlice struct {
	AsOf       *time.Time `json:"as_of,omitempty"`
	From       *time.Time `json:"from,omitempty"`
	To         *time.Time `json:"to,omitempty"`
	ValidAt    *time.Time `json:"valid_at,omitempty"`
	RecordedAt *time.Time `json:"recorded_at,omitempty"`
}

// ReportRetryPolicy captures retry/backoff policy metadata for one report run.
type ReportRetryPolicy struct {
	MaxAttempts   int   `json:"max_attempts,omitempty"`
	BaseBackoffMS int64 `json:"base_backoff_ms,omitempty"`
	MaxBackoffMS  int64 `json:"max_backoff_ms,omitempty"`
}

// ReportSectionResult summarizes one rendered section within a report run.
type ReportSectionResult struct {
	Key          string   `json:"key"`
	Title        string   `json:"title"`
	Kind         string   `json:"kind"`
	EnvelopeKind string   `json:"envelope_kind,omitempty"`
	Present      bool     `json:"present"`
	ContentType  string   `json:"content_type,omitempty"`
	ItemCount    int      `json:"item_count,omitempty"`
	FieldCount   int      `json:"field_count,omitempty"`
	FieldKeys    []string `json:"field_keys,omitempty"`
	MeasureIDs   []string `json:"measure_ids,omitempty"`
}

// ReportSnapshot stores materialization metadata for one report result.
type ReportSnapshot struct {
	ID           string              `json:"id"`
	ResultSchema string              `json:"result_schema"`
	GeneratedAt  time.Time           `json:"generated_at"`
	RecordedAt   time.Time           `json:"recorded_at"`
	ContentHash  string              `json:"content_hash"`
	ByteSize     int                 `json:"byte_size"`
	SectionCount int                 `json:"section_count"`
	Retained     bool                `json:"retained"`
	ExpiresAt    *time.Time          `json:"expires_at,omitempty"`
	Lineage      ReportLineage       `json:"lineage,omitempty"`
	Storage      ReportStoragePolicy `json:"storage,omitempty"`
	StoragePath  string              `json:"-"`
}

// ReportRun represents one instantiated execution of a report definition.
type ReportRun struct {
	ID              string                 `json:"id"`
	ReportID        string                 `json:"report_id"`
	Status          string                 `json:"status"`
	ExecutionMode   string                 `json:"execution_mode"`
	SubmittedAt     time.Time              `json:"submitted_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	RequestedBy     string                 `json:"requested_by,omitempty"`
	Parameters      []ReportParameterValue `json:"parameters,omitempty"`
	TimeSlice       ReportTimeSlice        `json:"time_slice,omitempty"`
	CacheKey        string                 `json:"cache_key,omitempty"`
	JobID           string                 `json:"job_id,omitempty"`
	JobStatusURL    string                 `json:"job_status_url,omitempty"`
	StatusURL       string                 `json:"status_url"`
	LatestAttemptID string                 `json:"latest_attempt_id,omitempty"`
	AttemptCount    int                    `json:"attempt_count,omitempty"`
	EventCount      int                    `json:"event_count,omitempty"`
	RetryPolicy     ReportRetryPolicy      `json:"retry_policy,omitempty"`
	Lineage         ReportLineage          `json:"lineage,omitempty"`
	Storage         ReportStoragePolicy    `json:"storage,omitempty"`
	Snapshot        *ReportSnapshot        `json:"snapshot,omitempty"`
	Sections        []ReportSectionResult  `json:"sections,omitempty"`
	Result          map[string]any         `json:"result,omitempty"`
	Error           string                 `json:"error,omitempty"`
	Attempts        []ReportRunAttempt     `json:"-"`
	Events          []ReportRunEvent       `json:"-"`
}

// ReportRunSummary is the lightweight list representation of a report run.
type ReportRunSummary struct {
	ID              string                 `json:"id"`
	ReportID        string                 `json:"report_id"`
	Status          string                 `json:"status"`
	ExecutionMode   string                 `json:"execution_mode"`
	SubmittedAt     time.Time              `json:"submitted_at"`
	StartedAt       *time.Time             `json:"started_at,omitempty"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	RequestedBy     string                 `json:"requested_by,omitempty"`
	Parameters      []ReportParameterValue `json:"parameters,omitempty"`
	TimeSlice       ReportTimeSlice        `json:"time_slice,omitempty"`
	CacheKey        string                 `json:"cache_key,omitempty"`
	JobID           string                 `json:"job_id,omitempty"`
	JobStatusURL    string                 `json:"job_status_url,omitempty"`
	StatusURL       string                 `json:"status_url"`
	LatestAttemptID string                 `json:"latest_attempt_id,omitempty"`
	AttemptCount    int                    `json:"attempt_count,omitempty"`
	EventCount      int                    `json:"event_count,omitempty"`
	RetryPolicy     ReportRetryPolicy      `json:"retry_policy,omitempty"`
	Lineage         ReportLineage          `json:"lineage,omitempty"`
	Storage         ReportStoragePolicy    `json:"storage,omitempty"`
	Snapshot        *ReportSnapshot        `json:"snapshot,omitempty"`
	Sections        []ReportSectionResult  `json:"sections,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// ReportRunCollection is the list response for report runs.
type ReportRunCollection struct {
	ReportID string             `json:"report_id"`
	Count    int                `json:"count"`
	Runs     []ReportRunSummary `json:"runs"`
}

func (value ReportParameterValue) ValueType() (string, error) {
	count := 0
	typeName := ""
	if value.StringValue != "" {
		count++
		typeName = "string"
	}
	if value.IntegerValue != nil {
		count++
		typeName = "integer"
	}
	if value.NumberValue != nil {
		count++
		typeName = "number"
	}
	if value.BooleanValue != nil {
		count++
		typeName = "boolean"
	}
	if value.TimestampValue != nil {
		count++
		typeName = "date-time"
	}
	if count == 0 {
		return "", fmt.Errorf("parameter %q must include exactly one typed value", value.Name)
	}
	if count > 1 {
		return "", fmt.Errorf("parameter %q must not include multiple typed values", value.Name)
	}
	return typeName, nil
}

func (value ReportParameterValue) QueryValue() (string, error) {
	valueType, err := value.ValueType()
	if err != nil {
		return "", err
	}
	switch valueType {
	case "string":
		return value.StringValue, nil
	case "integer":
		return fmt.Sprintf("%d", *value.IntegerValue), nil
	case "number":
		return fmt.Sprintf("%g", *value.NumberValue), nil
	case "boolean":
		return fmt.Sprintf("%t", *value.BooleanValue), nil
	case "date-time":
		return value.TimestampValue.UTC().Format(time.RFC3339), nil
	default:
		return "", fmt.Errorf("unsupported parameter value type %q", valueType)
	}
}

// ValidateReportParameterValues ensures run parameter bindings match the report definition contract.
func ValidateReportParameterValues(definition ReportDefinition, values []ReportParameterValue) error {
	allowed := make(map[string]ReportParameter, len(definition.Parameters))
	for _, parameter := range definition.Parameters {
		allowed[strings.TrimSpace(parameter.Name)] = parameter
	}

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if name == "" {
			return fmt.Errorf("report parameter name is required")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate report parameter %q", name)
		}
		seen[name] = struct{}{}

		definitionParameter, ok := allowed[name]
		if !ok {
			return fmt.Errorf("parameter %q is not defined for report %q", name, definition.ID)
		}

		valueType, err := value.ValueType()
		if err != nil {
			return err
		}
		if valueType != strings.TrimSpace(definitionParameter.ValueType) {
			return fmt.Errorf("parameter %q must use value type %q", name, definitionParameter.ValueType)
		}
	}

	for _, parameter := range definition.Parameters {
		if !parameter.Required {
			continue
		}
		if _, ok := seen[strings.TrimSpace(parameter.Name)]; !ok {
			return fmt.Errorf("required parameter %q is missing", parameter.Name)
		}
	}
	return nil
}

// ExtractReportTimeSlice promotes known temporal selectors into a dedicated time-slice envelope.
func ExtractReportTimeSlice(values []ReportParameterValue) ReportTimeSlice {
	slice := ReportTimeSlice{}
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if value.TimestampValue == nil || value.TimestampValue.IsZero() {
			continue
		}
		timestamp := value.TimestampValue.UTC()
		switch name {
		case "as_of":
			slice.AsOf = &timestamp
		case "from":
			slice.From = &timestamp
		case "to":
			slice.To = &timestamp
		case "valid_at":
			slice.ValidAt = &timestamp
		case "recorded_at":
			slice.RecordedAt = &timestamp
		}
	}
	return slice
}

// BuildReportSectionResults summarizes the section-level shape of a materialized report result.
func BuildReportSectionResults(definition ReportDefinition, result map[string]any) []ReportSectionResult {
	sections := make([]ReportSectionResult, 0, len(definition.Sections))
	for _, section := range definition.Sections {
		summary := ReportSectionResult{
			Key:          section.Key,
			Title:        section.Title,
			Kind:         section.Kind,
			EnvelopeKind: reportEnvelopeKindForSection(section.Kind),
			MeasureIDs:   append([]string(nil), section.Measures...),
		}
		content, ok := result[section.Key]
		if !ok {
			sections = append(sections, summary)
			continue
		}
		summary.Present = true
		switch typed := content.(type) {
		case map[string]any:
			summary.ContentType = "object"
			summary.FieldCount = len(typed)
			summary.FieldKeys = sortedReportFieldKeys(typed)
		case []any:
			summary.ContentType = "array"
			summary.ItemCount = len(typed)
		case string:
			summary.ContentType = "string"
		case bool:
			summary.ContentType = "boolean"
		case float64, int, int64:
			summary.ContentType = "number"
		default:
			if content == nil {
				summary.ContentType = "null"
			} else {
				summary.ContentType = fmt.Sprintf("%T", content)
			}
		}
		sections = append(sections, summary)
	}
	return sections
}

// BuildReportSnapshot constructs materialization metadata for one report run result.
func BuildReportSnapshot(runID string, definition ReportDefinition, result map[string]any, retained bool, now time.Time) (*ReportSnapshot, error) {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal report result: %w", err)
	}
	sum := sha256.Sum256(payload)
	var expiresAt *time.Time
	if retained {
		expires := now.Add(7 * 24 * time.Hour)
		expiresAt = &expires
	}
	return &ReportSnapshot{
		ID:           "report_snapshot:" + strings.TrimSpace(runID),
		ResultSchema: definition.ResultSchema,
		GeneratedAt:  now,
		RecordedAt:   now,
		ContentHash:  hex.EncodeToString(sum[:]),
		ByteSize:     len(payload),
		SectionCount: len(definition.Sections),
		Retained:     retained,
		ExpiresAt:    expiresAt,
		Storage:      BuildReportStoragePolicy(true, false),
	}, nil
}

// BuildReportRunCacheKey generates a stable cache key for one report definition + parameter binding set.
func BuildReportRunCacheKey(reportID string, values []ReportParameterValue) (string, error) {
	normalized := append([]ReportParameterValue(nil), values...)
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})
	payload, err := json.Marshal(struct {
		ReportID   string                 `json:"report_id"`
		Parameters []ReportParameterValue `json:"parameters,omitempty"`
	}{
		ReportID:   strings.TrimSpace(reportID),
		Parameters: normalized,
	})
	if err != nil {
		return "", fmt.Errorf("marshal report cache key payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// SummarizeReportRun strips the variable report payload while preserving execution metadata.
func SummarizeReportRun(run ReportRun) ReportRunSummary {
	return ReportRunSummary{
		ID:              run.ID,
		ReportID:        run.ReportID,
		Status:          run.Status,
		ExecutionMode:   run.ExecutionMode,
		SubmittedAt:     run.SubmittedAt,
		StartedAt:       cloneTimePtr(run.StartedAt),
		CompletedAt:     cloneTimePtr(run.CompletedAt),
		RequestedBy:     run.RequestedBy,
		Parameters:      CloneReportParameterValues(run.Parameters),
		TimeSlice:       cloneReportTimeSlice(run.TimeSlice),
		CacheKey:        run.CacheKey,
		JobID:           run.JobID,
		JobStatusURL:    run.JobStatusURL,
		StatusURL:       run.StatusURL,
		LatestAttemptID: run.LatestAttemptID,
		AttemptCount:    len(run.Attempts),
		EventCount:      len(run.Events),
		RetryPolicy:     NormalizeReportRetryPolicy(run.RetryPolicy),
		Lineage:         CloneReportLineage(run.Lineage),
		Storage:         CloneReportStoragePolicy(run.Storage),
		Snapshot:        cloneReportSnapshot(run.Snapshot),
		Sections:        CloneReportSectionResults(run.Sections),
		Error:           run.Error,
	}
}

// CloneReportRun returns a deep-enough copy for API storage and response safety.
func CloneReportRun(run *ReportRun) *ReportRun {
	if run == nil {
		return nil
	}
	cloned := *run
	cloned.StartedAt = cloneTimePtr(run.StartedAt)
	cloned.CompletedAt = cloneTimePtr(run.CompletedAt)
	cloned.Parameters = CloneReportParameterValues(run.Parameters)
	cloned.TimeSlice = cloneReportTimeSlice(run.TimeSlice)
	cloned.RetryPolicy = NormalizeReportRetryPolicy(run.RetryPolicy)
	cloned.Lineage = CloneReportLineage(run.Lineage)
	cloned.Storage = CloneReportStoragePolicy(run.Storage)
	cloned.Snapshot = cloneReportSnapshot(run.Snapshot)
	cloned.Sections = CloneReportSectionResults(run.Sections)
	cloned.Result = cloneReportResult(run.Result)
	cloned.Attempts = CloneReportRunAttempts(run.Attempts)
	cloned.Events = CloneReportRunEvents(run.Events)
	cloned.AttemptCount = len(cloned.Attempts)
	cloned.EventCount = len(cloned.Events)
	return &cloned
}

func CloneReportParameterValues(values []ReportParameterValue) []ReportParameterValue {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]ReportParameterValue, 0, len(values))
	for _, value := range values {
		item := value
		item.IntegerValue = cloneInt64Ptr(value.IntegerValue)
		item.NumberValue = cloneFloat64Ptr(value.NumberValue)
		item.BooleanValue = cloneBoolPtr(value.BooleanValue)
		item.TimestampValue = cloneTimePtr(value.TimestampValue)
		cloned = append(cloned, item)
	}
	return cloned
}

func CloneReportSectionResults(values []ReportSectionResult) []ReportSectionResult {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]ReportSectionResult(nil), values...)
	for i := range cloned {
		cloned[i].MeasureIDs = append([]string(nil), values[i].MeasureIDs...)
		cloned[i].FieldKeys = append([]string(nil), values[i].FieldKeys...)
	}
	return cloned
}

func cloneReportSnapshot(snapshot *ReportSnapshot) *ReportSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	cloned.ExpiresAt = cloneTimePtr(snapshot.ExpiresAt)
	cloned.Lineage = CloneReportLineage(snapshot.Lineage)
	cloned.Storage = CloneReportStoragePolicy(snapshot.Storage)
	return &cloned
}

func cloneReportResult(result map[string]any) map[string]any {
	return cloneAnyMap(result)
}

func reportEnvelopeKindForSection(kind string) string {
	switch strings.TrimSpace(kind) {
	case "scorecard", "context", "health_summary", "calibration_summary", "freshness_summary", "readiness_summary", "capability_summary", "backtest_summary":
		return "summary"
	case "timeseries_summary":
		return "timeseries"
	case "distribution", "coverage_breakdown", "health_breakdown", "breakdown_table":
		return "distribution"
	case "ranked_findings", "ranked_backlog", "action_list":
		return "ranking"
	case "embedded_report":
		return "embedded_report"
	default:
		return "object"
	}
}

func sortedReportFieldKeys(values map[string]any) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneReportTimeSlice(slice ReportTimeSlice) ReportTimeSlice {
	return ReportTimeSlice{
		AsOf:       cloneTimePtr(slice.AsOf),
		From:       cloneTimePtr(slice.From),
		To:         cloneTimePtr(slice.To),
		ValidAt:    cloneTimePtr(slice.ValidAt),
		RecordedAt: cloneTimePtr(slice.RecordedAt),
	}
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func cloneInt64Ptr(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneFloat64Ptr(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
