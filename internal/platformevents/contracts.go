package platformevents

import (
	"fmt"
	"sort"
	"strings"

	"github.com/evalops/cerebro/internal/webhooks"
)

const (
	schemaPrefix  = "urn:cerebro:events"
	schemaVersion = "v1"
)

// LifecycleEventContract describes one first-class platform lifecycle CloudEvent payload.
type LifecycleEventContract struct {
	EventType        webhooks.EventType `json:"event_type"`
	Summary          string             `json:"summary"`
	SchemaURL        string             `json:"schema_url"`
	RequiredDataKeys []string           `json:"required_data_keys,omitempty"`
	OptionalDataKeys []string           `json:"optional_data_keys,omitempty"`
	DataSchema       map[string]any     `json:"data_schema,omitempty"`
}

// LifecycleContracts returns the platform lifecycle event contracts emitted by writeback flows.
func LifecycleContracts() []LifecycleEventContract {
	contracts := []LifecycleEventContract{
		buildContract(
			webhooks.EventPlatformClaimWritten,
			"Claim write recorded on the shared platform knowledge layer.",
			[]fieldSpec{
				{name: "claim_id", kind: "string"},
				{name: "subject_id", kind: "string"},
				{name: "predicate", kind: "string"},
				{name: "claim_type", kind: "string"},
				{name: "status", kind: "string"},
				{name: "source_system", kind: "string"},
				{name: "source_event_id", kind: "string"},
				{name: "observed_at", kind: "string", format: "date-time"},
				{name: "recorded_at", kind: "string", format: "date-time"},
				{name: "transaction_from", kind: "string", format: "date-time"},
			},
			[]fieldSpec{
				{name: "source_id", kind: "string"},
				{name: "object_id", kind: "string"},
				{name: "object_value", kind: "string"},
				{name: "evidence_ids", kind: "array", itemKind: "string"},
				{name: "supporting_claim_ids", kind: "array", itemKind: "string"},
				{name: "refuting_claim_ids", kind: "array", itemKind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformClaimAdjudicated,
			"Claim-group adjudication recorded on the shared platform knowledge layer.",
			[]fieldSpec{
				{name: "group_id", kind: "string"},
				{name: "action", kind: "string"},
				{name: "created_claim_id", kind: "string"},
				{name: "affected_claim_ids", kind: "array", itemKind: "string"},
				{name: "superseded_claim_ids", kind: "array", itemKind: "string"},
				{name: "observed_at", kind: "string", format: "date-time"},
				{name: "recorded_at", kind: "string", format: "date-time"},
			},
			[]fieldSpec{
				{name: "authoritative_claim_id", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformDecisionRecorded,
			"Decision write recorded on the shared platform workflow layer.",
			[]fieldSpec{
				{name: "decision_id", kind: "string"},
				{name: "decision_type", kind: "string"},
				{name: "status", kind: "string"},
				{name: "target_ids", kind: "array", itemKind: "string"},
				{name: "source_system", kind: "string"},
				{name: "source_event_id", kind: "string"},
				{name: "observed_at", kind: "string", format: "date-time"},
				{name: "valid_from", kind: "string", format: "date-time"},
			},
			[]fieldSpec{
				{name: "made_by", kind: "string"},
				{name: "rationale", kind: "string"},
				{name: "evidence_ids", kind: "array", itemKind: "string"},
				{name: "action_ids", kind: "array", itemKind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformOutcomeRecorded,
			"Outcome write recorded on the shared platform workflow layer.",
			[]fieldSpec{
				{name: "outcome_id", kind: "string"},
				{name: "decision_id", kind: "string"},
				{name: "outcome_type", kind: "string"},
				{name: "verdict", kind: "string"},
				{name: "impact_score", kind: "number"},
				{name: "source_system", kind: "string"},
				{name: "source_event_id", kind: "string"},
				{name: "observed_at", kind: "string", format: "date-time"},
				{name: "valid_from", kind: "string", format: "date-time"},
			},
			[]fieldSpec{
				{name: "target_ids", kind: "array", itemKind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformActionRecorded,
			"Action write recorded on the shared platform workflow layer.",
			[]fieldSpec{
				{name: "action_id", kind: "string"},
				{name: "title", kind: "string"},
				{name: "target_ids", kind: "array", itemKind: "string"},
				{name: "source_system", kind: "string"},
				{name: "source_event_id", kind: "string"},
				{name: "observed_at", kind: "string", format: "date-time"},
				{name: "valid_from", kind: "string", format: "date-time"},
				{name: "auto_generated", kind: "boolean"},
			},
			[]fieldSpec{
				{name: "decision_id", kind: "string"},
				{name: "recommendation_id", kind: "string"},
				{name: "insight_type", kind: "string"},
				{name: "summary", kind: "string"},
				{name: "status", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportRunQueued,
			"Report execution queued on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "status", kind: "string"},
				{name: "execution_mode", kind: "string"},
				{name: "submitted_at", kind: "string", format: "date-time"},
				{name: "status_url", kind: "string"},
			},
			[]fieldSpec{
				{name: "requested_by", kind: "string"},
				{name: "cache_key", kind: "string"},
				{name: "cache_status", kind: "string"},
				{name: "cache_source_run_id", kind: "string"},
				{name: "job_id", kind: "string"},
				{name: "job_status_url", kind: "string"},
				{name: "parameter_count", kind: "integer"},
				{name: "materialized_result", kind: "boolean"},
				{name: "latest_attempt_id", kind: "string"},
				{name: "attempt_count", kind: "integer"},
				{name: "event_count", kind: "integer"},
				{name: "cancel_requested_at", kind: "string", format: "date-time"},
				{name: "cancel_requested_by", kind: "string"},
				{name: "cancel_reason", kind: "string"},
				{name: "trigger_surface", kind: "string"},
				{name: "execution_surface", kind: "string"},
				{name: "execution_host", kind: "string"},
				{name: "attempt_classification", kind: "string"},
				{name: "latest_attempt_status", kind: "string"},
				{name: "retry_of_attempt_id", kind: "string"},
				{name: "retry_reason", kind: "string"},
				{name: "retry_backoff_ms", kind: "integer"},
				{name: "scheduled_for", kind: "string", format: "date-time"},
				{name: "retry_max_attempts", kind: "integer"},
				{name: "retry_base_backoff_ms", kind: "integer"},
				{name: "retry_max_backoff_ms", kind: "integer"},
				{name: "storage_class", kind: "string"},
				{name: "retention_tier", kind: "string"},
				{name: "result_truncated", kind: "boolean"},
				{name: "graph_snapshot_id", kind: "string"},
				{name: "graph_snapshot_url", kind: "string"},
				{name: "graph_built_at", kind: "string", format: "date-time"},
				{name: "graph_schema_version", kind: "integer"},
				{name: "ontology_contract_version", kind: "string"},
				{name: "report_definition_version", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportRunStarted,
			"Report execution started on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "status", kind: "string"},
				{name: "execution_mode", kind: "string"},
				{name: "submitted_at", kind: "string", format: "date-time"},
				{name: "started_at", kind: "string", format: "date-time"},
				{name: "status_url", kind: "string"},
			},
			[]fieldSpec{
				{name: "requested_by", kind: "string"},
				{name: "cache_key", kind: "string"},
				{name: "cache_status", kind: "string"},
				{name: "cache_source_run_id", kind: "string"},
				{name: "job_id", kind: "string"},
				{name: "job_status_url", kind: "string"},
				{name: "parameter_count", kind: "integer"},
				{name: "materialized_result", kind: "boolean"},
				{name: "latest_attempt_id", kind: "string"},
				{name: "attempt_count", kind: "integer"},
				{name: "event_count", kind: "integer"},
				{name: "cancel_requested_at", kind: "string", format: "date-time"},
				{name: "cancel_requested_by", kind: "string"},
				{name: "cancel_reason", kind: "string"},
				{name: "trigger_surface", kind: "string"},
				{name: "execution_surface", kind: "string"},
				{name: "execution_host", kind: "string"},
				{name: "attempt_classification", kind: "string"},
				{name: "latest_attempt_status", kind: "string"},
				{name: "retry_of_attempt_id", kind: "string"},
				{name: "retry_reason", kind: "string"},
				{name: "retry_backoff_ms", kind: "integer"},
				{name: "scheduled_for", kind: "string", format: "date-time"},
				{name: "retry_max_attempts", kind: "integer"},
				{name: "retry_base_backoff_ms", kind: "integer"},
				{name: "retry_max_backoff_ms", kind: "integer"},
				{name: "storage_class", kind: "string"},
				{name: "retention_tier", kind: "string"},
				{name: "result_truncated", kind: "boolean"},
				{name: "graph_snapshot_id", kind: "string"},
				{name: "graph_snapshot_url", kind: "string"},
				{name: "graph_built_at", kind: "string", format: "date-time"},
				{name: "graph_schema_version", kind: "integer"},
				{name: "ontology_contract_version", kind: "string"},
				{name: "report_definition_version", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportRunCompleted,
			"Report execution completed on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "status", kind: "string"},
				{name: "execution_mode", kind: "string"},
				{name: "submitted_at", kind: "string", format: "date-time"},
				{name: "completed_at", kind: "string", format: "date-time"},
				{name: "status_url", kind: "string"},
				{name: "materialized_result", kind: "boolean"},
			},
			[]fieldSpec{
				{name: "started_at", kind: "string", format: "date-time"},
				{name: "requested_by", kind: "string"},
				{name: "cache_key", kind: "string"},
				{name: "cache_status", kind: "string"},
				{name: "cache_source_run_id", kind: "string"},
				{name: "job_id", kind: "string"},
				{name: "job_status_url", kind: "string"},
				{name: "parameter_count", kind: "integer"},
				{name: "latest_attempt_id", kind: "string"},
				{name: "attempt_count", kind: "integer"},
				{name: "event_count", kind: "integer"},
				{name: "cancel_requested_at", kind: "string", format: "date-time"},
				{name: "cancel_requested_by", kind: "string"},
				{name: "cancel_reason", kind: "string"},
				{name: "trigger_surface", kind: "string"},
				{name: "execution_surface", kind: "string"},
				{name: "execution_host", kind: "string"},
				{name: "attempt_classification", kind: "string"},
				{name: "latest_attempt_status", kind: "string"},
				{name: "retry_of_attempt_id", kind: "string"},
				{name: "retry_reason", kind: "string"},
				{name: "retry_backoff_ms", kind: "integer"},
				{name: "scheduled_for", kind: "string", format: "date-time"},
				{name: "retry_max_attempts", kind: "integer"},
				{name: "retry_base_backoff_ms", kind: "integer"},
				{name: "retry_max_backoff_ms", kind: "integer"},
				{name: "storage_class", kind: "string"},
				{name: "retention_tier", kind: "string"},
				{name: "result_truncated", kind: "boolean"},
				{name: "graph_snapshot_id", kind: "string"},
				{name: "graph_snapshot_url", kind: "string"},
				{name: "graph_built_at", kind: "string", format: "date-time"},
				{name: "graph_schema_version", kind: "integer"},
				{name: "ontology_contract_version", kind: "string"},
				{name: "report_definition_version", kind: "string"},
				{name: "snapshot_id", kind: "string"},
				{name: "result_schema", kind: "string"},
				{name: "section_count", kind: "integer"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportRunFailed,
			"Report execution failed on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "status", kind: "string"},
				{name: "execution_mode", kind: "string"},
				{name: "submitted_at", kind: "string", format: "date-time"},
				{name: "completed_at", kind: "string", format: "date-time"},
				{name: "status_url", kind: "string"},
				{name: "error", kind: "string"},
			},
			[]fieldSpec{
				{name: "started_at", kind: "string", format: "date-time"},
				{name: "requested_by", kind: "string"},
				{name: "cache_key", kind: "string"},
				{name: "cache_status", kind: "string"},
				{name: "cache_source_run_id", kind: "string"},
				{name: "job_id", kind: "string"},
				{name: "job_status_url", kind: "string"},
				{name: "parameter_count", kind: "integer"},
				{name: "materialized_result", kind: "boolean"},
				{name: "latest_attempt_id", kind: "string"},
				{name: "attempt_count", kind: "integer"},
				{name: "event_count", kind: "integer"},
				{name: "cancel_requested_at", kind: "string", format: "date-time"},
				{name: "cancel_requested_by", kind: "string"},
				{name: "cancel_reason", kind: "string"},
				{name: "trigger_surface", kind: "string"},
				{name: "execution_surface", kind: "string"},
				{name: "execution_host", kind: "string"},
				{name: "attempt_classification", kind: "string"},
				{name: "latest_attempt_status", kind: "string"},
				{name: "retry_of_attempt_id", kind: "string"},
				{name: "retry_reason", kind: "string"},
				{name: "retry_backoff_ms", kind: "integer"},
				{name: "scheduled_for", kind: "string", format: "date-time"},
				{name: "retry_max_attempts", kind: "integer"},
				{name: "retry_base_backoff_ms", kind: "integer"},
				{name: "retry_max_backoff_ms", kind: "integer"},
				{name: "storage_class", kind: "string"},
				{name: "retention_tier", kind: "string"},
				{name: "result_truncated", kind: "boolean"},
				{name: "graph_snapshot_id", kind: "string"},
				{name: "graph_snapshot_url", kind: "string"},
				{name: "graph_built_at", kind: "string", format: "date-time"},
				{name: "graph_schema_version", kind: "integer"},
				{name: "ontology_contract_version", kind: "string"},
				{name: "report_definition_version", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportRunCanceled,
			"Report execution canceled on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "status", kind: "string"},
				{name: "execution_mode", kind: "string"},
				{name: "submitted_at", kind: "string", format: "date-time"},
				{name: "completed_at", kind: "string", format: "date-time"},
				{name: "status_url", kind: "string"},
				{name: "cancel_reason", kind: "string"},
			},
			[]fieldSpec{
				{name: "started_at", kind: "string", format: "date-time"},
				{name: "requested_by", kind: "string"},
				{name: "cache_key", kind: "string"},
				{name: "cache_status", kind: "string"},
				{name: "cache_source_run_id", kind: "string"},
				{name: "job_id", kind: "string"},
				{name: "job_status_url", kind: "string"},
				{name: "parameter_count", kind: "integer"},
				{name: "materialized_result", kind: "boolean"},
				{name: "latest_attempt_id", kind: "string"},
				{name: "attempt_count", kind: "integer"},
				{name: "event_count", kind: "integer"},
				{name: "cancel_requested_at", kind: "string", format: "date-time"},
				{name: "cancel_requested_by", kind: "string"},
				{name: "trigger_surface", kind: "string"},
				{name: "execution_surface", kind: "string"},
				{name: "execution_host", kind: "string"},
				{name: "attempt_classification", kind: "string"},
				{name: "latest_attempt_status", kind: "string"},
				{name: "retry_of_attempt_id", kind: "string"},
				{name: "retry_reason", kind: "string"},
				{name: "retry_backoff_ms", kind: "integer"},
				{name: "scheduled_for", kind: "string", format: "date-time"},
				{name: "retry_max_attempts", kind: "integer"},
				{name: "retry_base_backoff_ms", kind: "integer"},
				{name: "retry_max_backoff_ms", kind: "integer"},
				{name: "storage_class", kind: "string"},
				{name: "retention_tier", kind: "string"},
				{name: "result_truncated", kind: "boolean"},
				{name: "graph_snapshot_id", kind: "string"},
				{name: "graph_snapshot_url", kind: "string"},
				{name: "graph_built_at", kind: "string", format: "date-time"},
				{name: "graph_schema_version", kind: "integer"},
				{name: "ontology_contract_version", kind: "string"},
				{name: "report_definition_version", kind: "string"},
				{name: "error", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportSectionEmitted,
			"Report section payload emitted on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "section_key", kind: "string"},
				{name: "sequence", kind: "integer"},
				{name: "emitted_at", kind: "string", format: "date-time"},
				{name: "status_url", kind: "string"},
			},
			[]fieldSpec{
				{name: "status", kind: "string"},
				{name: "progress_percent", kind: "integer"},
				{name: "envelope_kind", kind: "string"},
				{name: "envelope_schema", kind: "string"},
				{name: "content_type", kind: "string"},
				{name: "item_count", kind: "integer"},
				{name: "field_count", kind: "integer"},
				{name: "field_keys", kind: "array", itemKind: "string"},
				{name: "measure_ids", kind: "array", itemKind: "string"},
				{name: "payload_schema", kind: "string"},
				{name: "payload_schema_url", kind: "string"},
				{name: "payload_strict", kind: "boolean"},
				{name: "lineage", kind: "object"},
				{name: "materialization", kind: "object"},
				{name: "telemetry", kind: "object"},
				{name: "snapshot_id", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
		buildContract(
			webhooks.EventPlatformReportSnapshotMaterialized,
			"Report snapshot materialized on the shared platform intelligence layer.",
			[]fieldSpec{
				{name: "snapshot_id", kind: "string"},
				{name: "run_id", kind: "string"},
				{name: "report_id", kind: "string"},
				{name: "result_schema", kind: "string"},
				{name: "generated_at", kind: "string", format: "date-time"},
				{name: "recorded_at", kind: "string", format: "date-time"},
				{name: "content_hash", kind: "string"},
				{name: "byte_size", kind: "integer"},
				{name: "section_count", kind: "integer"},
				{name: "retained", kind: "boolean"},
				{name: "status_url", kind: "string"},
			},
			[]fieldSpec{
				{name: "expires_at", kind: "string", format: "date-time"},
				{name: "cache_key", kind: "string"},
				{name: "storage_class", kind: "string"},
				{name: "retention_tier", kind: "string"},
				{name: "materialized_result", kind: "boolean"},
				{name: "result_truncated", kind: "boolean"},
				{name: "graph_snapshot_id", kind: "string"},
				{name: "graph_snapshot_url", kind: "string"},
				{name: "graph_built_at", kind: "string", format: "date-time"},
				{name: "graph_schema_version", kind: "integer"},
				{name: "ontology_contract_version", kind: "string"},
				{name: "report_definition_version", kind: "string"},
				{name: "tenant_id", kind: "string"},
				{name: "traceparent", kind: "string"},
			},
		),
	}
	sort.Slice(contracts, func(i, j int) bool {
		return strings.Compare(string(contracts[i].EventType), string(contracts[j].EventType)) < 0
	})
	return contracts
}

type fieldSpec struct {
	name     string
	kind     string
	format   string
	itemKind string
}

func buildContract(eventType webhooks.EventType, summary string, required, optional []fieldSpec) LifecycleEventContract {
	properties := make(map[string]any, len(required)+len(optional))
	requiredKeys := make([]string, 0, len(required))
	optionalKeys := make([]string, 0, len(optional))
	for _, field := range required {
		requiredKeys = append(requiredKeys, field.name)
		properties[field.name] = schemaForField(field)
	}
	for _, field := range optional {
		optionalKeys = append(optionalKeys, field.name)
		properties[field.name] = schemaForField(field)
	}
	return LifecycleEventContract{
		EventType:        eventType,
		Summary:          strings.TrimSpace(summary),
		SchemaURL:        schemaURLFor(eventType),
		RequiredDataKeys: requiredKeys,
		OptionalDataKeys: optionalKeys,
		DataSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             requiredKeys,
			"properties":           properties,
		},
	}
}

func schemaForField(field fieldSpec) map[string]any {
	schema := map[string]any{"type": field.kind}
	if strings.TrimSpace(field.format) != "" {
		schema["format"] = strings.TrimSpace(field.format)
	}
	if field.kind == "array" {
		itemType := strings.TrimSpace(field.itemKind)
		if itemType == "" {
			itemType = "string"
		}
		schema["items"] = map[string]any{"type": itemType}
	}
	return schema
}

func schemaURLFor(eventType webhooks.EventType) string {
	normalized := strings.ToLower(strings.TrimSpace(string(eventType)))
	if normalized == "" {
		normalized = "unknown"
	}
	normalized = strings.ReplaceAll(normalized, " ", "-")
	return fmt.Sprintf("%s/%s/%s", schemaPrefix, normalized, schemaVersion)
}
