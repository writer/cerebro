package observability

import (
	"context"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

func otelSourceRuntimeRuns() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source_runtime.sync.runs",
		otelmetric.WithDescription("Total source runtime sync attempts."),
	)
	return instrument
}

func otelContentPackSelections() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.content_pack.selections",
		otelmetric.WithDescription("Content packs accepted, rejected, or replaced by embedded content at startup."),
	)
	return instrument
}

func otelSourceRuntimeDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.source_runtime.sync.duration",
		otelmetric.WithDescription("Source runtime sync duration."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelSourceRuntimeRecords() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source_runtime.records",
		otelmetric.WithDescription("Source runtime records read, accepted, rejected, appended, or projected."),
	)
	return instrument
}

func otelSourceRuntimeWatermarkLag() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.source_runtime.watermark.lag",
		otelmetric.WithDescription("Observed source runtime checkpoint watermark lag."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelSourceRuntimeShortCircuits() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source_runtime.sync.short_circuits",
		otelmetric.WithDescription("Source runtime syncs that intentionally skipped full work after an unchanged or advanced checkpoint."),
	)
	return instrument
}

func otelSourceProjectionRuns() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source_projection.runs",
		otelmetric.WithDescription("Total source projection attempts."),
	)
	return instrument
}

func otelSourceProjectionDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.source_projection.duration",
		otelmetric.WithDescription("Source projection duration."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelSourceProjectionRecords() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source_projection.records",
		otelmetric.WithDescription("Source projection records materialized or deleted."),
	)
	return instrument
}

func otelGraphActionRecorded() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.graph_action.recorded",
		otelmetric.WithDescription("Total graph action workflow records by bounded provider, action, and status."),
	)
	return instrument
}

func otelGraphRuleEvaluations() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.graph_rule.evaluations",
		otelmetric.WithDescription("Total graph rule evaluations by bounded source, rule, status, and error class."),
	)
	return instrument
}

func otelGraphRuleDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.graph_rule.duration",
		otelmetric.WithDescription("Graph rule evaluation duration by bounded source, rule, status, and error class."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelGraphRuleRecords() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.graph_rule.records",
		otelmetric.WithDescription("Graph rule rows read and findings emitted by bounded source, rule, status, and error class."),
	)
	return instrument
}

func otelNeo4jOperations() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.neo4j.operations",
		otelmetric.WithDescription("Total Neo4j operations by operation, status, and error class."),
	)
	return instrument
}

func otelNeo4jOperationDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.neo4j.operation.duration",
		otelmetric.WithDescription("Neo4j operation duration by operation, status, and error class."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelOrchestratorPhaseRuns() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.orchestrator.phase.runs",
		otelmetric.WithDescription("Total orchestrator phase attempts by bounded phase, source, status, and error class."),
	)
	return instrument
}

func otelOrchestratorPhaseDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.orchestrator.phase.duration",
		otelmetric.WithDescription("Orchestrator phase duration by bounded phase, source, status, and error class."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelOrchestratorPhaseSkips() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.orchestrator.phase.skips",
		otelmetric.WithDescription("Orchestrator phases skipped before execution by bounded phase, source, and skip reason."),
	)
	return instrument
}

func otelJetStreamPublishRequests() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.jetstream.publish.requests",
		otelmetric.WithDescription("Total JetStream publish requests by bounded subject, operation, status, and error category."),
	)
	return instrument
}

func otelJetStreamPublishRetries() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.jetstream.publish.retries",
		otelmetric.WithDescription("Total JetStream publish retry attempts by bounded subject, operation, status, and error category."),
	)
	return instrument
}

func otelJetStreamPublishDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.jetstream.publish.duration",
		otelmetric.WithDescription("JetStream publish duration by bounded subject, operation, status, and error category."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelJetStreamPublishMaxAttemptsExhausted() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.jetstream.publish.max_attempts_exhausted",
		otelmetric.WithDescription("Total JetStream publish requests that exhausted all configured attempts."),
	)
	return instrument
}

func otelJetStreamReplayRequests() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.jetstream.replay.requests",
		otelmetric.WithDescription("Total JetStream replay requests by strategy, status, and error category."),
	)
	return instrument
}

func otelJetStreamReplayDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.jetstream.replay.duration",
		otelmetric.WithDescription("JetStream replay duration by strategy, status, and error category."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelJetStreamReplayRecords() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.jetstream.replay.records",
		otelmetric.WithDescription("JetStream replay records scanned, decoded, matched, missing, or returned."),
	)
	return instrument
}

// SourceRuntimeSyncMetrics is intentionally shaped for low-cardinality OTEL
// metrics. Runtime IDs, tenant IDs, resource URNs, evidence IDs, request IDs,
// and trace IDs belong in spans/wide events, not metric labels.
type SourceRuntimeSyncMetrics struct {
	SourceID             string
	Status               string
	ErrorKind            string
	ContractConfigured   bool
	Duration             time.Duration
	PagesRead            uint32
	RecordsScanned       uint32
	RecordsAccepted      uint32
	RecordsRejected      uint32
	EventsAppended       uint32
	EntitiesProjected    uint32
	LinksProjected       uint32
	WatermarkLagSeconds  int64
	HasWatermarkLag      bool
	ShortCircuitReason   string
	ReconciliationReason string
}

type ContentPackSelectionMetrics struct {
	Kind   string
	Status string
	Count  int64
}

func RecordContentPackSelection(ctx context.Context, metrics ContentPackSelectionMetrics) {
	if metrics.Count <= 0 {
		return
	}
	otelContentPackSelections().Add(ctx, metrics.Count, otelmetric.WithAttributes(
		attribute.String("pack.kind", boundedMetricValue(metrics.Kind, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
	))
}

// SourceProjectionMetrics is intentionally scoped to bounded event dimensions.
type SourceProjectionMetrics struct {
	SourceID          string
	EventKind         string
	Status            string
	Duration          time.Duration
	EntitiesProjected uint32
	LinksProjected    uint32
	EntitiesDeleted   uint32
	LinksDeleted      uint32
}

// GraphActionMetrics is intentionally scoped to provider catalog dimensions.
// Tenant IDs, finding IDs, resource URNs, external IDs, request IDs, and trace
// IDs belong in workflow events/spans rather than metric labels.
type GraphActionMetrics struct {
	Provider       string
	Action         string
	Status         string
	ExternalStatus string
	DryRun         bool
}

// GraphRuleEvaluationMetrics is intentionally scoped to bounded catalog data.
// Tenant IDs, runtime IDs, finding IDs, graph URNs, trace IDs, and evidence IDs
// belong in spans/wide events rather than metric labels.
type GraphRuleEvaluationMetrics struct {
	SourceID  string
	RuleID    string
	Status    string
	ErrorKind string
	Duration  time.Duration
	RowsRead  uint32
	Findings  int
	Truncated bool
}

// Neo4jOperationMetrics keeps database telemetry low-cardinality. Database
// names, query text, parameters, and resource identifiers belong in traces or
// local diagnostics, not metric labels.
type Neo4jOperationMetrics struct {
	Operation          string
	Status             string
	ErrorKind          string
	Duration           time.Duration
	DatabaseConfigured bool
}

// OrchestratorPhaseMetrics records the SLO boundary around each orchestrator
// phase without promoting tenant/runtime IDs into metrics.
type OrchestratorPhaseMetrics struct {
	PhaseKey        string
	SourceID        string
	Status          string
	ErrorKind       string
	Duration        time.Duration
	TimeoutExceeded bool
}

// OrchestratorPhaseSkipMetrics records work intentionally not run. Runtime IDs
// and tenant IDs belong in spans/wide events, not metric labels.
type OrchestratorPhaseSkipMetrics struct {
	PhaseKey   string
	SourceID   string
	SkipReason string
}

// JetStreamPublishMetrics is intentionally scoped to bounded operational
// dimensions. Message IDs, tenant IDs, runtime IDs, and resource identifiers
// belong in spans/wide events rather than metric labels.
type JetStreamPublishMetrics struct {
	Subject              string
	Operation            string
	Status               string
	ErrorCategory        string
	Duration             time.Duration
	RetryCount           int
	MaxAttemptsExhausted bool
}

// JetStreamReplayMetrics is intentionally scoped to operational dimensions.
// Runtime IDs, tenant IDs, event IDs, subjects, and request IDs belong in spans
// and wide events rather than metric labels.
type JetStreamReplayMetrics struct {
	Strategy             string
	Status               string
	ErrorCategory        string
	Duration             time.Duration
	Scanned              uint64
	Missing              uint64
	SubjectMatched       uint64
	Decoded              uint64
	Matched              uint64
	Returned             uint64
	SubjectFilterPresent bool
}

func RecordSourceRuntimeSync(ctx context.Context, metrics SourceRuntimeSyncMetrics) {
	status := boundedMetricValue(metrics.Status, "unknown")
	attrs := []attribute.KeyValue{
		attribute.String("source_id", boundedMetricValue(metrics.SourceID, "unknown")),
		attribute.String("status", status),
		attribute.String("error_kind", boundedMetricValue(metrics.ErrorKind, "none")),
		attribute.Bool("contract_configured", metrics.ContractConfigured),
	}
	otelSourceRuntimeRuns().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelSourceRuntimeDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
	if strings.TrimSpace(metrics.ShortCircuitReason) != "" {
		shortCircuitAttrs := append(cloneMetricAttributes(attrs),
			attribute.String("short_circuit_reason", boundedMetricValue(metrics.ShortCircuitReason, "unknown")),
			attribute.String("reconciliation_reason", boundedMetricValue(metrics.ReconciliationReason, "none")),
		)
		otelSourceRuntimeShortCircuits().Add(ctx, 1, otelmetric.WithAttributes(shortCircuitAttrs...))
	}
	recordSourceRuntimeRecordCount(ctx, attrs, "page", int64(metrics.PagesRead))
	recordSourceRuntimeRecordCount(ctx, attrs, "scanned", int64(metrics.RecordsScanned))
	recordSourceRuntimeRecordCount(ctx, attrs, "accepted", int64(metrics.RecordsAccepted))
	recordSourceRuntimeRecordCount(ctx, attrs, "rejected", int64(metrics.RecordsRejected))
	recordSourceRuntimeRecordCount(ctx, attrs, "appended", int64(metrics.EventsAppended))
	recordSourceRuntimeRecordCount(ctx, attrs, "entity_projected", int64(metrics.EntitiesProjected))
	recordSourceRuntimeRecordCount(ctx, attrs, "link_projected", int64(metrics.LinksProjected))
	if metrics.HasWatermarkLag {
		otelSourceRuntimeWatermarkLag().Record(ctx, float64(maxInt64(metrics.WatermarkLagSeconds, 0)), otelmetric.WithAttributes(attrs...))
	}
}

func RecordSourceProjection(ctx context.Context, metrics SourceProjectionMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("source_id", boundedMetricValue(metrics.SourceID, "unknown")),
		attribute.String("event_kind", boundedMetricValue(metrics.EventKind, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
	}
	otelSourceProjectionRuns().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelSourceProjectionDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
	recordSourceProjectionRecordCount(ctx, attrs, "entity_projected", int64(metrics.EntitiesProjected))
	recordSourceProjectionRecordCount(ctx, attrs, "link_projected", int64(metrics.LinksProjected))
	recordSourceProjectionRecordCount(ctx, attrs, "entity_deleted", int64(metrics.EntitiesDeleted))
	recordSourceProjectionRecordCount(ctx, attrs, "link_deleted", int64(metrics.LinksDeleted))
}

func RecordGraphAction(ctx context.Context, metrics GraphActionMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("provider", boundedMetricValue(metrics.Provider, "unknown")),
		attribute.String("action", boundedMetricValue(metrics.Action, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
		attribute.String("external_status", boundedMetricValue(metrics.ExternalStatus, "none")),
		attribute.Bool("dry_run", metrics.DryRun),
	}
	otelGraphActionRecorded().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
}

func RecordGraphRuleEvaluation(ctx context.Context, metrics GraphRuleEvaluationMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("source_id", boundedMetricValue(metrics.SourceID, "unknown")),
		attribute.String("rule_id", boundedMetricValue(metrics.RuleID, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
		attribute.String("error_kind", boundedMetricValue(metrics.ErrorKind, "none")),
		attribute.Bool("truncated", metrics.Truncated),
	}
	otelGraphRuleEvaluations().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelGraphRuleDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
	recordGraphRuleRecordCount(ctx, attrs, "row_read", int64(metrics.RowsRead))
	recordGraphRuleRecordCount(ctx, attrs, "finding_emitted", int64(metrics.Findings))
}

func RecordNeo4jOperation(ctx context.Context, metrics Neo4jOperationMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", boundedMetricValue(metrics.Operation, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
		attribute.String("error_kind", boundedMetricValue(metrics.ErrorKind, "none")),
		attribute.Bool("database_configured", metrics.DatabaseConfigured),
	}
	otelNeo4jOperations().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelNeo4jOperationDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
}

func RecordOrchestratorPhase(ctx context.Context, metrics OrchestratorPhaseMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("phase_key", boundedMetricValue(metrics.PhaseKey, "unknown")),
		attribute.String("source_id", boundedMetricValue(metrics.SourceID, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
		attribute.String("error_kind", boundedMetricValue(metrics.ErrorKind, "none")),
		attribute.Bool("timeout_exceeded", metrics.TimeoutExceeded),
	}
	otelOrchestratorPhaseRuns().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelOrchestratorPhaseDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
}

func RecordOrchestratorPhaseSkip(ctx context.Context, metrics OrchestratorPhaseSkipMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("phase_key", boundedMetricValue(metrics.PhaseKey, "unknown")),
		attribute.String("source_id", boundedMetricValue(metrics.SourceID, "unknown")),
		attribute.String("skip_reason", boundedMetricValue(metrics.SkipReason, "unknown")),
	}
	otelOrchestratorPhaseSkips().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
}

func RecordJetStreamPublish(ctx context.Context, metrics JetStreamPublishMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("subject", boundedJetStreamMetricSubject(metrics.Subject)),
		attribute.String("operation", boundedMetricValue(metrics.Operation, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
		attribute.String("error_category", boundedMetricValue(metrics.ErrorCategory, "none")),
		attribute.Bool("max_attempts_exhausted", metrics.MaxAttemptsExhausted),
	}
	otelJetStreamPublishRequests().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelJetStreamPublishDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
	if metrics.RetryCount > 0 {
		otelJetStreamPublishRetries().Add(ctx, int64(metrics.RetryCount), otelmetric.WithAttributes(attrs...))
	}
	if metrics.MaxAttemptsExhausted {
		otelJetStreamPublishMaxAttemptsExhausted().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	}
}

func RecordJetStreamReplay(ctx context.Context, metrics JetStreamReplayMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("strategy", boundedMetricValue(metrics.Strategy, "unknown")),
		attribute.String("status", boundedMetricValue(metrics.Status, "unknown")),
		attribute.String("error_category", boundedMetricValue(metrics.ErrorCategory, "none")),
		attribute.Bool("subject_filter_present", metrics.SubjectFilterPresent),
	}
	otelJetStreamReplayRequests().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.Duration >= 0 {
		otelJetStreamReplayDuration().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
	recordJetStreamReplayRecordCount(ctx, attrs, "scanned", metrics.Scanned)
	recordJetStreamReplayRecordCount(ctx, attrs, "missing", metrics.Missing)
	recordJetStreamReplayRecordCount(ctx, attrs, "subject_matched", metrics.SubjectMatched)
	recordJetStreamReplayRecordCount(ctx, attrs, "decoded", metrics.Decoded)
	recordJetStreamReplayRecordCount(ctx, attrs, "matched", metrics.Matched)
	recordJetStreamReplayRecordCount(ctx, attrs, "returned", metrics.Returned)
}

func recordSourceRuntimeRecordCount(ctx context.Context, base []attribute.KeyValue, kind string, count int64) {
	if count <= 0 {
		return
	}
	attrs := append(cloneMetricAttributes(base), attribute.String("record.kind", kind))
	otelSourceRuntimeRecords().Add(ctx, count, otelmetric.WithAttributes(attrs...))
}

func recordSourceProjectionRecordCount(ctx context.Context, base []attribute.KeyValue, kind string, count int64) {
	if count <= 0 {
		return
	}
	attrs := append(cloneMetricAttributes(base), attribute.String("record.kind", kind))
	otelSourceProjectionRecords().Add(ctx, count, otelmetric.WithAttributes(attrs...))
}

func recordGraphRuleRecordCount(ctx context.Context, base []attribute.KeyValue, kind string, count int64) {
	if count <= 0 {
		return
	}
	attrs := append(cloneMetricAttributes(base), attribute.String("record.kind", kind))
	otelGraphRuleRecords().Add(ctx, count, otelmetric.WithAttributes(attrs...))
}

func recordJetStreamReplayRecordCount(ctx context.Context, base []attribute.KeyValue, kind string, count uint64) {
	if count == 0 {
		return
	}
	attrs := append(cloneMetricAttributes(base), attribute.String("record.kind", kind))
	otelJetStreamReplayRecords().Add(ctx, boundedUint64ToInt64(count), otelmetric.WithAttributes(attrs...))
}

func cloneMetricAttributes(values []attribute.KeyValue) []attribute.KeyValue {
	copied := make([]attribute.KeyValue, len(values))
	copy(copied, values)
	return copied
}

func boundedMetricValue(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	value = strings.ToLower(value)
	var out strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			out.WriteRune(char)
		case char >= '0' && char <= '9':
			out.WriteRune(char)
		case char == '.', char == '_', char == '-':
			out.WriteRune(char)
		default:
			out.WriteRune('_')
		}
		if out.Len() >= 96 {
			break
		}
	}
	if strings.Trim(out.String(), "_-.") == "" {
		return fallback
	}
	return out.String()
}

func boundedJetStreamMetricSubject(subject string) string {
	subject = boundedMetricValue(subject, "unknown")
	switch {
	case subject == "sec.findings.v1.recorded":
		return subject
	case strings.HasPrefix(subject, "sec.findings.v1."):
		return "sec.findings.v1._other"
	case strings.HasPrefix(subject, "sec."):
		return boundedMetricSubjectPrefix(subject, 4)
	case strings.HasPrefix(subject, "events.workflow.v1."):
		return boundedMetricSubjectPrefix(subject, 5)
	case strings.HasPrefix(subject, "events."):
		return boundedMetricSubjectPrefix(subject, 3)
	default:
		return subject
	}
}

func boundedMetricSubjectPrefix(subject string, maxTokens int) string {
	tokens := strings.Split(subject, ".")
	if len(tokens) <= maxTokens || maxTokens <= 0 {
		return subject
	}
	return strings.Join(tokens[:maxTokens], ".") + "._other"
}

func maxInt64(value int64, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func boundedUint64ToInt64(value uint64) int64 {
	const maxMetricInt64 = int64(1<<63 - 1)
	if value > uint64(maxMetricInt64) {
		return maxMetricInt64
	}
	return int64(value) // #nosec G115 -- value is capped above.
}
