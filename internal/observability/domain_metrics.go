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

// SourceRuntimeSyncMetrics is intentionally shaped for low-cardinality OTEL
// metrics. Runtime IDs, tenant IDs, resource URNs, evidence IDs, request IDs,
// and trace IDs belong in spans/wide events, not metric labels.
type SourceRuntimeSyncMetrics struct {
	SourceID            string
	Status              string
	ErrorKind           string
	ContractConfigured  bool
	Duration            time.Duration
	PagesRead           uint32
	RecordsScanned      uint32
	RecordsAccepted     uint32
	RecordsRejected     uint32
	EventsAppended      uint32
	EntitiesProjected   uint32
	LinksProjected      uint32
	WatermarkLagSeconds int64
	HasWatermarkLag     bool
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

func maxInt64(value int64, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}
