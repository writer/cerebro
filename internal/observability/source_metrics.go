package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

const (
	SourceSyncOutcomeCompleted = "completed"
	SourceSyncOutcomeFailed    = "failed"
	SourceSyncOutcomeSkipped   = "skipped"
)

// SourceSyncMetrics describes one orchestrator decision for one source
// runtime. Metric labels stay keyed by source_id: runtime IDs and tenant IDs
// can number in the hundreds per source and belong in spans/wide events. The
// lag and failure-count instruments are histograms rather than gauges so that
// several runtimes of the same source aggregate (max = worst runtime) instead
// of overwriting each other.
type SourceSyncMetrics struct {
	SourceID     string
	Outcome      string
	FailureClass string
	SkipReason   string
	// ConsecutiveFailures is recorded only when HasConsecutiveFailures is set,
	// so a missing schedule store never reports a healthy zero.
	ConsecutiveFailures    uint32
	HasConsecutiveFailures bool
	CircuitOpen            bool
	// Nil lag values are unknown and are not recorded.
	SyncLagSeconds      *int64
	WatermarkLagSeconds *int64
	GraphLagSeconds     *int64
}

func otelSourceSyncRuns() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source.sync.runs",
		otelmetric.WithDescription("Orchestrator source sync decisions by bounded source, outcome, failure class, and skip reason."),
	)
	return instrument
}

func otelSourceFreshnessLag() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.source.freshness.lag",
		otelmetric.WithDescription("Source runtime sync, watermark, and graph lag observed by the orchestrator."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func otelSourceSyncConsecutiveFailures() otelmetric.Int64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Histogram(
		"cerebro.source.sync.consecutive_failures",
		otelmetric.WithDescription("Consecutive failed syncs per source runtime as stored by the sync schedule."),
	)
	return instrument
}

func otelSourceSyncCircuitOpen() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.source.sync.circuit_open",
		otelmetric.WithDescription("Orchestrator decisions that observed an open sync circuit for a source runtime."),
	)
	return instrument
}

// RecordSourceSync records one orchestrator source sync decision.
func RecordSourceSync(ctx context.Context, metrics SourceSyncMetrics) {
	source := attribute.String("source_id", boundedMetricValue(metrics.SourceID, "unknown"))
	otelSourceSyncRuns().Add(ctx, 1, otelmetric.WithAttributes(
		source,
		attribute.String("outcome", normalizeSourceSyncOutcome(metrics.Outcome)),
		attribute.String("failure_class", boundedMetricValue(metrics.FailureClass, "none")),
		attribute.String("skip_reason", boundedMetricValue(metrics.SkipReason, "none")),
	))
	recordSourceFreshnessLag(ctx, source, "sync", metrics.SyncLagSeconds)
	recordSourceFreshnessLag(ctx, source, "watermark", metrics.WatermarkLagSeconds)
	recordSourceFreshnessLag(ctx, source, "graph", metrics.GraphLagSeconds)
	if metrics.HasConsecutiveFailures {
		otelSourceSyncConsecutiveFailures().Record(ctx, int64(metrics.ConsecutiveFailures), otelmetric.WithAttributes(source))
	}
	if metrics.CircuitOpen {
		otelSourceSyncCircuitOpen().Add(ctx, 1, otelmetric.WithAttributes(source))
	}
}

func recordSourceFreshnessLag(ctx context.Context, source attribute.KeyValue, kind string, seconds *int64) {
	if seconds == nil {
		return
	}
	otelSourceFreshnessLag().Record(ctx, float64(maxInt64(*seconds, 0)), otelmetric.WithAttributes(
		source,
		attribute.String("lag.kind", kind),
	))
}

func normalizeSourceSyncOutcome(outcome string) string {
	switch value := boundedMetricValue(outcome, "unknown"); value {
	case SourceSyncOutcomeCompleted, SourceSyncOutcomeFailed, SourceSyncOutcomeSkipped:
		return value
	default:
		return "unknown"
	}
}
