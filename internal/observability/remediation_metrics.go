package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

// RemediationOutcomeMetrics uses only bounded contract states and action
// catalog values. Tenant, finding, execution, and verification IDs stay out of
// metric labels.
type RemediationOutcomeMetrics struct {
	ActionType          string
	VerificationState   string
	CensoredReason      string
	SourceHealth        string
	ProviderSucceeded   bool
	VerificationLatency time.Duration
	HasLatency          bool
}

// ResolutionEpisodeMetrics uses bounded lifecycle states. Finding and episode
// identifiers belong in the read model, not metric labels.
type ResolutionEpisodeMetrics struct {
	ResolutionType   string
	DurabilityState  string
	SourceHealth     string
	TimeToResolution time.Duration
	TimeToRecurrence time.Duration
	HasResolution    bool
	HasRecurrence    bool
}

func remediationOutcomeCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.remediation.outcomes",
		otelmetric.WithDescription("Derived remediation results by verification, censoring, source health, and action state."),
	)
	return instrument
}

func remediationVerificationLatency() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.remediation.verification_latency",
		otelmetric.WithDescription("Elapsed time from action completion to fresh complete verification."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func resolutionEpisodeCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro.remediation.episodes",
		otelmetric.WithDescription("Derived resolution episodes by resolution, durability, and source-health state."),
	)
	return instrument
}

func resolutionEpisodeDuration() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro.remediation.episode_duration",
		otelmetric.WithDescription("Time to finding resolution or recurrence for derived remediation episodes."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func RecordRemediationOutcome(ctx context.Context, metrics RemediationOutcomeMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("action_type", boundedMetricValue(metrics.ActionType, "unknown")),
		attribute.String("verification_state", boundedMetricValue(metrics.VerificationState, "unknown")),
		attribute.String("censored_reason", boundedMetricValue(metrics.CensoredReason, "none")),
		attribute.String("source_health", boundedMetricValue(metrics.SourceHealth, "unknown")),
		attribute.Bool("provider_succeeded", metrics.ProviderSucceeded),
	}
	remediationOutcomeCounter().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.HasLatency && metrics.VerificationLatency >= 0 {
		remediationVerificationLatency().Record(ctx, metrics.VerificationLatency.Seconds(), otelmetric.WithAttributes(attrs...))
	}
}

func RecordResolutionEpisode(ctx context.Context, metrics ResolutionEpisodeMetrics) {
	attrs := []attribute.KeyValue{
		attribute.String("resolution_type", boundedMetricValue(metrics.ResolutionType, "none")),
		attribute.String("durability_state", boundedMetricValue(metrics.DurabilityState, "unknown")),
		attribute.String("source_health", boundedMetricValue(metrics.SourceHealth, "unknown")),
	}
	resolutionEpisodeCounter().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.HasResolution && metrics.TimeToResolution >= 0 {
		resolutionAttrs := append(cloneMetricAttributes(attrs), attribute.String("duration_kind", "resolution"))
		resolutionEpisodeDuration().Record(ctx, metrics.TimeToResolution.Seconds(), otelmetric.WithAttributes(resolutionAttrs...))
	}
	if metrics.HasRecurrence && metrics.TimeToRecurrence >= 0 {
		recurrenceAttrs := append(cloneMetricAttributes(attrs), attribute.String("duration_kind", "recurrence"))
		resolutionEpisodeDuration().Record(ctx, metrics.TimeToRecurrence.Seconds(), otelmetric.WithAttributes(recurrenceAttrs...))
	}
}
