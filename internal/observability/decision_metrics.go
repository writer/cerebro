package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"

	"github.com/writer/cerebro/internal/decisionworkflow"
)

// DecisionMetrics contains only bounded workflow states. Tenant, actor,
// decision, packet, evidence, and resource identifiers must remain in durable
// records and traces rather than metric attributes.
type DecisionMetrics struct {
	Workflow        decisionworkflow.Workflow
	DecisionState   decisionworkflow.DecisionState
	CoverageState   decisionworkflow.CoverageState
	ActionState     decisionworkflow.ActionState
	Outcome         decisionworkflow.Outcome
	Duration        time.Duration
	FreshnessAge    time.Duration
	HasDuration     bool
	HasFreshnessAge bool
}

func decisionRequestedCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro_decisions_requested_total",
		otelmetric.WithDescription("Evidence-backed decision requests by workflow."),
	)
	return instrument
}

func decisionPacketBuiltCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro_decision_packets_built_total",
		otelmetric.WithDescription("Decision packets built from bounded authorized evidence."),
	)
	return instrument
}

func decisionCompletedCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro_decisions_completed_total",
		otelmetric.WithDescription("Durable evidence-backed decisions with a terminal outcome."),
	)
	return instrument
}

func decisionActionCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro_decision_actions_total",
		otelmetric.WithDescription("Decision workflow actions by bounded action state."),
	)
	return instrument
}

func decisionOutcomeCounter() otelmetric.Int64Counter {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Int64Counter(
		"cerebro_decision_outcomes_total",
		otelmetric.WithDescription("Decision workflow outcomes, including incomplete and reopened results."),
	)
	return instrument
}

func decisionDurationHistogram() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro_decision_duration_seconds",
		otelmetric.WithDescription("Elapsed time to build or complete an evidence-backed decision."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func decisionEvidenceFreshnessHistogram() otelmetric.Float64Histogram {
	instrument, _ := otel.Meter("github.com/writer/cerebro/internal/observability").Float64Histogram(
		"cerebro_decision_evidence_freshness_seconds",
		otelmetric.WithDescription("Age of the oldest evidence used by a decision packet."),
		otelmetric.WithUnit("s"),
	)
	return instrument
}

func RecordDecisionRequested(ctx context.Context, metrics DecisionMetrics) {
	decisionRequestedCounter().Add(ctx, 1, otelmetric.WithAttributes(decisionMetricAttributes(metrics)...))
}

func RecordDecisionPacketBuilt(ctx context.Context, metrics DecisionMetrics) {
	attrs := decisionMetricAttributes(metrics)
	decisionPacketBuiltCounter().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if metrics.HasDuration && metrics.Duration >= 0 {
		decisionDurationHistogram().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
	}
	if metrics.HasFreshnessAge && metrics.FreshnessAge >= 0 {
		decisionEvidenceFreshnessHistogram().Record(ctx, metrics.FreshnessAge.Seconds(), otelmetric.WithAttributes(attrs...))
	}
}

func RecordDecisionAction(ctx context.Context, metrics DecisionMetrics) {
	decisionActionCounter().Add(ctx, 1, otelmetric.WithAttributes(decisionMetricAttributes(metrics)...))
}

func RecordDecisionOutcome(ctx context.Context, metrics DecisionMetrics, completion decisionworkflow.Completion) {
	attrs := decisionMetricAttributes(metrics)
	decisionOutcomeCounter().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
	if completion.Completed() {
		decisionCompletedCounter().Add(ctx, 1, otelmetric.WithAttributes(attrs...))
		if metrics.HasDuration && metrics.Duration >= 0 {
			decisionDurationHistogram().Record(ctx, metrics.Duration.Seconds(), otelmetric.WithAttributes(attrs...))
		}
	}
}

func decisionMetricAttributes(metrics DecisionMetrics) []attribute.KeyValue {
	workflow := metrics.Workflow
	switch workflow {
	case decisionworkflow.WorkflowChangeDecision, decisionworkflow.WorkflowFindingToVerifiedFix, decisionworkflow.WorkflowContinuousEvidence:
	default:
		workflow = decisionworkflow.WorkflowUnknown
	}
	decisionState := metrics.DecisionState
	switch decisionState {
	case decisionworkflow.DecisionSupported, decisionworkflow.DecisionSupportedWithGaps, decisionworkflow.DecisionBlocked,
		decisionworkflow.DecisionInsufficientEvidence, decisionworkflow.DecisionNotApplicable:
	default:
		decisionState = decisionworkflow.DecisionUnknown
	}
	return []attribute.KeyValue{
		attribute.String("workflow", string(workflow)),
		attribute.String("decision_state", string(decisionState)),
		attribute.String("coverage_state", string(normalizeMetricCoverage(metrics.CoverageState))),
		attribute.String("action_state", string(decisionworkflow.NormalizeActionState(string(metrics.ActionState)))),
		attribute.String("outcome", string(decisionworkflow.NormalizeOutcome(string(metrics.Outcome)))),
	}
}

func normalizeMetricCoverage(state decisionworkflow.CoverageState) decisionworkflow.CoverageState {
	switch state {
	case decisionworkflow.CoverageComplete, decisionworkflow.CoveragePartial, decisionworkflow.CoverageStale,
		decisionworkflow.CoverageFailed, decisionworkflow.CoverageUnconfigured, decisionworkflow.CoverageUnsupported,
		decisionworkflow.CoverageUnverified:
		return state
	default:
		return decisionworkflow.CoverageUnknown
	}
}
