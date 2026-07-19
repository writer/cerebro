package observability

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/writer/cerebro/internal/decisionworkflow"
)

func TestDecisionMetricsUseOnlyBoundedDimensions(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)

	metrics := DecisionMetrics{
		Workflow:      decisionworkflow.WorkflowFindingToVerifiedFix,
		DecisionState: decisionworkflow.DecisionSupportedWithGaps,
		CoverageState: decisionworkflow.CoveragePartial,
		ActionState:   decisionworkflow.ActionProposal,
		Outcome:       decisionworkflow.OutcomeVerifiedClosed,
		Duration:      2 * time.Second, FreshnessAge: 10 * time.Minute, HasDuration: true, HasFreshnessAge: true,
	}
	RecordDecisionRequested(context.Background(), metrics)
	RecordDecisionPacketBuilt(context.Background(), metrics)
	RecordDecisionAction(context.Background(), metrics)
	RecordDecisionOutcome(context.Background(), metrics, decisionworkflow.Completion{
		Workflow: decisionworkflow.WorkflowFindingToVerifiedFix, DecisionID: "decision-1",
		DecisionState: decisionworkflow.DecisionSupportedWithGaps, Outcome: decisionworkflow.OutcomeVerifiedClosed,
		AuthenticatedTenant: true, Durable: true,
	})

	collected := collectMetrics(t, reader)
	for _, name := range []string{
		"cerebro_decisions_requested_total",
		"cerebro_decision_packets_built_total",
		"cerebro_decisions_completed_total",
		"cerebro_decision_actions_total",
		"cerebro_decision_outcomes_total",
		"cerebro_decision_duration_seconds",
		"cerebro_decision_evidence_freshness_seconds",
	} {
		metric, ok := collected[name]
		if !ok {
			t.Fatalf("metric %q missing from %#v", name, metricNames(collected))
		}
		assertNoForbiddenMetricAttributes(t, metric)
	}
	assertMetricHasAttribute(t, collected["cerebro_decisions_completed_total"], "workflow", "finding_to_verified_fix")
	assertMetricHasAttribute(t, collected["cerebro_decisions_completed_total"], "outcome", "verified_closed")
}

func TestReopenedOutcomeDoesNotIncrementCompletedDecisions(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)

	metrics := DecisionMetrics{
		Workflow: decisionworkflow.WorkflowFindingToVerifiedFix, DecisionState: decisionworkflow.DecisionSupported,
		CoverageState: decisionworkflow.CoverageComplete, ActionState: decisionworkflow.ActionVerified,
		Outcome: decisionworkflow.OutcomeReopened,
	}
	RecordDecisionOutcome(context.Background(), metrics, decisionworkflow.Completion{
		Workflow: decisionworkflow.WorkflowFindingToVerifiedFix, DecisionID: "decision-1",
		DecisionState: decisionworkflow.DecisionSupported, Outcome: decisionworkflow.OutcomeReopened,
		AuthenticatedTenant: true, Durable: true, Reopened: true,
	})

	collected := collectMetrics(t, reader)
	if _, ok := collected["cerebro_decisions_completed_total"]; ok {
		t.Fatal("reopened outcome emitted a completed-decision metric")
	}
	if got := int64MetricTotal(collected["cerebro_decision_outcomes_total"]); got != 1 {
		t.Fatalf("outcome total = %d, want 1", got)
	}
}

func int64MetricTotal(metric metricdata.Metrics) int64 {
	data, ok := metric.Data.(metricdata.Sum[int64])
	if !ok {
		return 0
	}
	var total int64
	for _, point := range data.DataPoints {
		total += point.Value
	}
	return total
}
