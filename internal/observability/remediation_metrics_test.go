package observability

import (
	"context"
	"testing"
	"time"
)

func TestRemediationMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)

	RecordRemediationOutcome(context.Background(), RemediationOutcomeMetrics{
		ActionType: "identity.okta.suspend_user", VerificationState: "censored",
		CensoredReason: "source_unhealthy", SourceHealth: "unhealthy", ProviderSucceeded: true,
	})
	RecordResolutionEpisode(context.Background(), ResolutionEpisodeMetrics{
		ResolutionType: "verified", DurabilityState: "recurred", SourceHealth: "healthy",
		TimeToResolution: 24 * time.Hour, TimeToRecurrence: 30 * 24 * time.Hour,
		HasResolution: true, HasRecurrence: true,
	})

	metrics := collectMetrics(t, reader)
	for _, name := range []string{
		"cerebro.remediation.outcomes",
		"cerebro.remediation.episodes",
		"cerebro.remediation.episode_duration",
	} {
		metric, ok := metrics[name]
		if !ok {
			t.Fatalf("metric %q missing from %#v", name, metricNames(metrics))
		}
		assertNoForbiddenMetricAttributes(t, metric)
	}
	assertMetricHasAttribute(t, metrics["cerebro.remediation.outcomes"], "verification_state", "censored")
	assertMetricHasAttribute(t, metrics["cerebro.remediation.outcomes"], "censored_reason", "source_unhealthy")
	assertMetricHasBoolAttribute(t, metrics["cerebro.remediation.outcomes"], "provider_succeeded", true)
	assertMetricHasAttribute(t, metrics["cerebro.remediation.episodes"], "durability_state", "recurred")
}

func TestVerifiedRemediationRecordsVerificationLatency(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)
	RecordRemediationOutcome(context.Background(), RemediationOutcomeMetrics{
		ActionType: "identity.okta.suspend_user", VerificationState: "verified_closed",
		SourceHealth: "healthy", ProviderSucceeded: true,
		VerificationLatency: 5 * time.Minute, HasLatency: true,
	})
	metrics := collectMetrics(t, reader)
	metric, ok := metrics["cerebro.remediation.verification_latency"]
	if !ok {
		t.Fatalf("verification latency metric missing from %#v", metricNames(metrics))
	}
	assertNoForbiddenMetricAttributes(t, metric)
}
