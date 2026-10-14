package observability

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestRecordSourceSyncRecordsEveryInstrument(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)

	syncLag, watermarkLag, graphLag := int64(120), int64(3600), int64(-5)
	RecordSourceSync(context.Background(), SourceSyncMetrics{
		SourceID:               " GitHub ",
		Outcome:                SourceSyncOutcomeFailed,
		FailureClass:           "rate_limited",
		ConsecutiveFailures:    4,
		HasConsecutiveFailures: true,
		CircuitOpen:            true,
		SyncLagSeconds:         &syncLag,
		WatermarkLagSeconds:    &watermarkLag,
		GraphLagSeconds:        &graphLag,
	})

	collected := collectMetrics(t, reader)
	for _, name := range []string{
		"cerebro.source.sync.runs",
		"cerebro.source.freshness.lag",
		"cerebro.source.sync.consecutive_failures",
		"cerebro.source.sync.circuit_open",
	} {
		metric, ok := collected[name]
		if !ok {
			t.Fatalf("metric %q missing from %#v", name, metricNames(collected))
		}
		assertNoForbiddenMetricAttributes(t, metric)
		assertMetricHasAttribute(t, metric, "source_id", "github")
	}
	runs := collected["cerebro.source.sync.runs"]
	if got := int64MetricTotal(runs); got != 1 {
		t.Fatalf("runs total = %d, want 1", got)
	}
	assertMetricHasAttribute(t, runs, "outcome", "failed")
	assertMetricHasAttribute(t, runs, "failure_class", "rate_limited")
	assertMetricHasAttribute(t, runs, "skip_reason", "none")

	lags := float64HistogramByAttribute(t, collected["cerebro.source.freshness.lag"], "lag.kind")
	if len(lags) != 3 || lags["sync"].Sum != 120 || lags["watermark"].Sum != 3600 || lags["graph"].Count != 1 || lags["graph"].Sum != 0 {
		t.Fatalf("freshness lag points = %#v, want sync=120 watermark=3600 graph clamped to 0", lags)
	}
	if unit := collected["cerebro.source.freshness.lag"].Unit; unit != "s" {
		t.Fatalf("freshness lag unit = %q, want s", unit)
	}
	failures, ok := collected["cerebro.source.sync.consecutive_failures"].Data.(metricdata.Histogram[int64])
	if !ok || len(failures.DataPoints) != 1 || failures.DataPoints[0].Sum != 4 {
		t.Fatalf("consecutive failures = %#v, want one point of 4", collected["cerebro.source.sync.consecutive_failures"].Data)
	}
	if got := int64MetricTotal(collected["cerebro.source.sync.circuit_open"]); got != 1 {
		t.Fatalf("circuit open total = %d, want 1", got)
	}
}

func TestRecordSourceSyncOmitsUnknownValues(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)

	watermarkLag := int64(30)
	RecordSourceSync(context.Background(), SourceSyncMetrics{
		SourceID:            "okta",
		Outcome:             SourceSyncOutcomeSkipped,
		SkipReason:          "lease_not_acquired",
		WatermarkLagSeconds: &watermarkLag,
	})

	collected := collectMetrics(t, reader)
	for _, name := range []string{"cerebro.source.sync.consecutive_failures", "cerebro.source.sync.circuit_open"} {
		if _, ok := collected[name]; ok {
			t.Fatalf("metric %q recorded without a known value", name)
		}
	}
	lags := float64HistogramByAttribute(t, collected["cerebro.source.freshness.lag"], "lag.kind")
	if len(lags) != 1 || lags["watermark"].Count != 1 {
		t.Fatalf("freshness lag points = %#v, want only watermark", lags)
	}
	runs := collected["cerebro.source.sync.runs"]
	assertMetricHasAttribute(t, runs, "outcome", "skipped")
	assertMetricHasAttribute(t, runs, "skip_reason", "lease_not_acquired")
	assertMetricHasAttribute(t, runs, "failure_class", "none")
}

func TestRecordSourceSyncBoundsAttributeValues(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	t.Cleanup(shutdown)

	RecordSourceSync(context.Background(), SourceSyncMetrics{
		SourceID:     strings.Repeat("a", 500),
		Outcome:      "exploded: dial tcp 10.0.0.1",
		FailureClass: "Provider Unavailable/" + strings.Repeat("x", 500),
	})

	runs := collectMetrics(t, reader)["cerebro.source.sync.runs"]
	assertMetricHasAttribute(t, runs, "outcome", "unknown")
	for _, attrs := range metricAttributeSets(runs) {
		for _, kv := range attrs.ToSlice() {
			if len(kv.Value.AsString()) > 128 {
				t.Fatalf("attribute %s has %d bytes, want bounded value", kv.Key, len(kv.Value.AsString()))
			}
			if strings.ContainsAny(kv.Value.AsString(), " /:") {
				t.Fatalf("attribute %s=%q contains unsanitized characters", kv.Key, kv.Value.AsString())
			}
		}
	}
}

func float64HistogramByAttribute(t *testing.T, metric metricdata.Metrics, key attribute.Key) map[string]metricdata.HistogramDataPoint[float64] {
	t.Helper()
	data, ok := metric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("metric %q data = %T, want float64 histogram", metric.Name, metric.Data)
	}
	points := map[string]metricdata.HistogramDataPoint[float64]{}
	for _, point := range data.DataPoints {
		value, _ := point.Attributes.Value(key)
		points[value.AsString()] = point
	}
	return points
}
