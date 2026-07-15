package observability

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestRecordSourceRuntimeSyncMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	RecordSourceRuntimeSync(context.Background(), SourceRuntimeSyncMetrics{
		SourceID:             "GitHub",
		Status:               "completed",
		ContractConfigured:   true,
		Duration:             150 * time.Millisecond,
		PagesRead:            2,
		RecordsScanned:       10,
		RecordsAccepted:      9,
		RecordsRejected:      1,
		EventsAppended:       9,
		EntitiesProjected:    7,
		LinksProjected:       4,
		WatermarkLagSeconds:  42,
		HasWatermarkLag:      true,
		ShortCircuitReason:   "not_modified",
		ReconciliationReason: "max_consecutive_skips",
	})
	t.Cleanup(shutdown)

	metrics := collectMetrics(t, reader)
	for _, name := range []string{
		"cerebro.source_runtime.sync.runs",
		"cerebro.source_runtime.sync.duration",
		"cerebro.source_runtime.records",
		"cerebro.source_runtime.watermark.lag",
		"cerebro.source_runtime.sync.short_circuits",
	} {
		if _, ok := metrics[name]; !ok {
			t.Fatalf("metric %q missing from %#v", name, metricNames(metrics))
		}
	}
	assertNoForbiddenMetricAttributes(t, metrics["cerebro.source_runtime.records"])
	assertNoForbiddenMetricAttributes(t, metrics["cerebro.source_runtime.sync.short_circuits"])
	assertMetricHasAttribute(t, metrics["cerebro.source_runtime.records"], "record.kind", "accepted")
	assertMetricHasAttribute(t, metrics["cerebro.source_runtime.records"], "source_id", "github")
	assertMetricHasAttribute(t, metrics["cerebro.source_runtime.sync.short_circuits"], "short_circuit_reason", "not_modified")
	assertMetricHasAttribute(t, metrics["cerebro.source_runtime.sync.short_circuits"], "reconciliation_reason", "max_consecutive_skips")
}

func TestRecordContentPackSelectionMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	RecordContentPackSelection(context.Background(), ContentPackSelectionMetrics{Kind: "Policy Control", Status: "Embedded Fallback", Count: 1})
	t.Cleanup(shutdown)

	metrics := collectMetrics(t, reader)
	metric, ok := metrics["cerebro.content_pack.selections"]
	if !ok {
		t.Fatalf("content-pack metric missing from %#v", metricNames(metrics))
	}
	assertNoForbiddenMetricAttributes(t, metric)
	assertMetricHasAttribute(t, metric, "pack.kind", "policy_control")
	assertMetricHasAttribute(t, metric, "status", "embedded_fallback")
}

func TestRecordSourceProjectionMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	RecordSourceProjection(context.Background(), SourceProjectionMetrics{
		SourceID:          "evidence_cas",
		EventKind:         "evidence_cas.object",
		Status:            "failed",
		Duration:          20 * time.Millisecond,
		EntitiesProjected: 3,
		LinksProjected:    2,
		EntitiesDeleted:   1,
	})
	t.Cleanup(shutdown)

	metrics := collectMetrics(t, reader)
	for _, name := range []string{
		"cerebro.source_projection.runs",
		"cerebro.source_projection.duration",
		"cerebro.source_projection.records",
	} {
		if _, ok := metrics[name]; !ok {
			t.Fatalf("metric %q missing from %#v", name, metricNames(metrics))
		}
	}
	assertNoForbiddenMetricAttributes(t, metrics["cerebro.source_projection.records"])
	assertMetricHasAttribute(t, metrics["cerebro.source_projection.records"], "event_kind", "evidence_cas.object")
	assertMetricHasAttribute(t, metrics["cerebro.source_projection.records"], "record.kind", "entity_deleted")
}

func TestRecordGraphActionMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	RecordGraphAction(context.Background(), GraphActionMetrics{
		Provider:       "Access Approvals",
		Action:         "identity.okta.suspend_user",
		Status:         "Succeeded",
		ExternalStatus: "SUSPENDED",
		DryRun:         false,
	})
	t.Cleanup(shutdown)

	metrics := collectMetrics(t, reader)
	metric, ok := metrics["cerebro.graph_action.recorded"]
	if !ok {
		t.Fatalf("metric %q missing from %#v", "cerebro.graph_action.recorded", metricNames(metrics))
	}
	assertNoForbiddenMetricAttributes(t, metric)
	assertMetricHasAttribute(t, metric, "provider", "access_approvals")
	assertMetricHasAttribute(t, metric, "action", "identity.okta.suspend_user")
	assertMetricHasAttribute(t, metric, "status", "succeeded")
	assertMetricHasAttribute(t, metric, "external_status", "suspended")
	assertMetricHasBoolAttribute(t, metric, "dry_run", false)
}

func TestRecordOrchestratorPhaseSkipMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	RecordOrchestratorPhaseSkip(context.Background(), OrchestratorPhaseSkipMetrics{
		PhaseKey:   "Graph Ingest",
		SourceID:   "GitHub",
		SkipReason: "source_unchanged",
	})
	t.Cleanup(shutdown)

	metrics := collectMetrics(t, reader)
	metric, ok := metrics["cerebro.orchestrator.phase.skips"]
	if !ok {
		t.Fatalf("metric %q missing from %#v", "cerebro.orchestrator.phase.skips", metricNames(metrics))
	}
	assertNoForbiddenMetricAttributes(t, metric)
	assertMetricHasAttribute(t, metric, "phase_key", "graph_ingest")
	assertMetricHasAttribute(t, metric, "source_id", "github")
	assertMetricHasAttribute(t, metric, "skip_reason", "source_unchanged")
}

func TestRecordJetStreamPublishMetricsAreLowCardinality(t *testing.T) {
	reader, shutdown := installManualMetricReader(t)
	RecordJetStreamPublish(context.Background(), JetStreamPublishMetrics{
		Subject:              "sec.findings.v1.recorded",
		Operation:            "append",
		Status:               "failed",
		ErrorCategory:        "no_response",
		Duration:             250 * time.Millisecond,
		RetryCount:           3,
		MaxAttemptsExhausted: true,
	})
	t.Cleanup(shutdown)

	metrics := collectMetrics(t, reader)
	for _, name := range []string{
		"cerebro.jetstream.publish.requests",
		"cerebro.jetstream.publish.retries",
		"cerebro.jetstream.publish.duration",
		"cerebro.jetstream.publish.max_attempts_exhausted",
	} {
		if _, ok := metrics[name]; !ok {
			t.Fatalf("metric %q missing from %#v", name, metricNames(metrics))
		}
	}
	metric := metrics["cerebro.jetstream.publish.requests"]
	assertNoForbiddenMetricAttributes(t, metric)
	assertMetricHasAttribute(t, metric, "subject", "sec.findings.v1.recorded")
	assertMetricHasAttribute(t, metric, "operation", "append")
	assertMetricHasAttribute(t, metric, "status", "failed")
	assertMetricHasAttribute(t, metric, "error_category", "no_response")
	assertMetricHasBoolAttribute(t, metric, "max_attempts_exhausted", true)
}

func TestBoundedMetricValueNormalizesAndBoundsLabels(t *testing.T) {
	got := boundedMetricValue("Runtime ID With Spaces And / Weird # Chars", "unknown")
	if got != "runtime_id_with_spaces_and___weird___chars" {
		t.Fatalf("bounded metric value = %q", got)
	}
	if got := boundedMetricValue("!!!", "unknown"); got != "unknown" {
		t.Fatalf("punctuation-only value = %q, want fallback", got)
	}
	if got := boundedMetricValue("source-"+strings.Repeat("x", 200), "unknown"); len(got) > 96 {
		t.Fatalf("bounded metric value length = %d, want <= 96", len(got))
	}
}

func TestBoundedJetStreamMetricSubjectCollapsesUnknownFindingsSubjects(t *testing.T) {
	if got := boundedJetStreamMetricSubject("sec.findings.v1.recorded"); got != "sec.findings.v1.recorded" {
		t.Fatalf("recorded subject = %q, want exact finding subject", got)
	}
	if got := boundedJetStreamMetricSubject("sec.findings.v1.some_new_subject"); got != "sec.findings.v1._other" {
		t.Fatalf("other finding subject = %q, want collapsed finding family", got)
	}
	if got := boundedJetStreamMetricSubject("events.some.dynamic.identifier.value"); got != "events.some.dynamic._other" {
		t.Fatalf("dynamic event subject = %q, want bounded event family", got)
	}
}

func installManualMetricReader(t *testing.T) (*sdkmetric.ManualReader, func()) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	oldProvider := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	return reader, func() {
		otel.SetMeterProvider(oldProvider)
		_ = provider.Shutdown(context.Background())
	}
}

func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	metrics := map[string]metricdata.Metrics{}
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			metrics[metric.Name] = metric
		}
	}
	return metrics
}

func metricNames(metrics map[string]metricdata.Metrics) []string {
	names := make([]string, 0, len(metrics))
	for name := range metrics {
		names = append(names, name)
	}
	return names
}

func assertNoForbiddenMetricAttributes(t *testing.T, metric metricdata.Metrics) {
	t.Helper()
	for _, attrs := range metricAttributeSets(metric) {
		forbidden := map[attribute.Key]bool{
			"tenant_id":    true,
			"runtime_id":   true,
			"resource_urn": true,
			"evidence_id":  true,
			"request_id":   true,
			"trace_id":     true,
		}
		for _, kv := range attrs.ToSlice() {
			if forbidden[kv.Key] {
				t.Fatalf("metric %q contains forbidden attribute %q", metric.Name, kv.Key)
			}
		}
	}
}

func assertMetricHasAttribute(t *testing.T, metric metricdata.Metrics, key attribute.Key, value string) {
	t.Helper()
	for _, attrs := range metricAttributeSets(metric) {
		for _, kv := range attrs.ToSlice() {
			if kv.Key == key && kv.Value.AsString() == value {
				return
			}
		}
	}
	t.Fatalf("metric %q missing attribute %s=%q", metric.Name, key, value)
}

func assertMetricHasBoolAttribute(t *testing.T, metric metricdata.Metrics, key attribute.Key, value bool) {
	t.Helper()
	for _, attrs := range metricAttributeSets(metric) {
		for _, kv := range attrs.ToSlice() {
			if kv.Key == key && kv.Value.AsBool() == value {
				return
			}
		}
	}
	t.Fatalf("metric %q missing attribute %s=%t", metric.Name, key, value)
}

func metricAttributeSets(metric metricdata.Metrics) []attribute.Set {
	switch data := metric.Data.(type) {
	case metricdata.Sum[int64]:
		sets := make([]attribute.Set, 0, len(data.DataPoints))
		for _, point := range data.DataPoints {
			sets = append(sets, point.Attributes)
		}
		return sets
	case metricdata.Histogram[float64]:
		sets := make([]attribute.Set, 0, len(data.DataPoints))
		for _, point := range data.DataPoints {
			sets = append(sets, point.Attributes)
		}
		return sets
	default:
		return nil
	}
}
