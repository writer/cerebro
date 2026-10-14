package main

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
)

func installOrchestratorMetricReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return reader
}

func collectOrchestratorMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
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

// requireSingleSourceSyncRun asserts exactly one runs datapoint with a count
// of one and the given attributes.
func requireSingleSourceSyncRun(t *testing.T, metrics map[string]metricdata.Metrics, want map[string]string) {
	t.Helper()
	runs, ok := metrics["cerebro.source.sync.runs"].Data.(metricdata.Sum[int64])
	if !ok || len(runs.DataPoints) != 1 {
		t.Fatalf("cerebro.source.sync.runs = %#v, want one datapoint", metrics["cerebro.source.sync.runs"].Data)
	}
	point := runs.DataPoints[0]
	if point.Value != 1 {
		t.Fatalf("runs value = %d, want 1", point.Value)
	}
	if point.Attributes.Len() != len(want) {
		t.Fatalf("runs attributes = %v, want exactly %v", point.Attributes.ToSlice(), want)
	}
	for key, value := range want {
		got, ok := point.Attributes.Value(attribute.Key(key))
		if !ok || got.AsString() != value {
			t.Fatalf("runs attribute %s = %q, want %q (all: %v)", key, got.AsString(), value, point.Attributes.ToSlice())
		}
	}
}

func consecutiveFailureSamples(t *testing.T, metrics map[string]metricdata.Metrics) []metricdata.HistogramDataPoint[int64] {
	t.Helper()
	metric, ok := metrics["cerebro.source.sync.consecutive_failures"]
	if !ok {
		return nil
	}
	data, ok := metric.Data.(metricdata.Histogram[int64])
	if !ok {
		t.Fatalf("consecutive failures data = %T, want int64 histogram", metric.Data)
	}
	return data.DataPoints
}

func TestOrchestratorSourceSyncMetricsFailedSync(t *testing.T) {
	reader := installOrchestratorMetricReader(t)
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source", TenantId: "writer"},
		acquired: true,
	})
	if _, err := runScheduleIteration(t, store, orchestratorOptions{}); err == nil {
		t.Fatal("runOrchestratorIteration() error = nil, want sync failure")
	}

	metrics := collectOrchestratorMetrics(t, reader)
	requireSingleSourceSyncRun(t, metrics, map[string]string{
		"source_id": "missing-source", "outcome": "failed", "failure_class": "internal", "skip_reason": "none",
	})
	samples := consecutiveFailureSamples(t, metrics)
	if len(samples) != 1 || samples[0].Count != 1 || samples[0].Sum != 1 {
		t.Fatalf("consecutive failure samples = %#v, want one sample of 1", samples)
	}
}

func TestOrchestratorSourceSyncMetricsBackoffSkip(t *testing.T) {
	reader := installOrchestratorMetricReader(t)
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "missing-source"},
		acquired: true,
	})
	store.schedules["runtime-1"] = ports.SourceRuntimeSyncSchedule{
		RuntimeID:           "runtime-1",
		ConsecutiveFailures: 9,
		LastFailureClass:    "provider_unavailable",
		NextAttemptAt:       time.Now().UTC().Add(30 * time.Minute),
		CircuitOpen:         true,
	}
	if _, err := runScheduleIteration(t, store, orchestratorOptions{}); err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v", err)
	}

	metrics := collectOrchestratorMetrics(t, reader)
	requireSingleSourceSyncRun(t, metrics, map[string]string{
		"source_id": "missing-source", "outcome": "skipped", "failure_class": "provider_unavailable", "skip_reason": "backoff",
	})
	samples := consecutiveFailureSamples(t, metrics)
	if len(samples) != 1 || samples[0].Sum != 9 {
		t.Fatalf("consecutive failure samples = %#v, want one sample of 9", samples)
	}
	circuit, ok := metrics["cerebro.source.sync.circuit_open"].Data.(metricdata.Sum[int64])
	if !ok || len(circuit.DataPoints) != 1 || circuit.DataPoints[0].Value != 1 {
		t.Fatalf("circuit open = %#v, want one open observation", metrics["cerebro.source.sync.circuit_open"].Data)
	}
}

func TestOrchestratorSourceSyncMetricsLeaseNotAcquired(t *testing.T) {
	reader := installOrchestratorMetricReader(t)
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github"},
		acquired: false,
	})
	if _, err := runScheduleIteration(t, store, orchestratorOptions{}); err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v", err)
	}

	metrics := collectOrchestratorMetrics(t, reader)
	requireSingleSourceSyncRun(t, metrics, map[string]string{
		"source_id": "github", "outcome": "skipped", "failure_class": "none", "skip_reason": "lease_not_acquired",
	})
	if samples := consecutiveFailureSamples(t, metrics); len(samples) != 0 {
		t.Fatalf("consecutive failure samples = %#v, want none when another owner holds the lease", samples)
	}
	if _, ok := metrics["cerebro.source.sync.circuit_open"]; ok {
		t.Fatal("circuit open recorded for lease skip")
	}
}

func TestOrchestratorSourceSyncMetricsCompletedSync(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(orchestratorTestSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	ruleRegistry, err := findings.NewRegistry(orchestratorNoopRule{})
	if err != nil {
		t.Fatalf("NewRegistry() finding rule error = %v", err)
	}
	reader := installOrchestratorMetricReader(t)
	store := newScheduleRuntimeStore(&orchestratorRuntimeStore{
		runtime:  &cerebrov1.SourceRuntime{Id: "runtime-1", SourceId: "github", TenantId: "writer"},
		acquired: true,
	})
	store.schedules["runtime-1"] = ports.SourceRuntimeSyncSchedule{
		RuntimeID:           "runtime-1",
		ConsecutiveFailures: 4,
		LastFailureClass:    "provider_unavailable",
		NextAttemptAt:       time.Now().UTC().Add(-time.Minute),
	}
	eventLog := &orchestratorEventLog{}
	findingStore := &orchestratorFindingStore{}
	graphStore := newGraphTestStore()
	if _, err := runOrchestratorIteration(
		context.Background(),
		store,
		store,
		"test-owner",
		sourceruntime.New(registry, store, eventLog, nil),
		findings.NewWithRegistry(store, eventLog, findingStore, findingStore, findingStore, findingStore, ruleRegistry),
		graphingest.New(registry, store, sourceprojection.New(nil, graphStore), graphStore),
		orchestratorOptions{},
		1,
	); err != nil {
		t.Fatalf("runOrchestratorIteration() error = %v", err)
	}

	metrics := collectOrchestratorMetrics(t, reader)
	requireSingleSourceSyncRun(t, metrics, map[string]string{
		"source_id": "github", "outcome": "completed", "failure_class": "none", "skip_reason": "none",
	})
	samples := consecutiveFailureSamples(t, metrics)
	if len(samples) != 1 || samples[0].Count != 1 || samples[0].Sum != 0 {
		t.Fatalf("consecutive failure samples = %#v, want one cleared sample of 0", samples)
	}
	if _, ok := metrics["cerebro.source.freshness.lag"]; !ok {
		t.Fatal("freshness lag missing after completed sync")
	}
}
