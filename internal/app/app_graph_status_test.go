package app

import (
	"testing"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/metrics"
	dto "github.com/prometheus/client_model/go"
)

func TestSetSecurityGraphPublishesGraphCountMetrics(t *testing.T) {
	metrics.Register()

	application := &App{}
	live := graph.New()
	live.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "admin"})
	live.AddNode(&graph.Node{ID: "bucket:critical", Kind: graph.NodeKindBucket, Name: "critical"})
	live.AddEdge(&graph.Edge{
		ID:     "role:admin->bucket:critical",
		Source: "role:admin",
		Target: "bucket:critical",
		Kind:   graph.EdgeKindCanRead,
		Effect: graph.EdgeEffectAllow,
	})

	application.setSecurityGraph(live)
	if got := gaugeValueFromMetric(t, metrics.GraphNodesTotal); got != 2 {
		t.Fatalf("expected graph nodes gauge 2, got %v", got)
	}
	if got := gaugeValueFromMetric(t, metrics.GraphEdgesTotal); got != 1 {
		t.Fatalf("expected graph edges gauge 1, got %v", got)
	}

	application.setSecurityGraph(nil)
	if got := gaugeValueFromMetric(t, metrics.GraphNodesTotal); got != 0 {
		t.Fatalf("expected graph nodes gauge 0 after clear, got %v", got)
	}
	if got := gaugeValueFromMetric(t, metrics.GraphEdgesTotal); got != 0 {
		t.Fatalf("expected graph edges gauge 0 after clear, got %v", got)
	}
}

func gaugeValueFromMetric(t *testing.T, gauge interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatalf("write gauge metric: %v", err)
	}
	return metric.GetGauge().GetValue()
}
