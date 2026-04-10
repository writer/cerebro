package app

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/metrics"
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

func TestCurrentSecurityGraphUsesConfiguredStoreWhenLiveGraphEmpty(t *testing.T) {
	configured := graph.New()
	configured.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})

	application := &App{SecurityGraph: graph.New()}
	setConfiguredSnapshotGraphFromGraph(t, application, configured)

	current := application.CurrentSecurityGraph()
	if current == nil {
		t.Fatal("expected configured graph")
	}
	if _, ok := current.GetNode("service:payments"); !ok {
		t.Fatal("expected configured graph node")
	}
}

type stubConfiguredSnapshotStore struct {
	graph.GraphStore
	snapshot *graph.Snapshot
	err      error
}

func (s *stubConfiguredSnapshotStore) Snapshot(context.Context) (*graph.Snapshot, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.snapshot, nil
}

func TestCurrentSecurityGraphReturnsNilWhenConfiguredViewMissing(t *testing.T) {
	application := &App{
		SecurityGraph: graph.New(),
	}
	setConfiguredGraphStore(t, application, &stubConfiguredSnapshotStore{})

	if current := application.CurrentSecurityGraph(); current != nil {
		t.Fatalf("expected nil current graph when live graph is unreadable and configured view is missing, got %p", current)
	}
}

func TestCurrentSecurityGraphReturnsNilWhenConfiguredViewErrors(t *testing.T) {
	application := &App{
		SecurityGraph: graph.New(),
	}
	setConfiguredGraphStore(t, application, &stubConfiguredSnapshotStore{err: context.DeadlineExceeded})

	if current := application.CurrentSecurityGraph(); current != nil {
		t.Fatalf("expected nil current graph when configured view errors, got %p", current)
	}
}

func TestCurrentOrStoredSecurityGraphViewReturnsNilWhenSourcesUnreadable(t *testing.T) {
	application := &App{
		SecurityGraph: graph.New(),
	}
	setConfiguredGraphStore(t, application, &stubConfiguredSnapshotStore{})

	current, err := application.currentOrStoredSecurityGraphView()
	if err != nil {
		t.Fatalf("currentOrStoredSecurityGraphView() error = %v, want nil", err)
	}
	if current != nil {
		t.Fatalf("expected nil graph when live graph is unreadable and configured view is missing, got %p", current)
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
