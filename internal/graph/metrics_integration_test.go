package graph

import (
	"testing"

	"github.com/evalops/cerebro/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestGraphOperationMetrics(t *testing.T) {
	metrics.Register()

	beforeAddNode := histogramCountVec(t, metrics.GraphMutationLatency, "add_node")
	beforeAddNodesBatch := histogramCountVec(t, metrics.GraphMutationLatency, "add_nodes_batch")
	beforeAddEdge := histogramCountVec(t, metrics.GraphMutationLatency, "add_edge")
	beforeAddEdgesBatch := histogramCountVec(t, metrics.GraphMutationLatency, "add_edges_batch")
	beforeSetProperty := histogramCountVec(t, metrics.GraphMutationLatency, "set_property")
	beforeBuildIndex := histogramCountVec(t, metrics.GraphIndexBuildDuration, "manual")
	beforeSearch := histogramCountVec(t, metrics.GraphSearchLatency, "entity_search")
	beforeSuggest := histogramCountVec(t, metrics.GraphSearchLatency, "entity_suggest")
	beforeCreateSnapshot := histogramCountVec(t, metrics.GraphSnapshotDuration, "create")
	beforeRestoreSnapshot := histogramCountVec(t, metrics.GraphSnapshotDuration, "restore")
	beforeClone := histogramCount(t, metrics.GraphCloneDuration)

	g := New()
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "admin", Account: "111111111111"})
	g.AddNode(&Node{ID: "bucket:critical", Kind: NodeKindBucket, Name: "critical", Account: "111111111111"})
	g.AddEdge(&Edge{ID: "role:admin->bucket:critical", Source: "role:admin", Target: "bucket:critical", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.SetNodeProperty("bucket:critical", "internet_exposed", true)
	g.BuildIndex()
	_ = SearchEntities(g, EntitySearchOptions{Query: "admin"})
	_ = SuggestEntities(g, EntitySuggestOptions{Prefix: "adm"})

	snapshot := CreateSnapshot(g)
	restored := RestoreFromSnapshot(snapshot)
	clone := g.Clone()

	if restored.NodeCount() != g.NodeCount() {
		t.Fatalf("restored.NodeCount() = %d, want %d", restored.NodeCount(), g.NodeCount())
	}
	if clone.NodeCount() != g.NodeCount() {
		t.Fatalf("clone.NodeCount() = %d, want %d", clone.NodeCount(), g.NodeCount())
	}

	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_node"); got < beforeAddNode+2 {
		t.Fatalf("expected add_node histogram count to increase by at least 2, got before=%d after=%d", beforeAddNode, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_nodes_batch"); got != beforeAddNodesBatch {
		t.Fatalf("expected add_nodes_batch histogram count to remain unchanged, got before=%d after=%d", beforeAddNodesBatch, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_edge"); got != beforeAddEdge+1 {
		t.Fatalf("expected add_edge histogram count to increase by 1, got before=%d after=%d", beforeAddEdge, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_edges_batch"); got != beforeAddEdgesBatch {
		t.Fatalf("expected add_edges_batch histogram count to remain unchanged, got before=%d after=%d", beforeAddEdgesBatch, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "set_property"); got != beforeSetProperty+1 {
		t.Fatalf("expected set_property histogram count to increase by 1, got before=%d after=%d", beforeSetProperty, got)
	}
	if got := histogramCountVec(t, metrics.GraphIndexBuildDuration, "manual"); got != beforeBuildIndex+1 {
		t.Fatalf("expected build index histogram count to increase by 1, got before=%d after=%d", beforeBuildIndex, got)
	}
	if got := histogramCountVec(t, metrics.GraphSearchLatency, "entity_search"); got != beforeSearch+1 {
		t.Fatalf("expected entity_search histogram count to increase by 1, got before=%d after=%d", beforeSearch, got)
	}
	if got := histogramCountVec(t, metrics.GraphSearchLatency, "entity_suggest"); got != beforeSuggest+1 {
		t.Fatalf("expected entity_suggest histogram count to increase by 1, got before=%d after=%d", beforeSuggest, got)
	}
	if got := histogramCountVec(t, metrics.GraphSnapshotDuration, "create"); got != beforeCreateSnapshot+1 {
		t.Fatalf("expected create snapshot histogram count to increase by 1, got before=%d after=%d", beforeCreateSnapshot, got)
	}
	if got := histogramCountVec(t, metrics.GraphSnapshotDuration, "restore"); got != beforeRestoreSnapshot+1 {
		t.Fatalf("expected restore snapshot histogram count to increase by 1, got before=%d after=%d", beforeRestoreSnapshot, got)
	}
	if got := histogramCount(t, metrics.GraphCloneDuration); got != beforeClone+1 {
		t.Fatalf("expected clone histogram count to increase by 1, got before=%d after=%d", beforeClone, got)
	}
}

func TestSnapshotStorePublishesSnapshotSizeMetric(t *testing.T) {
	metrics.Register()

	g := New()
	g.AddNode(&Node{ID: "role:admin", Kind: NodeKindRole, Name: "admin"})
	store := NewSnapshotStore(t.TempDir(), 2)

	if _, _, err := store.SaveGraph(g); err != nil {
		t.Fatalf("SaveGraph() error = %v", err)
	}
	if got := gaugeValue(t, metrics.GraphSnapshotSizeBytes); got <= 0 {
		t.Fatalf("expected graph snapshot size gauge to be > 0, got %v", got)
	}
}

func TestGraphBatchMutationMetricsUseDistinctLabels(t *testing.T) {
	metrics.Register()

	beforeAddNode := histogramCountVec(t, metrics.GraphMutationLatency, "add_node")
	beforeAddNodesBatch := histogramCountVec(t, metrics.GraphMutationLatency, "add_nodes_batch")
	beforeAddEdge := histogramCountVec(t, metrics.GraphMutationLatency, "add_edge")
	beforeAddEdgesBatch := histogramCountVec(t, metrics.GraphMutationLatency, "add_edges_batch")

	g := New()
	g.AddNodesBatch([]*Node{
		{ID: "role:batch-a", Kind: NodeKindRole, Name: "batch-a"},
		{ID: "role:batch-b", Kind: NodeKindRole, Name: "batch-b"},
	})
	g.AddEdgesBatch([]*Edge{
		{ID: "edge:batch", Source: "role:batch-a", Target: "role:batch-b", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow},
	})

	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_node"); got != beforeAddNode {
		t.Fatalf("expected add_node histogram count unchanged, got before=%d after=%d", beforeAddNode, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_nodes_batch"); got != beforeAddNodesBatch+1 {
		t.Fatalf("expected add_nodes_batch histogram count to increase by 1, got before=%d after=%d", beforeAddNodesBatch, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_edge"); got != beforeAddEdge {
		t.Fatalf("expected add_edge histogram count unchanged, got before=%d after=%d", beforeAddEdge, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_edges_batch"); got != beforeAddEdgesBatch+1 {
		t.Fatalf("expected add_edges_batch histogram count to increase by 1, got before=%d after=%d", beforeAddEdgesBatch, got)
	}
}

func TestGraphViewFromSnapshotDoesNotEmitMutationMetrics(t *testing.T) {
	metrics.Register()

	beforeAddNode := histogramCountVec(t, metrics.GraphMutationLatency, "add_node")
	beforeAddNodesBatch := histogramCountVec(t, metrics.GraphMutationLatency, "add_nodes_batch")
	beforeAddEdge := histogramCountVec(t, metrics.GraphMutationLatency, "add_edge")
	beforeAddEdgesBatch := histogramCountVec(t, metrics.GraphMutationLatency, "add_edges_batch")

	snapshot := &Snapshot{
		Version: snapshotVersion,
		Nodes: []*Node{
			{ID: "role:view", Kind: NodeKindRole, Name: "view"},
			{ID: "bucket:view", Kind: NodeKindBucket, Name: "view"},
		},
		Edges: []*Edge{
			{ID: "edge:view", Source: "role:view", Target: "bucket:view", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow},
		},
	}

	view := GraphViewFromSnapshot(snapshot)
	if view == nil {
		t.Fatal("expected graph view")
	}
	if view.NodeCount() != 2 {
		t.Fatalf("view.NodeCount() = %d, want 2", view.NodeCount())
	}
	if view.EdgeCount() != 1 {
		t.Fatalf("view.EdgeCount() = %d, want 1", view.EdgeCount())
	}

	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_node"); got != beforeAddNode {
		t.Fatalf("expected add_node histogram count unchanged, got before=%d after=%d", beforeAddNode, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_nodes_batch"); got != beforeAddNodesBatch {
		t.Fatalf("expected add_nodes_batch histogram count unchanged, got before=%d after=%d", beforeAddNodesBatch, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_edge"); got != beforeAddEdge {
		t.Fatalf("expected add_edge histogram count unchanged, got before=%d after=%d", beforeAddEdge, got)
	}
	if got := histogramCountVec(t, metrics.GraphMutationLatency, "add_edges_batch"); got != beforeAddEdgesBatch {
		t.Fatalf("expected add_edges_batch histogram count unchanged, got before=%d after=%d", beforeAddEdgesBatch, got)
	}
}

func histogramCountVec(t *testing.T, histogram *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	collector, err := histogram.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get histogram metric with labels %v: %v", labels, err)
	}
	metricCollector, ok := collector.(prometheus.Metric)
	if !ok {
		t.Fatalf("histogram collector does not implement prometheus.Metric")
	}
	var metric dto.Metric
	if err := metricCollector.Write(&metric); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}
	return metric.GetHistogram().GetSampleCount()
}

func histogramCount(t *testing.T, histogram prometheus.Histogram) uint64 {
	t.Helper()
	var metric dto.Metric
	if err := histogram.Write(&metric); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}
	return metric.GetHistogram().GetSampleCount()
}

func gaugeValue(t *testing.T, gauge interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatalf("write gauge metric: %v", err)
	}
	return metric.GetGauge().GetValue()
}
