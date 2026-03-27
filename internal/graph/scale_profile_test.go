package graph

import (
	"strings"
	"testing"
)

func TestNormalizeScaleProfileSpec(t *testing.T) {
	spec := NormalizeScaleProfileSpec(ScaleProfileSpec{
		Tiers:           []int{10000, 1000, -1, 1000, 50000},
		QueryIterations: 0,
	})
	if spec.QueryIterations != defaultScaleProfileQueryIterations {
		t.Fatalf("expected default query iterations, got %d", spec.QueryIterations)
	}
	expected := []int{1000, 10000, 50000}
	if len(spec.Tiers) != len(expected) {
		t.Fatalf("unexpected tiers: %#v", spec.Tiers)
	}
	for i := range expected {
		if spec.Tiers[i] != expected[i] {
			t.Fatalf("unexpected tier at %d: got %d want %d", i, spec.Tiers[i], expected[i])
		}
	}
}

func TestProfileSyntheticScaleSmallTier(t *testing.T) {
	report, err := ProfileSyntheticScale(ScaleProfileSpec{
		Tiers:           []int{24},
		QueryIterations: 1,
	})
	if err != nil {
		t.Fatalf("unexpected profile error: %v", err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
	if len(report.Measurements) != 1 {
		t.Fatalf("expected one measurement, got %d", len(report.Measurements))
	}
	measurement := report.Measurements[0]
	if measurement.ResourceCount != 24 {
		t.Fatalf("unexpected resource count: %d", measurement.ResourceCount)
	}
	if measurement.NodeCount <= 0 || measurement.EdgeCount <= 0 {
		t.Fatalf("expected non-zero topology, got nodes=%d edges=%d", measurement.NodeCount, measurement.EdgeCount)
	}
	if measurement.SearchResultCount <= 0 || measurement.SuggestResultCount <= 0 {
		t.Fatalf("expected search/suggest results, got search=%d suggest=%d", measurement.SearchResultCount, measurement.SuggestResultCount)
	}
	if measurement.BlastRadiusReachableCount <= 0 {
		t.Fatalf("expected blast radius reachability, got %d", measurement.BlastRadiusReachableCount)
	}
	if measurement.SnapshotCompressedBytes <= 0 {
		t.Fatalf("expected compressed snapshot bytes, got %d", measurement.SnapshotCompressedBytes)
	}
	if report.RecommendedPath == "" || report.Recommendation == "" {
		t.Fatalf("expected recommendation, got path=%q recommendation=%q", report.RecommendedPath, report.Recommendation)
	}
}

func TestProfileSyntheticScaleRejectsUnboundedInputs(t *testing.T) {
	if _, err := ProfileSyntheticScale(ScaleProfileSpec{
		Tiers:           []int{1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000},
		QueryIterations: 1,
	}); err == nil {
		t.Fatal("expected too-many-tiers error")
	}
	if _, err := ProfileSyntheticScale(ScaleProfileSpec{
		Tiers:           []int{maxScaleProfileResourceCount + 1},
		QueryIterations: 1,
	}); err == nil {
		t.Fatal("expected oversized-tier error")
	}
	if _, err := ProfileSyntheticScale(ScaleProfileSpec{
		Tiers:           []int{1000},
		QueryIterations: maxScaleProfileQueryIterations + 1,
	}); err == nil {
		t.Fatal("expected query-iteration error")
	}
}

func TestRecommendScalePathPrefersNeptuneAlignedGuidance(t *testing.T) {
	tests := []struct {
		name        string
		measurement ScaleProfileMeasurement
		wantPath    string
		wantPhrase  string
	}{
		{
			name:        "single node hot graph",
			measurement: ScaleProfileMeasurement{HeapAllocBytes: 64 * 1024 * 1024, CopyOnWriteDurationMS: 12},
			wantPath:    "single_node_hot_graph",
			wantPhrase:  "rely on Neptune as the durable system of record",
		},
		{
			name:        "tenant sharded hot graph",
			measurement: ScaleProfileMeasurement{HeapAllocBytes: 768 * 1024 * 1024, CopyOnWriteDurationMS: 300},
			wantPath:    "tenant_sharded_hot_graph",
			wantPhrase:  "Neptune-backed reads",
		},
		{
			name:        "hybrid persistent graph",
			measurement: ScaleProfileMeasurement{HeapAllocBytes: 2 * 1024 * 1024 * 1024, CopyOnWriteDurationMS: 1600},
			wantPath:    "hybrid_persistent_graph",
			wantPhrase:  "durable backing storage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, recommendation := recommendScalePath([]ScaleProfileMeasurement{tt.measurement})
			if path != tt.wantPath {
				t.Fatalf("recommendScalePath() path = %q, want %q", path, tt.wantPath)
			}
			if recommendation == "" || !strings.Contains(recommendation, tt.wantPhrase) {
				t.Fatalf("recommendScalePath() recommendation = %q, want phrase %q", recommendation, tt.wantPhrase)
			}
		})
	}
}

func TestBuildSyntheticScaleGraphFixture(t *testing.T) {
	g, fixture := buildSyntheticScaleGraph(32)
	if g == nil {
		t.Fatal("expected graph")
	}
	if fixture.principalID == "" || fixture.mutationNodeID == "" {
		t.Fatalf("expected populated fixture IDs, got %+v", fixture)
	}
	if _, ok := g.GetNode(fixture.principalID); !ok {
		t.Fatalf("expected principal node %s", fixture.principalID)
	}
	if _, ok := g.GetNode(fixture.mutationNodeID); !ok {
		t.Fatalf("expected mutation node %s", fixture.mutationNodeID)
	}
	if g.NodeCount() <= 32 {
		t.Fatalf("expected topology richer than raw resource count, got %d nodes", g.NodeCount())
	}
}

func TestSyntheticFunctionsAreNotAllInternetFacing(t *testing.T) {
	g, _ := buildSyntheticScaleGraph(128)
	if g == nil {
		t.Fatal("expected graph")
	}
	functionCount := 0
	exposedFunctionCount := 0
	for _, node := range g.Nodes() {
		if node == nil || node.Kind != NodeKindFunction {
			continue
		}
		functionCount++
		if publicFacing(node.Kind, node.Properties) {
			exposedFunctionCount++
		}
	}
	if functionCount == 0 {
		t.Fatal("expected synthetic functions")
	}
	if exposedFunctionCount == 0 {
		t.Fatal("expected some exposed synthetic functions")
	}
	if exposedFunctionCount == functionCount {
		t.Fatalf("expected only a subset of functions to be internet-facing, got %d/%d", exposedFunctionCount, functionCount)
	}
}

func TestSyntheticWorkloadsDoNotAllLookInternetFacing(t *testing.T) {
	g, _ := buildSyntheticScaleGraph(128)
	if g == nil {
		t.Fatal("expected graph")
	}
	workloadCount := 0
	exposedWorkloadCount := 0
	for _, node := range g.Nodes() {
		if node == nil || node.Kind != NodeKindWorkload {
			continue
		}
		workloadCount++
		if publicFacing(node.Kind, node.PropertyMap()) {
			exposedWorkloadCount++
		}
		if exposed, ok := node.PropertyValue("internet_exposed"); ok && exposed == false {
			if publicIP, ok := node.PropertyValue("public_ip"); ok && publicIP != "" {
				t.Fatalf("expected non-exposed synthetic workload %s to omit public_ip, got %s", node.ID, publicIP)
			}
		}
	}
	if workloadCount == 0 {
		t.Fatal("expected synthetic workloads")
	}
	if exposedWorkloadCount == 0 {
		t.Fatal("expected some exposed synthetic workloads")
	}
	if exposedWorkloadCount == workloadCount {
		t.Fatalf("expected only a subset of workloads to be internet-facing, got %d/%d", exposedWorkloadCount, workloadCount)
	}
}
