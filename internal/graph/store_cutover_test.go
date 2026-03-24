package graph

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestCompareGraphStoresDetectsSnapshotAndTraversalDrift(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := New()
	shadow.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	shadow.AddNode(&Node{ID: "service:api", Kind: NodeKindService, Name: "API"})
	shadow.AddEdge(&Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	report, err := CompareGraphStores(context.Background(), primary, shadow, []StoreTraversalProbe{
		{Name: "blast-radius", Kind: StoreTraversalProbeBlastRadius, PrincipalID: "user:alice", MaxDepth: 3},
		{Name: "reverse-access", Kind: StoreTraversalProbeReverseAccess, ResourceID: "db:prod", MaxDepth: 3},
	})
	if err != nil {
		t.Fatalf("CompareGraphStores() error = %v", err)
	}
	if !report.HasDrift() {
		t.Fatal("expected drift report")
	}
	if report.PrimaryNodeCount != 3 || report.ShadowNodeCount != 2 {
		t.Fatalf("unexpected node counts: %+v", report)
	}
	if report.PrimaryEdgeCount != 2 || report.ShadowEdgeCount != 1 {
		t.Fatalf("unexpected edge counts: %+v", report)
	}
	if report.SnapshotDiff == nil || len(report.SnapshotDiff.NodesRemoved) != 1 || len(report.SnapshotDiff.EdgesRemoved) != 1 {
		t.Fatalf("expected structural diff for missing node and edge, got %#v", report.SnapshotDiff)
	}
	classes := mismatchClasses(report.Mismatches)
	if !slices.Contains(classes, StoreParityMismatchMissingNode) {
		t.Fatalf("expected missing-node mismatch, got %#v", report.Mismatches)
	}
	if !slices.Contains(classes, StoreParityMismatchMissingEdge) {
		t.Fatalf("expected missing-edge mismatch, got %#v", report.Mismatches)
	}
	if !slices.Contains(classes, StoreParityMismatchTraversalDrift) {
		t.Fatalf("expected traversal drift mismatch, got %#v", report.Mismatches)
	}
}

func TestCompareGraphStoresEquivalentStoresHaveNoDrift(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := buildCutoverParityPrimaryGraph()

	report, err := CompareGraphStores(context.Background(), primary, shadow, []StoreTraversalProbe{
		{Name: "blast-radius", Kind: StoreTraversalProbeBlastRadius, PrincipalID: "user:alice", MaxDepth: 3},
		{Name: "reverse-access", Kind: StoreTraversalProbeReverseAccess, ResourceID: "db:prod", MaxDepth: 3},
	})
	if err != nil {
		t.Fatalf("CompareGraphStores() error = %v", err)
	}
	if report.HasDrift() {
		t.Fatalf("expected no drift, got %#v", report)
	}
}

func TestShadowReadGraphStoreReturnsPrimaryDataAndEmitsDrift(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := New()
	shadow.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	shadow.AddNode(&Node{ID: "service:api", Kind: NodeKindService, Name: "API"})
	shadow.AddEdge(&Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	var reports []StoreParityReport
	store := NewShadowReadGraphStore(primary, shadow, func(_ context.Context, report StoreParityReport) {
		reports = append(reports, report)
	})

	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot == nil || len(snapshot.Nodes) != 3 {
		t.Fatalf("expected primary snapshot, got %#v", snapshot)
	}

	result, err := store.BlastRadius(context.Background(), "user:alice", 3)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if result.TotalCount != 2 {
		t.Fatalf("expected primary blast radius result, got %#v", result)
	}
	if len(reports) != 2 {
		t.Fatalf("expected snapshot and traversal parity reports, got %d", len(reports))
	}
	if !reports[0].HasDrift() || !reports[1].HasDrift() {
		t.Fatalf("expected both parity reports to capture drift, got %#v", reports)
	}
}

func TestShadowReadGraphStoreEmitsShadowErrorsButReturnsPrimaryResult(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadowErr := errors.New("shadow unavailable")
	store := NewShadowReadGraphStore(primary, failingShadowGraphStore{GraphStore: New(), err: shadowErr}, nil)

	result, err := store.BlastRadius(context.Background(), "user:alice", 3)
	if err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if result.TotalCount != 2 {
		t.Fatalf("expected primary blast radius result, got %#v", result)
	}

	shadowStore, ok := store.(*ShadowReadGraphStore)
	if !ok {
		t.Fatalf("expected shadow read wrapper, got %T", store)
	}
	var reports []StoreParityReport
	shadowStore.observe = func(_ context.Context, report StoreParityReport) {
		reports = append(reports, report)
	}
	if _, err := shadowStore.BlastRadius(context.Background(), "user:alice", 3); err != nil {
		t.Fatalf("BlastRadius() error = %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected one shadow-error report, got %#v", reports)
	}
	if classes := mismatchClasses(reports[0].Mismatches); !slices.Contains(classes, StoreParityMismatchShadowError) {
		t.Fatalf("expected shadow-error mismatch, got %#v", reports[0].Mismatches)
	}
}

func TestCompareGraphStoresDetectsShadowOnlyAdditions(t *testing.T) {
	primary := New()
	primary.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})

	shadow := New()
	shadow.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	shadow.AddNode(&Node{ID: "service:api", Kind: NodeKindService, Name: "API"})
	shadow.AddEdge(&Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	report, err := CompareGraphStores(context.Background(), primary, shadow, nil)
	if err != nil {
		t.Fatalf("CompareGraphStores() error = %v", err)
	}
	if !report.HasDrift() {
		t.Fatalf("expected drift for shadow-only additions, got %#v", report)
	}
	if report.SnapshotDiff == nil || len(report.SnapshotDiff.NodesAdded) != 1 || len(report.SnapshotDiff.EdgesAdded) != 1 {
		t.Fatalf("expected snapshot diff to retain shadow additions, got %#v", report.SnapshotDiff)
	}

	nodeMismatch := findMismatch(report.Mismatches, StoreParityMismatchMissingNode, "service:api")
	if nodeMismatch == nil {
		t.Fatalf("expected mismatch for shadow-only node, got %#v", report.Mismatches)
	}
	if got := mismatchDetailString(nodeMismatch, "direction"); got != "shadow_extra" {
		t.Fatalf("expected shadow_extra node direction, got %#v", nodeMismatch)
	}

	edgeMismatch := findMismatch(report.Mismatches, StoreParityMismatchMissingEdge, "alice-api")
	if edgeMismatch == nil {
		t.Fatalf("expected mismatch for shadow-only edge, got %#v", report.Mismatches)
	}
	if got := mismatchDetailString(edgeMismatch, "direction"); got != "shadow_extra" {
		t.Fatalf("expected shadow_extra edge direction, got %#v", edgeMismatch)
	}
}

func TestBuildSnapshotParityReportPreservesMissingDirection(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := New()
	shadow.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	shadow.AddNode(&Node{ID: "service:api", Kind: NodeKindService, Name: "API"})
	shadow.AddEdge(&Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	primarySnapshot, err := primary.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("primary snapshot: %v", err)
	}
	shadowSnapshot, err := shadow.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("shadow snapshot: %v", err)
	}
	report := buildSnapshotParityReport(primarySnapshot, shadowSnapshot)

	nodeMismatch := findMismatch(report.Mismatches, StoreParityMismatchMissingNode, "db:prod")
	if nodeMismatch == nil {
		t.Fatalf("expected mismatch for primary-only node, got %#v", report.Mismatches)
	}
	if got := mismatchDetailString(nodeMismatch, "direction"); got != "shadow_missing" {
		t.Fatalf("expected shadow_missing node direction, got %#v", nodeMismatch)
	}

	edgeMismatch := findMismatch(report.Mismatches, StoreParityMismatchMissingEdge, "api-db")
	if edgeMismatch == nil {
		t.Fatalf("expected mismatch for primary-only edge, got %#v", report.Mismatches)
	}
	if got := mismatchDetailString(edgeMismatch, "direction"); got != "shadow_missing" {
		t.Fatalf("expected shadow_missing edge direction, got %#v", edgeMismatch)
	}
}

func TestCompareGraphStoreReportsDetectsReportDrift(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := buildCutoverParityPrimaryGraph()
	shadow.AddNode(&Node{ID: "cache:edge", Kind: NodeKindDatabase, Name: "Edge Cache"})

	report, err := CompareGraphStoreReports(context.Background(), primary, shadow, []StoreReportProbe{{
		Name: "active-node-count",
		Build: func(g *Graph) (any, error) {
			snapshot, err := g.Snapshot(context.Background())
			if err != nil {
				return nil, err
			}
			nodeCount, _ := activeSnapshotCounts(snapshot)
			return map[string]any{
				"generated_at": "strip-me",
				"node_count":   nodeCount,
			}, nil
		},
	}})
	if err != nil {
		t.Fatalf("CompareGraphStoreReports() error = %v", err)
	}
	if !report.HasDrift() {
		t.Fatalf("expected report drift, got %#v", report)
	}

	mismatch := findMismatch(report.Mismatches, StoreParityMismatchReportDrift, "active-node-count")
	if mismatch == nil {
		t.Fatalf("expected report drift mismatch, got %#v", report.Mismatches)
	}
	if mismatch.Operation != "report" {
		t.Fatalf("expected report operation, got %#v", mismatch)
	}
	if got := mismatchDetailInt(mismatch, "primary.node_count"); got != 3 {
		t.Fatalf("expected primary node count 3, got %#v", mismatch.Details)
	}
	if got := mismatchDetailInt(mismatch, "shadow.node_count"); got != 4 {
		t.Fatalf("expected shadow node count 4, got %#v", mismatch.Details)
	}
}

func TestCompareGraphStoreReportsEquivalentStoresHaveNoDrift(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := buildCutoverParityPrimaryGraph()

	report, err := CompareGraphStoreReports(context.Background(), primary, shadow, []StoreReportProbe{{
		Name: "reachable-services",
		Build: func(g *Graph) (any, error) {
			result, err := g.BlastRadius(context.Background(), "user:alice", 3)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"total_count": result.TotalCount,
			}, nil
		},
	}})
	if err != nil {
		t.Fatalf("CompareGraphStoreReports() error = %v", err)
	}
	if report.HasDrift() {
		t.Fatalf("expected no report drift, got %#v", report)
	}
}

func TestObserveShadowReadGraphStoreReportsEmitsDrift(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadow := buildCutoverParityPrimaryGraph()
	shadow.AddNode(&Node{ID: "cache:edge", Kind: NodeKindDatabase, Name: "Edge Cache"})

	var reports []StoreParityReport
	store := NewShadowReadGraphStore(primary, shadow, func(_ context.Context, report StoreParityReport) {
		reports = append(reports, report)
	})

	err := ObserveShadowReadGraphStoreReports(context.Background(), store, []StoreReportProbe{{
		Name: "active-node-count",
		Build: func(g *Graph) (any, error) {
			snapshot, err := g.Snapshot(context.Background())
			if err != nil {
				return nil, err
			}
			nodeCount, _ := activeSnapshotCounts(snapshot)
			return map[string]any{"node_count": nodeCount}, nil
		},
	}})
	if err != nil {
		t.Fatalf("ObserveShadowReadGraphStoreReports() error = %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected one parity report, got %#v", reports)
	}
	if classes := mismatchClasses(reports[0].Mismatches); !slices.Contains(classes, StoreParityMismatchReportDrift) {
		t.Fatalf("expected report drift mismatch, got %#v", reports[0].Mismatches)
	}
}

func TestObserveShadowReadGraphStoreReportsEmitsShadowErrors(t *testing.T) {
	primary := buildCutoverParityPrimaryGraph()
	shadowErr := errors.New("shadow unavailable")
	store := NewShadowReadGraphStore(primary, failingShadowGraphStore{GraphStore: New(), err: shadowErr}, nil)

	shadowStore, ok := store.(*ShadowReadGraphStore)
	if !ok {
		t.Fatalf("expected shadow read wrapper, got %T", store)
	}
	var reports []StoreParityReport
	shadowStore.observe = func(_ context.Context, report StoreParityReport) {
		reports = append(reports, report)
	}

	err := ObserveShadowReadGraphStoreReports(context.Background(), shadowStore, []StoreReportProbe{{
		Name: "active-node-count",
		Build: func(g *Graph) (any, error) {
			snapshot, err := g.Snapshot(context.Background())
			if err != nil {
				return nil, err
			}
			nodeCount, _ := activeSnapshotCounts(snapshot)
			return map[string]any{"node_count": nodeCount}, nil
		},
	}})
	if err != nil {
		t.Fatalf("ObserveShadowReadGraphStoreReports() error = %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected one shadow-error report, got %#v", reports)
	}
	if classes := mismatchClasses(reports[0].Mismatches); !slices.Contains(classes, StoreParityMismatchShadowError) {
		t.Fatalf("expected shadow-error mismatch, got %#v", reports[0].Mismatches)
	}
}

type failingShadowGraphStore struct {
	GraphStore
	err error
}

func (s failingShadowGraphStore) Snapshot(context.Context) (*Snapshot, error) {
	return nil, s.err
}

func (s failingShadowGraphStore) BlastRadius(context.Context, string, int) (*BlastRadiusResult, error) {
	return nil, s.err
}

func buildCutoverParityPrimaryGraph() *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:alice", Kind: NodeKindUser, Name: "Alice"})
	g.AddNode(&Node{ID: "service:api", Kind: NodeKindService, Name: "API"})
	g.AddNode(&Node{ID: "db:prod", Kind: NodeKindDatabase, Name: "Prod DB"})
	g.AddEdge(&Edge{ID: "alice-api", Source: "user:alice", Target: "service:api", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "api-db", Source: "service:api", Target: "db:prod", Kind: EdgeKindDependsOn, Effect: EdgeEffectAllow})
	return g
}

func mismatchClasses(mismatches []StoreParityMismatch) []StoreParityMismatchClass {
	out := make([]StoreParityMismatchClass, 0, len(mismatches))
	for _, mismatch := range mismatches {
		out = append(out, mismatch.Class)
	}
	return out
}

func findMismatch(mismatches []StoreParityMismatch, class StoreParityMismatchClass, identifier string) *StoreParityMismatch {
	for i := range mismatches {
		if mismatches[i].Class == class && mismatches[i].Identifier == identifier {
			return &mismatches[i]
		}
	}
	return nil
}

func mismatchDetailInt(mismatch *StoreParityMismatch, path string) int {
	if mismatch == nil {
		return 0
	}
	parts := []string{}
	for _, part := range splitMismatchDetailPath(path) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	var current any = mismatch.Details
	for _, part := range parts {
		asMap, ok := current.(map[string]any)
		if !ok {
			return 0
		}
		current = asMap[part]
	}
	switch typed := current.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func splitMismatchDetailPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i < len(path) && path[i] != '.' {
			continue
		}
		parts = append(parts, path[start:i])
		start = i + 1
	}
	return parts
}

func mismatchDetailString(mismatch *StoreParityMismatch, key string) string {
	if mismatch == nil || mismatch.Details == nil {
		return ""
	}
	value, _ := mismatch.Details[key].(string)
	return value
}
