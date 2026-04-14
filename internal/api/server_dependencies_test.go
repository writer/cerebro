package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
)

type stubGraphRuntime struct {
	freshness      app.GraphFreshnessStatus
	graph          *graph.Graph
	store          graph.GraphStore
	healthSnapshot app.GraphHealthSnapshot
	tryApply       func(context.Context, string) (graph.GraphMutationSummary, bool, error)
}

func (s stubGraphRuntime) CurrentSecurityGraph() *graph.Graph { return s.graph }

func (s stubGraphRuntime) CurrentSecurityGraphStore() graph.GraphStore { return s.store }

func (s stubGraphRuntime) CurrentSecurityGraphStoreForTenant(_ string) graph.GraphStore {
	return s.store
}

func (s stubGraphRuntime) GraphBuildSnapshot() app.GraphBuildSnapshot {
	return app.GraphBuildSnapshot{State: app.GraphBuildSuccess}
}

func (s stubGraphRuntime) CurrentRetentionStatus() app.RetentionStatus { return app.RetentionStatus{} }

func (s stubGraphRuntime) GraphFreshnessStatusSnapshot(_ time.Time) app.GraphFreshnessStatus {
	return s.freshness
}

func (s stubGraphRuntime) GraphHealthSnapshot(now time.Time) app.GraphHealthSnapshot {
	snapshot := s.healthSnapshot
	if snapshot.EvaluatedAt.IsZero() {
		snapshot.EvaluatedAt = now.UTC()
	}
	if s.graph != nil {
		snapshot.NodeCount = s.graph.NodeCount()
		snapshot.EdgeCount = s.graph.EdgeCount()
		if snapshot.TierDistribution.Hot == 0 {
			snapshot.TierDistribution.Hot = 1
		}
	}
	return snapshot
}

func (s stubGraphRuntime) RebuildSecurityGraph(_ context.Context) error { return nil }

func (s stubGraphRuntime) TryApplySecurityGraphChanges(ctx context.Context, trigger string) (graph.GraphMutationSummary, bool, error) {
	if s.tryApply != nil {
		return s.tryApply(ctx, trigger)
	}
	return graph.GraphMutationSummary{}, true, nil
}

func (s stubGraphRuntime) CanApplySecurityGraphChanges() bool {
	return s.tryApply != nil
}

type mutatingFallbackGraphRuntime struct {
	current *graph.Graph
}

func (m *mutatingFallbackGraphRuntime) CurrentSecurityGraph() *graph.Graph { return m.current }

func (m *mutatingFallbackGraphRuntime) CurrentSecurityGraphStore() graph.GraphStore { return m.current }

func (m *mutatingFallbackGraphRuntime) CurrentSecurityGraphStoreForTenant(_ string) graph.GraphStore {
	return m.current
}

func (m *mutatingFallbackGraphRuntime) GraphBuildSnapshot() app.GraphBuildSnapshot {
	return app.GraphBuildSnapshot{State: app.GraphBuildSuccess}
}

func (m *mutatingFallbackGraphRuntime) CurrentRetentionStatus() app.RetentionStatus {
	return app.RetentionStatus{}
}

func (m *mutatingFallbackGraphRuntime) GraphFreshnessStatusSnapshot(_ time.Time) app.GraphFreshnessStatus {
	return app.GraphFreshnessStatus{}
}

func (m *mutatingFallbackGraphRuntime) RebuildSecurityGraph(_ context.Context) error { return nil }

func (m *mutatingFallbackGraphRuntime) TryApplySecurityGraphChanges(_ context.Context, _ string) (graph.GraphMutationSummary, bool, error) {
	next := graph.New()
	next.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService})
	m.current = next
	return graph.GraphMutationSummary{}, true, nil
}

func (m *mutatingFallbackGraphRuntime) CanApplySecurityGraphChanges() bool { return true }

type emptyBuilderDataSource struct{}

func (emptyBuilderDataSource) Query(context.Context, string, ...any) (*builders.DataQueryResult, error) {
	return &builders.DataQueryResult{Rows: []map[string]any{}}, nil
}

func TestNewServerWithDependencies_UsesGraphRuntimeWithoutApp(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphRuntime: stubGraphRuntime{
			freshness: app.GraphFreshnessStatus{
				EvaluatedAt: time.Date(2026, time.March, 12, 15, 0, 0, 0, time.UTC),
				Healthy:     false,
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodGet, "/api/v1/status/freshness", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["healthy"] != false {
		t.Fatalf("expected freshness healthy=false, got %#v", body)
	}
}

func TestNewServerWithDependencies_DefaultsLoggerWhenNil(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
	})
	t.Cleanup(func() { s.Close() })

	if s.app == nil || s.app.Logger == nil {
		t.Fatalf("expected constructor to default logger, got %#v", s.app)
	}
}

func TestNewServerWithDependencies_InitializesRuntimeIngestFromExecutionStore(t *testing.T) {
	a := newTestApp(t)
	deps := newServerDependenciesFromApp(a)
	deps.RuntimeIngest = nil

	s := NewServerWithDependencies(deps)
	t.Cleanup(func() { s.Close() })

	if s.app == nil || s.app.RuntimeIngest == nil {
		t.Fatalf("expected constructor to initialize runtime ingest store, got %#v", s.app)
	}
	if got := s.runtimeIngestStore(); got == nil {
		t.Fatal("expected runtimeIngestStore to return initialized store")
		return
	}
}

func TestServerDependenciesCurrentSecurityGraphStoreUsesRuntimeStore(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService})

	deps := serverDependencies{
		graphRuntime: stubGraphRuntime{store: g},
	}

	store := deps.CurrentSecurityGraphStore()
	if store == nil {
		t.Fatal("expected graph store from runtime")
		return
	}
	node, ok, err := store.LookupNode(context.Background(), "service:payments")
	if err != nil {
		t.Fatalf("LookupNode() error = %v", err)
	}
	if !ok || node == nil || node.ID != "service:payments" {
		t.Fatalf("LookupNode() = (%#v, %v), want service:payments", node, ok)
	}
}

func TestServerDependenciesCanApplySecurityGraphChangesIgnoresUnconfiguredAdapter(t *testing.T) {
	deps := newServerDependenciesFromApp(&app.App{Config: &app.Config{}})

	if deps.CanApplySecurityGraphChanges() {
		t.Fatal("expected unconfigured adapter to report no graph apply capability")
	}
}

func TestGraphRuntimeAdapterCanApplySecurityGraphChangesAfterFallbackRefresh(t *testing.T) {
	fallback := &mutatingFallbackGraphRuntime{current: graph.New()}
	deps := &serverDependencies{}
	runtime := &graphRuntimeAdapter{
		deps:     deps,
		delegate: fallback,
	}

	if !runtime.CanApplySecurityGraphChanges() {
		t.Fatal("expected fallback apply capability before refresh")
	}

	if _, applied, err := runtime.TryApplySecurityGraphChanges(context.Background(), "sync"); err != nil {
		t.Fatalf("TryApplySecurityGraphChanges() error = %v", err)
	} else if !applied {
		t.Fatal("expected fallback apply to report applied")
	}

	if deps.SecurityGraph != fallback.current {
		t.Fatalf("expected deps graph to track refreshed fallback graph")
	}
	if !runtime.CanApplySecurityGraphChanges() {
		t.Fatal("expected fallback apply capability after refresh")
	}
}

func TestServerDependenciesGraphHealthSnapshotEstimatesMemoryFromGraphCounts(t *testing.T) {
	current := graph.New()
	current.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService})
	current.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket})
	current.AddEdge(&graph.Edge{ID: "edge:read", Source: "service:payments", Target: "bucket:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	snapshot := serverDependencies{SecurityGraph: current}.GraphHealthSnapshot(time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC))
	expected := app.EstimateGraphMemoryUsageBytes(current.NodeCount(), current.EdgeCount())

	if snapshot.MemoryUsageEstimateBytes != expected {
		t.Fatalf("MemoryUsageEstimateBytes = %d, want %d", snapshot.MemoryUsageEstimateBytes, expected)
	}
}

func TestServerDependenciesGraphHealthSnapshotEmptyGraphIsNotHot(t *testing.T) {
	snapshot := serverDependencies{SecurityGraph: graph.New()}.GraphHealthSnapshot(time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC))

	if snapshot.TierDistribution.Hot != 0 {
		t.Fatalf("TierDistribution.Hot = %d, want 0", snapshot.TierDistribution.Hot)
	}
}

func TestGraphRuntimeAdapterGraphHealthSnapshotNilReceiver(t *testing.T) {
	var runtime *graphRuntimeAdapter

	snapshot := runtime.GraphHealthSnapshot(time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC))
	if snapshot != (app.GraphHealthSnapshot{}) {
		t.Fatalf("GraphHealthSnapshot() = %+v, want zero value", snapshot)
	}
}

func TestGraphRuntimeAdapterGraphHealthSnapshotRecalculatesMemoryEstimate(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)

	providerGraph := graph.New()
	providerGraph.AddNode(&graph.Node{ID: "service:provider", Kind: graph.NodeKindService})

	localGraph := graph.New()
	localGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService})
	localGraph.AddNode(&graph.Node{ID: "bucket:prod", Kind: graph.NodeKindBucket})
	localGraph.AddEdge(&graph.Edge{ID: "edge:read", Source: "service:payments", Target: "bucket:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	runtime := &graphRuntimeAdapter{
		deps: &serverDependencies{
			SecurityGraph:        localGraph,
			SecurityGraphBuilder: &builders.Builder{},
		},
		delegate: stubGraphRuntime{
			graph: providerGraph,
			healthSnapshot: app.GraphHealthSnapshot{
				MemoryUsageEstimateBytes: app.EstimateGraphMemoryUsageBytes(providerGraph.NodeCount(), providerGraph.EdgeCount()),
			},
		},
	}

	snapshot := runtime.GraphHealthSnapshot(now)
	expected := app.EstimateGraphMemoryUsageBytes(localGraph.NodeCount(), localGraph.EdgeCount())

	if snapshot.NodeCount != localGraph.NodeCount() || snapshot.EdgeCount != localGraph.EdgeCount() {
		t.Fatalf("snapshot counts = (%d,%d), want (%d,%d)", snapshot.NodeCount, snapshot.EdgeCount, localGraph.NodeCount(), localGraph.EdgeCount())
	}
	if snapshot.MemoryUsageEstimateBytes != expected {
		t.Fatalf("MemoryUsageEstimateBytes = %d, want %d", snapshot.MemoryUsageEstimateBytes, expected)
	}
}

func TestGraphRuntimeAdapterGraphHealthSnapshotEmptyLocalGraphIsNotHot(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)

	t.Run("with provider snapshot", func(t *testing.T) {
		runtime := &graphRuntimeAdapter{
			deps: &serverDependencies{
				SecurityGraph:        graph.New(),
				SecurityGraphBuilder: &builders.Builder{},
			},
			delegate: stubGraphRuntime{},
		}

		snapshot := runtime.GraphHealthSnapshot(now)
		if snapshot.TierDistribution.Hot != 0 {
			t.Fatalf("TierDistribution.Hot = %d, want 0", snapshot.TierDistribution.Hot)
		}
	})

	t.Run("without provider snapshot", func(t *testing.T) {
		runtime := &graphRuntimeAdapter{
			deps: &serverDependencies{
				SecurityGraph: graph.New(),
			},
		}

		snapshot := runtime.GraphHealthSnapshot(now)
		if snapshot.TierDistribution.Hot != 0 {
			t.Fatalf("TierDistribution.Hot = %d, want 0", snapshot.TierDistribution.Hot)
		}
	})
}

func TestGraphRuntimeAdapterGraphHealthSnapshotFallbackUsesLocalBuilderLastMutation(t *testing.T) {
	now := time.Date(2026, time.March, 20, 18, 0, 0, 0, time.UTC)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	builder := builders.NewBuilder(emptyBuilderDataSource{}, logger)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	lastMutationAt := builder.LastMutation().Until
	if lastMutationAt.IsZero() {
		t.Fatal("expected local builder to record a last mutation time")
	}

	localGraph := graph.New()
	localGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService})

	runtime := &graphRuntimeAdapter{
		deps: &serverDependencies{
			SecurityGraph:        localGraph,
			SecurityGraphBuilder: builder,
		},
		delegate: &mutatingFallbackGraphRuntime{current: graph.New()},
	}

	snapshot := runtime.GraphHealthSnapshot(now)
	if !snapshot.LastMutationAt.Equal(lastMutationAt.UTC()) {
		t.Fatalf("LastMutationAt = %s, want %s", snapshot.LastMutationAt, lastMutationAt.UTC())
	}
}
