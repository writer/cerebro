package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

type stubGraphRuntime struct {
	freshness app.GraphFreshnessStatus
	graph     *graph.Graph
	store     graph.GraphStore
	tryApply  func(context.Context, string) (graph.GraphMutationSummary, bool, error)
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
		fallback: fallback,
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
