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
}

func (s stubGraphRuntime) CurrentSecurityGraph() *graph.Graph { return nil }

func (s stubGraphRuntime) GraphBuildSnapshot() app.GraphBuildSnapshot {
	return app.GraphBuildSnapshot{State: app.GraphBuildSuccess}
}

func (s stubGraphRuntime) CurrentRetentionStatus() app.RetentionStatus { return app.RetentionStatus{} }

func (s stubGraphRuntime) GraphFreshnessStatusSnapshot(_ time.Time) app.GraphFreshnessStatus {
	return s.freshness
}

func (s stubGraphRuntime) RebuildSecurityGraph(_ context.Context) error { return nil }

func (s stubGraphRuntime) TryApplySecurityGraphChanges(_ context.Context, _ string) (graph.GraphMutationSummary, bool, error) {
	return graph.GraphMutationSummary{}, true, nil
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
	}
}
