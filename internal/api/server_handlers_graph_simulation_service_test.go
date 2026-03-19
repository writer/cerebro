package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

type stubGraphSimulationService struct {
	simulateFunc      func(context.Context, graph.GraphDelta) (*graph.GraphSimulationResult, error)
	simulateReorgFunc func(context.Context, []graph.ReorgChange) (*graph.ReorgImpact, error)
}

func (s stubGraphSimulationService) Simulate(ctx context.Context, delta graph.GraphDelta) (*graph.GraphSimulationResult, error) {
	if s.simulateFunc != nil {
		return s.simulateFunc(ctx, delta)
	}
	return &graph.GraphSimulationResult{}, nil
}

func (s stubGraphSimulationService) SimulateReorg(ctx context.Context, changes []graph.ReorgChange) (*graph.ReorgImpact, error) {
	if s.simulateReorgFunc != nil {
		return s.simulateReorgFunc(ctx, changes)
	}
	return &graph.ReorgImpact{}, nil
}

func TestGraphSimulationHandlersUseServiceInterface(t *testing.T) {
	var (
		simulateCalled bool
		reorgCalled    bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphSimulation: stubGraphSimulationService{
			simulateFunc: func(_ context.Context, delta graph.GraphDelta) (*graph.GraphSimulationResult, error) {
				simulateCalled = true
				if len(delta.Nodes) != 1 {
					t.Fatalf("expected one node mutation, got %#v", delta.Nodes)
				}
				if delta.Nodes[0].Action != "modify" || delta.Nodes[0].ID != "user-1" {
					t.Fatalf("unexpected node delta: %#v", delta.Nodes[0])
				}
				if len(delta.Edges) != 1 {
					t.Fatalf("expected one edge mutation, got %#v", delta.Edges)
				}
				if delta.Edges[0].Action != "remove" || delta.Edges[0].Source != "user-1" || delta.Edges[0].Target != "role-1" {
					t.Fatalf("unexpected edge delta: %#v", delta.Edges[0])
				}
				return &graph.GraphSimulationResult{
					Delta: graph.GraphSimulationDiff{RiskScoreDelta: 12.5},
				}, nil
			},
			simulateReorgFunc: func(_ context.Context, changes []graph.ReorgChange) (*graph.ReorgImpact, error) {
				reorgCalled = true
				if len(changes) != 1 {
					t.Fatalf("expected one reorg change, got %#v", changes)
				}
				if changes[0].Person != "person:bob@example.com" || changes[0].NewDepartment != "Platform" {
					t.Fatalf("unexpected reorg change: %#v", changes[0])
				}
				return &graph.ReorgImpact{
					RecommendedActions: []graph.ReorgMitigation{{
						Action:   "assign-shadow",
						Priority: "high",
					}},
				}, nil
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	simResp := do(t, s, http.MethodPost, "/api/v1/graph/simulate", map[string]any{
		"mutations": []map[string]any{
			{"type": "remove_edge", "source": "user-1", "target": "role-1", "kind": "can_assume"},
			{"type": "modify_node", "id": "user-1", "properties": map[string]any{"mfa_enabled": true}},
		},
	})
	if simResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed simulate handler, got %d: %s", simResp.Code, simResp.Body.String())
	}
	if !simulateCalled {
		t.Fatal("expected simulate handler to use graphSimulation service")
	}
	simBody := decodeJSON(t, simResp)
	delta, ok := simBody["delta"].(map[string]any)
	if !ok || delta["risk_score_delta"] != 12.5 {
		t.Fatalf("expected stubbed simulation result, got %#v", simBody)
	}

	reorgResp := do(t, s, http.MethodPost, "/api/v1/org/reorg-simulations", map[string]any{
		"changes": []map[string]any{{
			"person":         "person:bob@example.com",
			"new_department": "Platform",
			"new_manager":    "person:vp@example.com",
		}},
	})
	if reorgResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed reorg simulate handler, got %d: %s", reorgResp.Code, reorgResp.Body.String())
	}
	if !reorgCalled {
		t.Fatal("expected reorg simulation handler to use graphSimulation service")
	}
	reorgBody := decodeJSON(t, reorgResp)
	actions, ok := reorgBody["recommended_actions"].([]any)
	if !ok || len(actions) != 1 {
		t.Fatalf("expected stubbed reorg impact response, got %#v", reorgBody)
	}
}
