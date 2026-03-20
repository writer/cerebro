package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/knowledge"
)

type stubGraphAdvisoryService struct {
	evaluateChangeFunc func(context.Context, *graph.ChangeProposal, ...graph.PropagationOption) (*graph.PropagationResult, error)
	recommendTeamFunc  func(context.Context, graph.TeamRecommendationRequest) (graph.TeamRecommendationResult, error)
	whoKnowsFunc       func(context.Context, knowledge.KnowledgeQuery) (knowledge.KnowledgeRoutingResult, error)
}

func (s stubGraphAdvisoryService) EvaluateChange(ctx context.Context, proposal *graph.ChangeProposal, options ...graph.PropagationOption) (*graph.PropagationResult, error) {
	if s.evaluateChangeFunc != nil {
		return s.evaluateChangeFunc(ctx, proposal, options...)
	}
	return &graph.PropagationResult{}, nil
}

func (s stubGraphAdvisoryService) RecommendTeam(ctx context.Context, req graph.TeamRecommendationRequest) (graph.TeamRecommendationResult, error) {
	if s.recommendTeamFunc != nil {
		return s.recommendTeamFunc(ctx, req)
	}
	return graph.TeamRecommendationResult{}, nil
}

func (s stubGraphAdvisoryService) WhoKnows(ctx context.Context, query knowledge.KnowledgeQuery) (knowledge.KnowledgeRoutingResult, error) {
	if s.whoKnowsFunc != nil {
		return s.whoKnowsFunc(ctx, query)
	}
	return knowledge.KnowledgeRoutingResult{}, nil
}

func TestGraphAdvisoryReadHandlersUseServiceInterface(t *testing.T) {
	var (
		whoKnowsCalled      bool
		recommendTeamCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphAdvisory: stubGraphAdvisoryService{
			whoKnowsFunc: func(_ context.Context, query knowledge.KnowledgeQuery) (knowledge.KnowledgeRoutingResult, error) {
				whoKnowsCalled = true
				if query.System != "auth-svc" {
					t.Fatalf("expected auth-svc system query, got %q", query.System)
				}
				if query.Limit != 2 {
					t.Fatalf("expected limit=2, got %d", query.Limit)
				}
				return knowledge.KnowledgeRoutingResult{
					Count: 1,
					Candidates: []knowledge.KnowledgeCandidate{{
						Person: &graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice"},
					}},
				}, nil
			},
			recommendTeamFunc: func(_ context.Context, req graph.TeamRecommendationRequest) (graph.TeamRecommendationResult, error) {
				recommendTeamCalled = true
				if len(req.TargetSystems) != 2 || req.TargetSystems[0] != "payment-service" {
					t.Fatalf("unexpected target systems: %#v", req.TargetSystems)
				}
				return graph.TeamRecommendationResult{
					RecommendedTeam: []graph.TeamCandidate{{
						Person: &graph.TeamCandidatePerson{ID: "person:alice@example.com", Name: "Alice"},
					}},
				}, nil
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/org/expertise/queries?system=auth-svc&limit=2", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed who-knows query, got %d: %s", w.Code, w.Body.String())
	}
	if !whoKnowsCalled {
		t.Fatal("expected who-knows handler to use graphAdvisory service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/org/team-recommendations", map[string]any{
		"target_systems": []string{"payment-service", "billing-api"},
		"team_size":      2,
	}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed team recommendation, got %d: %s", w.Code, w.Body.String())
	}
	if !recommendTeamCalled {
		t.Fatal("expected recommend-team handler to use graphAdvisory service")
	}
}

func TestGraphAdvisoryEvaluateChangeHandlerUsesServiceInterface(t *testing.T) {
	var called bool

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphAdvisory: stubGraphAdvisoryService{
			evaluateChangeFunc: func(_ context.Context, proposal *graph.ChangeProposal, _ ...graph.PropagationOption) (*graph.PropagationResult, error) {
				called = true
				if proposal == nil {
					t.Fatal("expected proposal")
				}
				if proposal.ID != "proposal-1" {
					t.Fatalf("expected proposal-1, got %q", proposal.ID)
				}
				if len(proposal.Delta.Nodes) != 1 {
					t.Fatalf("expected one node mutation, got %#v", proposal.Delta)
				}
				return &graph.PropagationResult{
					Decision: graph.DecisionSafe,
				}, nil
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/graph/evaluate-change", map[string]any{
		"id":     "proposal-1",
		"source": "api-test",
		"reason": "quarterly review",
		"nodes": []map[string]any{{
			"type": "modify_node",
			"id":   "user-1",
		}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed graph change evaluation, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected evaluate-change handler to use graphAdvisory service")
	}
}

func TestGraphAdvisoryEvaluateChangeHandlerReturnsServiceUnavailableWhenStoreUnavailable(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphAdvisory: stubGraphAdvisoryService{
			evaluateChangeFunc: func(_ context.Context, _ *graph.ChangeProposal, _ ...graph.PropagationOption) (*graph.PropagationResult, error) {
				return nil, graph.ErrStoreUnavailable
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/graph/evaluate-change", map[string]any{
		"id":     "proposal-1",
		"source": "api-test",
		"reason": "quarterly review",
		"nodes": []map[string]any{{
			"type": "modify_node",
			"id":   "user-1",
		}},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for store-unavailable graph change evaluation, got %d: %s", w.Code, w.Body.String())
	}
}
