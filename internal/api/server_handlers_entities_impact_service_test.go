package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
)

type stubEntitiesImpactService struct {
	getEntityCohortFunc       func(context.Context, string) (*graph.EntityCohort, bool, error)
	getEntityOutlierScoreFunc func(context.Context, string) (*graph.EntityOutlierScore, bool, error)
	analyzeImpactFunc         func(context.Context, string, graph.ImpactScenario, int) (*graph.ImpactAnalysisResult, error)
}

func (s stubEntitiesImpactService) GetEntityCohort(ctx context.Context, entityID string) (*graph.EntityCohort, bool, error) {
	if s.getEntityCohortFunc != nil {
		return s.getEntityCohortFunc(ctx, entityID)
	}
	return nil, false, nil
}

func (s stubEntitiesImpactService) GetEntityOutlierScore(ctx context.Context, entityID string) (*graph.EntityOutlierScore, bool, error) {
	if s.getEntityOutlierScoreFunc != nil {
		return s.getEntityOutlierScoreFunc(ctx, entityID)
	}
	return nil, false, nil
}

func (s stubEntitiesImpactService) AnalyzeImpact(ctx context.Context, startNodeID string, scenario graph.ImpactScenario, maxDepth int) (*graph.ImpactAnalysisResult, error) {
	if s.analyzeImpactFunc != nil {
		return s.analyzeImpactFunc(ctx, startNodeID, scenario, maxDepth)
	}
	return &graph.ImpactAnalysisResult{}, nil
}

func TestEntityImpactReadHandlersUseServiceInterface(t *testing.T) {
	var (
		cohortCalled  bool
		outlierCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		entitiesImpact: stubEntitiesImpactService{
			getEntityCohortFunc: func(_ context.Context, entityID string) (*graph.EntityCohort, bool, error) {
				cohortCalled = true
				if entityID != "customer-1" {
					t.Fatalf("expected customer-1, got %q", entityID)
				}
				return &graph.EntityCohort{
					EntityID: "customer-1",
					GroupID:  "cohort-a",
					Members:  []string{"customer-1", "customer-2"},
				}, true, nil
			},
			getEntityOutlierScoreFunc: func(_ context.Context, entityID string) (*graph.EntityOutlierScore, bool, error) {
				outlierCalled = true
				if entityID != "customer-1" {
					t.Fatalf("expected customer-1, got %q", entityID)
				}
				return &graph.EntityOutlierScore{
					EntityID:     "customer-1",
					OutlierScore: 0.42,
				}, true, nil
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	cohort := do(t, s, http.MethodGet, "/api/v1/entities/customer-1/cohort", nil)
	if cohort.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed cohort lookup, got %d: %s", cohort.Code, cohort.Body.String())
	}
	if !cohortCalled {
		t.Fatal("expected cohort handler to use entitiesImpact service")
	}

	outlier := do(t, s, http.MethodGet, "/api/v1/entities/customer-1/outlier-score", nil)
	if outlier.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed outlier lookup, got %d: %s", outlier.Code, outlier.Body.String())
	}
	if !outlierCalled {
		t.Fatal("expected outlier handler to use entitiesImpact service")
	}
}

func TestEntityImpactAnalysisHandlerUsesServiceInterface(t *testing.T) {
	var called bool

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		entitiesImpact: stubEntitiesImpactService{
			analyzeImpactFunc: func(_ context.Context, startNodeID string, scenario graph.ImpactScenario, maxDepth int) (*graph.ImpactAnalysisResult, error) {
				called = true
				if startNodeID != "subscription-1" {
					t.Fatalf("expected subscription-1, got %q", startNodeID)
				}
				if scenario != graph.ImpactScenarioRevenueImpact {
					t.Fatalf("expected revenue_impact, got %q", scenario)
				}
				if maxDepth != 4 {
					t.Fatalf("expected maxDepth=4, got %d", maxDepth)
				}
				return &graph.ImpactAnalysisResult{
					Scenario:  scenario,
					StartNode: startNodeID,
					Paths: []*graph.ImpactPath{{
						ID:        "path-1",
						Scenario:  scenario,
						StartNode: startNodeID,
						EndNode:   "deal-1",
					}},
				}, nil
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/impact-analysis", map[string]any{
		"start_node": "subscription-1",
		"scenario":   "revenue_impact",
		"max_depth":  4,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed impact analysis, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected impact analysis handler to use entitiesImpact service")
	}
}

func TestEntityImpactHandlersReturnServiceUnavailableWhenGraphMissing(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
	})
	t.Cleanup(func() { s.Close() })

	cohort := do(t, s, http.MethodGet, "/api/v1/entities/customer-1/cohort", nil)
	if cohort.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for missing graph-backed cohort lookup, got %d: %s", cohort.Code, cohort.Body.String())
	}

	impact := do(t, s, http.MethodPost, "/api/v1/impact-analysis", map[string]any{
		"start_node": "subscription-1",
		"scenario":   "revenue_impact",
	})
	if impact.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for missing graph-backed impact analysis, got %d: %s", impact.Code, impact.Body.String())
	}
}
