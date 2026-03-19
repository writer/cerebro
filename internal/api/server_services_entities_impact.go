package api

import (
	"context"

	"github.com/evalops/cerebro/internal/graph"
)

type entitiesImpactService interface {
	GetEntityCohort(ctx context.Context, entityID string) (*graph.EntityCohort, bool, error)
	GetEntityOutlierScore(ctx context.Context, entityID string) (*graph.EntityOutlierScore, bool, error)
	AnalyzeImpact(ctx context.Context, startNodeID string, scenario graph.ImpactScenario, maxDepth int) (*graph.ImpactAnalysisResult, error)
}

type serverEntitiesImpactService struct {
	deps *serverDependencies
}

func newEntitiesImpactService(deps *serverDependencies) entitiesImpactService {
	return serverEntitiesImpactService{deps: deps}
}

func (s serverEntitiesImpactService) GetEntityCohort(ctx context.Context, entityID string) (*graph.EntityCohort, bool, error) {
	view, err := currentOrStoredTenantGraphView(ctx, s.deps)
	if err != nil {
		return nil, false, err
	}
	cohort, ok := graph.GetEntityCohort(view, entityID)
	return cohort, ok, nil
}

func (s serverEntitiesImpactService) GetEntityOutlierScore(ctx context.Context, entityID string) (*graph.EntityOutlierScore, bool, error) {
	view, err := currentOrStoredTenantGraphView(ctx, s.deps)
	if err != nil {
		return nil, false, err
	}
	outlier, ok := graph.GetEntityOutlierScore(view, entityID)
	return outlier, ok, nil
}

func (s serverEntitiesImpactService) AnalyzeImpact(ctx context.Context, startNodeID string, scenario graph.ImpactScenario, maxDepth int) (*graph.ImpactAnalysisResult, error) {
	view, err := currentOrStoredTenantGraphView(ctx, s.deps)
	if err != nil {
		return nil, err
	}
	analyzer := graph.NewImpactPathAnalyzer(view)
	return analyzer.Analyze(startNodeID, scenario, maxDepth), nil
}

var _ entitiesImpactService = serverEntitiesImpactService{}
