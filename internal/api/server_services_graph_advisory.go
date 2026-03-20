package api

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/knowledge"
)

type graphAdvisoryService interface {
	EvaluateChange(ctx context.Context, proposal *graph.ChangeProposal, options ...graph.PropagationOption) (*graph.PropagationResult, error)
	RecommendTeam(ctx context.Context, req graph.TeamRecommendationRequest) (graph.TeamRecommendationResult, error)
	WhoKnows(ctx context.Context, query knowledge.KnowledgeQuery) (knowledge.KnowledgeRoutingResult, error)
}

type serverGraphAdvisoryService struct {
	deps *serverDependencies
}

func newGraphAdvisoryService(deps *serverDependencies) graphAdvisoryService {
	return serverGraphAdvisoryService{deps: deps}
}

func (s serverGraphAdvisoryService) graphView(ctx context.Context) (*graph.Graph, error) {
	return currentOrStoredTenantGraphView(ctx, s.deps)
}

func (s serverGraphAdvisoryService) EvaluateChange(ctx context.Context, proposal *graph.ChangeProposal, options ...graph.PropagationOption) (*graph.PropagationResult, error) {
	g, err := s.graphView(ctx)
	if err != nil {
		return nil, err
	}
	engine := graph.NewPropagationEngine(g, options...)
	return engine.Evaluate(proposal)
}

func (s serverGraphAdvisoryService) RecommendTeam(ctx context.Context, req graph.TeamRecommendationRequest) (graph.TeamRecommendationResult, error) {
	g, err := s.graphView(ctx)
	if err != nil {
		return graph.TeamRecommendationResult{}, err
	}
	return graph.RecommendTeam(g, req), nil
}

func (s serverGraphAdvisoryService) WhoKnows(ctx context.Context, query knowledge.KnowledgeQuery) (knowledge.KnowledgeRoutingResult, error) {
	g, err := s.graphView(ctx)
	if err != nil {
		return knowledge.KnowledgeRoutingResult{}, err
	}
	return knowledge.WhoKnows(g, query), nil
}

var _ graphAdvisoryService = serverGraphAdvisoryService{}
