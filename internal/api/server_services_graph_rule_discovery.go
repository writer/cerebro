package api

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
	risk "github.com/writer/cerebro/internal/graph/risk"
	"github.com/writer/cerebro/internal/metrics"
)

type graphRuleDiscoveryService interface {
	Discover(ctx context.Context, req graph.RuleDiscoveryRequest) ([]graph.DiscoveredRuleCandidate, error)
	List(ctx context.Context, status string) ([]graph.DiscoveredRuleCandidate, error)
	Decide(ctx context.Context, candidateID string, req graph.RuleDecisionRequest) (*graph.DiscoveredRuleCandidate, error)
}

type serverGraphRuleDiscoveryService struct {
	server *Server
}

func newGraphRuleDiscoveryService(server *Server) graphRuleDiscoveryService {
	return serverGraphRuleDiscoveryService{server: server}
}

func (s serverGraphRuleDiscoveryService) Discover(ctx context.Context, req graph.RuleDiscoveryRequest) ([]graph.DiscoveredRuleCandidate, error) {
	engine := s.engine(ctx)
	if engine == nil {
		return nil, errGraphRiskUnavailable
	}

	candidates := engine.DiscoverRules(req)
	for _, candidate := range candidates {
		metrics.RecordGraphRuleDiscoveryCandidate(candidate.Type, candidate.Status)
	}
	s.server.persistRiskEngineState(ctx, engine)
	return candidates, nil
}

func (s serverGraphRuleDiscoveryService) List(ctx context.Context, status string) ([]graph.DiscoveredRuleCandidate, error) {
	engine := s.engine(ctx)
	if engine == nil {
		return nil, errGraphRiskUnavailable
	}
	return engine.ListDiscoveredRules(status), nil
}

func (s serverGraphRuleDiscoveryService) Decide(ctx context.Context, candidateID string, req graph.RuleDecisionRequest) (*graph.DiscoveredRuleCandidate, error) {
	engine := s.engine(ctx)
	if engine == nil {
		return nil, errGraphRiskUnavailable
	}

	updated, err := engine.DecideDiscoveredRule(candidateID, req)
	if err != nil {
		return nil, err
	}
	metrics.RecordGraphRuleDecision(updated.Type, updated.Status)
	s.server.persistRiskEngineState(ctx, engine)
	return updated, nil
}

func (s serverGraphRuleDiscoveryService) engine(ctx context.Context) *risk.RiskEngine {
	if s.server == nil || s.server.app == nil {
		return nil
	}
	return s.server.graphRiskEngine(ctx)
}

var _ graphRuleDiscoveryService = serverGraphRuleDiscoveryService{}
