package api

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
)

type graphSimulationService interface {
	Simulate(ctx context.Context, delta graph.GraphDelta) (*graph.GraphSimulationResult, error)
	SimulateReorg(ctx context.Context, changes []graph.ReorgChange) (*graph.ReorgImpact, error)
}

type serverGraphSimulationService struct {
	deps *serverDependencies
}

func newGraphSimulationService(deps *serverDependencies) graphSimulationService {
	return serverGraphSimulationService{deps: deps}
}

func (s serverGraphSimulationService) Simulate(ctx context.Context, delta graph.GraphDelta) (*graph.GraphSimulationResult, error) {
	g, err := currentOrStoredTenantGraphView(ctx, s.deps)
	if err != nil {
		return nil, err
	}
	return g.Simulate(delta)
}

func (s serverGraphSimulationService) SimulateReorg(ctx context.Context, changes []graph.ReorgChange) (*graph.ReorgImpact, error) {
	g, err := currentOrStoredTenantGraphView(ctx, s.deps)
	if err != nil {
		return nil, err
	}
	return graph.SimulateReorg(g, changes)
}

var _ graphSimulationService = serverGraphSimulationService{}
