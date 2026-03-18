package api

import (
	"context"
	"errors"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	risk "github.com/evalops/cerebro/internal/graph/risk"
)

var errGraphRiskUnavailable = errors.New("graph platform not initialized")

type graphRiskStatsResponse struct {
	BuiltAt       time.Time `json:"built_at"`
	NodeCount     int       `json:"node_count"`
	EdgeCount     int       `json:"edge_count"`
	Providers     []string  `json:"providers"`
	Accounts      []string  `json:"accounts"`
	BuildDuration string    `json:"build_duration"`
}

type graphRebuildResponse struct {
	Success       bool      `json:"success"`
	BuiltAt       time.Time `json:"built_at"`
	NodeCount     int       `json:"node_count"`
	EdgeCount     int       `json:"edge_count"`
	BuildDuration string    `json:"build_duration"`
}

type graphRiskService interface {
	GraphStats(ctx context.Context) (*graphRiskStatsResponse, error)
	BlastRadius(ctx context.Context, principalID string, maxDepth int) (*risk.BlastRadiusResult, error)
	CascadingBlastRadius(ctx context.Context, principalID string, maxDepth int) (*risk.CascadingBlastRadiusResult, error)
	ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*risk.ReverseAccessResult, error)
	Rebuild(ctx context.Context) (*graphRebuildResponse, error)
	RiskReport(ctx context.Context) (*risk.SecurityReport, error)
	ToxicCombinations(ctx context.Context) ([]*risk.ToxicCombination, error)
	AttackPaths(ctx context.Context, maxDepth int) (*risk.SimulationResult, error)
	SimulateAttackPathFix(ctx context.Context, nodeID string) (*risk.FixSimulation, error)
	Chokepoints(ctx context.Context) ([]*risk.Chokepoint, error)
	DetectPrivilegeEscalation(ctx context.Context, principalID string) ([]*graph.PrivilegeEscalationRisk, error)
	AnalyzePeerGroups(ctx context.Context, minSimilarity float64, minGroupSize int) (*graph.PeerGroupAnalysis, []*graph.OutlierNode, error)
	EffectivePermissions(ctx context.Context, principalID string, evalCtx *graph.PermissionEvaluationContext) (*graph.EffectivePermissions, error)
	ComparePermissions(ctx context.Context, principal1, principal2 string) (*graph.AccessComparison, error)
}

type serverGraphRiskService struct {
	server *Server
	deps   *serverDependencies
}

func newGraphRiskService(server *Server, deps *serverDependencies) graphRiskService {
	return serverGraphRiskService{server: server, deps: deps}
}

func (s serverGraphRiskService) GraphStats(ctx context.Context) (*graphRiskStatsResponse, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	meta := g.Metadata()
	return &graphRiskStatsResponse{
		BuiltAt:       meta.BuiltAt,
		NodeCount:     meta.NodeCount,
		EdgeCount:     meta.EdgeCount,
		Providers:     append([]string(nil), meta.Providers...),
		Accounts:      append([]string(nil), meta.Accounts...),
		BuildDuration: meta.BuildDuration.String(),
	}, nil
}

func (s serverGraphRiskService) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*risk.BlastRadiusResult, error) {
	store := s.tenantStore(ctx)
	if store == nil {
		return nil, errGraphRiskUnavailable
	}
	result, err := store.BlastRadius(ctx, principalID, maxDepth)
	return result, graphRiskErr(err)
}

func (s serverGraphRiskService) CascadingBlastRadius(ctx context.Context, principalID string, maxDepth int) (*risk.CascadingBlastRadiusResult, error) {
	store := s.tenantStore(ctx)
	if store == nil {
		return nil, errGraphRiskUnavailable
	}
	result, err := store.CascadingBlastRadius(ctx, principalID, maxDepth)
	return result, graphRiskErr(err)
}

func (s serverGraphRiskService) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*risk.ReverseAccessResult, error) {
	store := s.tenantStore(ctx)
	if store == nil {
		return nil, errGraphRiskUnavailable
	}
	result, err := store.ReverseAccess(ctx, resourceID, maxDepth)
	return result, graphRiskErr(err)
}

func (s serverGraphRiskService) Rebuild(ctx context.Context) (*graphRebuildResponse, error) {
	if s.deps == nil || s.deps.SecurityGraphBuilder == nil {
		return nil, errGraphRiskUnavailable
	}
	if err := s.deps.RebuildSecurityGraph(ctx); err != nil {
		return nil, err
	}
	g := s.deps.CurrentSecurityGraph()
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	meta := g.Metadata()
	return &graphRebuildResponse{
		Success:       true,
		BuiltAt:       meta.BuiltAt,
		NodeCount:     meta.NodeCount,
		EdgeCount:     meta.EdgeCount,
		BuildDuration: meta.BuildDuration.String(),
	}, nil
}

func (s serverGraphRiskService) RiskReport(ctx context.Context) (*risk.SecurityReport, error) {
	if s.server == nil {
		g := s.tenantGraph(ctx)
		if g == nil {
			return nil, errGraphRiskUnavailable
		}
		return risk.NewRiskEngine(g).Analyze(), nil
	}
	engine := s.server.currentTenantRiskEngine(ctx)
	if engine == nil {
		return nil, errGraphRiskUnavailable
	}
	report := engine.Analyze()
	if !requestUsesTenantScope(ctx) {
		s.server.persistRiskEngineState(ctx, engine)
	}
	return report, nil
}

func (s serverGraphRiskService) ToxicCombinations(ctx context.Context) ([]*risk.ToxicCombination, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	return risk.NewToxicCombinationEngine().Analyze(g), nil
}

func (s serverGraphRiskService) AttackPaths(ctx context.Context, maxDepth int) (*risk.SimulationResult, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	return risk.NewAttackPathSimulator(g).Simulate(maxDepth), nil
}

func (s serverGraphRiskService) SimulateAttackPathFix(ctx context.Context, nodeID string) (*risk.FixSimulation, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	sim := risk.NewAttackPathSimulator(g)
	result := sim.Simulate(6)
	return sim.SimulateFix(result, nodeID), nil
}

func (s serverGraphRiskService) Chokepoints(ctx context.Context) ([]*risk.Chokepoint, error) {
	result, err := s.AttackPaths(ctx, 6)
	if err != nil {
		return nil, err
	}
	return result.Chokepoints, nil
}

func (s serverGraphRiskService) DetectPrivilegeEscalation(ctx context.Context, principalID string) ([]*graph.PrivilegeEscalationRisk, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	return graph.DetectPrivilegeEscalationRisks(g, principalID), nil
}

func (s serverGraphRiskService) AnalyzePeerGroups(ctx context.Context, minSimilarity float64, minGroupSize int) (*graph.PeerGroupAnalysis, []*graph.OutlierNode, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, nil, errGraphRiskUnavailable
	}
	return graph.AnalyzePeerGroups(g, minSimilarity, minGroupSize), graph.FindPrivilegeCreep(g, 1.5), nil
}

func (s serverGraphRiskService) EffectivePermissions(ctx context.Context, principalID string, evalCtx *graph.PermissionEvaluationContext) (*graph.EffectivePermissions, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	calc := graph.NewEffectivePermissionsCalculator(g)
	if evalCtx != nil {
		return calc.CalculateWithContext(principalID, evalCtx), nil
	}
	return calc.Calculate(principalID), nil
}

func (s serverGraphRiskService) ComparePermissions(ctx context.Context, principal1, principal2 string) (*graph.AccessComparison, error) {
	g := s.tenantGraph(ctx)
	if g == nil {
		return nil, errGraphRiskUnavailable
	}
	return graph.CompareAccess(g, principal1, principal2), nil
}

func (s serverGraphRiskService) tenantGraph(ctx context.Context) *graph.Graph {
	if s.deps == nil {
		return nil
	}
	return s.deps.CurrentSecurityGraphForTenant(currentTenantScopeID(ctx))
}

func (s serverGraphRiskService) tenantStore(ctx context.Context) graph.GraphStore {
	if s.deps == nil {
		return nil
	}
	return s.deps.CurrentSecurityGraphStoreForTenant(currentTenantScopeID(ctx))
}

func graphRiskErr(err error) error {
	if errors.Is(err, graph.ErrStoreUnavailable) {
		return errGraphRiskUnavailable
	}
	return err
}

var _ graphRiskService = serverGraphRiskService{}
