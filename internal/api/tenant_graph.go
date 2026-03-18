package api

import (
	"context"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) tenantScopedGraph(ctx context.Context, g *graph.Graph) *graph.Graph {
	if s == nil || g == nil {
		return nil
	}
	tenantID := currentTenantScopeID(ctx)
	return g.SubgraphForTenant(tenantID)
}

func currentTenantScopeID(ctx context.Context) string {
	return strings.TrimSpace(GetTenantID(ctx))
}

func requestUsesTenantScope(ctx context.Context) bool {
	return currentTenantScopeID(ctx) != ""
}

func (s *Server) currentTenantSecurityGraph(ctx context.Context) *graph.Graph {
	if s == nil || s.app == nil {
		return nil
	}
	return s.tenantScopedGraph(ctx, s.app.CurrentSecurityGraph())
}

func (s *Server) currentTenantRiskEngine(ctx context.Context) *graph.RiskEngine {
	if s == nil || s.app == nil {
		return nil
	}
	if !requestUsesTenantScope(ctx) {
		return s.graphRiskEngine()
	}
	g := s.currentTenantSecurityGraph(ctx)
	if g == nil {
		return nil
	}
	engine := graph.NewRiskEngine(g)
	if s.app.Config != nil {
		engine.SetCrossTenantPrivacyConfig(graph.CrossTenantPrivacyConfig{
			MinTenantCount:    s.app.Config.GraphCrossTenantMinTenants,
			MinPatternSupport: s.app.Config.GraphCrossTenantMinSupport,
		})
	}
	return engine
}
