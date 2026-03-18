package api

import (
	"context"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
	risk "github.com/evalops/cerebro/internal/graph/risk"
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
	return s.app.CurrentSecurityGraphForTenant(currentTenantScopeID(ctx))
}

func (s *Server) currentTenantSecurityGraphStore(ctx context.Context) graph.GraphStore {
	if s == nil || s.app == nil {
		return nil
	}
	return s.app.CurrentSecurityGraphStoreForTenant(currentTenantScopeID(ctx))
}

func (s *Server) currentTenantRiskEngine(ctx context.Context) *risk.RiskEngine {
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
	engine := risk.NewRiskEngine(g)
	if s.app.Config != nil {
		engine.SetCrossTenantPrivacyConfig(risk.CrossTenantPrivacyConfig{
			MinTenantCount:    s.app.Config.GraphCrossTenantMinTenants,
			MinPatternSupport: s.app.Config.GraphCrossTenantMinSupport,
		})
	}
	return engine
}
