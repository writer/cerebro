package api

import (
	"context"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
	risk "github.com/evalops/cerebro/internal/graph/risk"
)

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

func (s *Server) currentTenantSecurityGraphView(ctx context.Context) (*graph.Graph, error) {
	if s == nil || s.app == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return currentOrStoredGraphView(ctx, s.currentTenantSecurityGraph(ctx), s.currentTenantSecurityGraphStore(ctx))
}

func (s *Server) currentTenantSecurityGraphSnapshotView(ctx context.Context) (*graph.Graph, error) {
	if s == nil || s.app == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return snapshotBackedGraphView(ctx, s.currentTenantSecurityGraph(ctx), s.currentTenantSecurityGraphStore(ctx))
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
	g, err := s.currentTenantSecurityGraphView(ctx)
	if err != nil || g == nil {
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
