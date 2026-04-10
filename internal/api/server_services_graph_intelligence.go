package api

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
)

// graphIntelligenceService narrows the handler dependency surface to the graph
// and mapper primitives consumed by the graph-intelligence routes.
type graphIntelligenceService interface {
	CurrentGraph(ctx context.Context) (*graph.Graph, error)
	CurrentEntityGraph(ctx context.Context, entityID string, validAt, recordedAt time.Time) (*graph.Graph, error)
	MapperInitialized() bool
	MapperValidationMode() string
	MapperDeadLetterPath() string
	MapperStats() graphingest.MapperStats
	MapperContractCatalog(now time.Time) (graphingest.ContractCatalog, bool)
}

type serverGraphIntelligenceService struct {
	deps *serverDependencies
}

type graphViewProvider interface {
	GraphView(context.Context) (*graph.Graph, error)
}

func newGraphIntelligenceService(deps *serverDependencies) graphIntelligenceService {
	return serverGraphIntelligenceService{deps: deps}
}

func (s serverGraphIntelligenceService) CurrentGraph(ctx context.Context) (*graph.Graph, error) {
	if s.deps == nil {
		return nil, graph.ErrStoreUnavailable
	}
	tenantID := currentTenantScopeID(ctx)
	return currentOrStoredGraphView(ctx, s.deps.CurrentSecurityGraphForTenant(tenantID), s.deps.CurrentSecurityGraphStoreForTenant(tenantID))
}

func (s serverGraphIntelligenceService) CurrentEntityGraph(ctx context.Context, entityID string, validAt, recordedAt time.Time) (*graph.Graph, error) {
	if s.deps == nil {
		return nil, graph.ErrStoreUnavailable
	}
	tenantID := currentTenantScopeID(ctx)
	current := s.deps.CurrentSecurityGraphForTenant(tenantID)
	if current != nil {
		return current, nil
	}
	store := s.deps.CurrentSecurityGraphStoreForTenant(tenantID)
	if store == nil {
		return nil, graph.ErrStoreUnavailable
	}
	opts := graph.ExtractSubgraphOptions{MaxDepth: 3}
	if !validAt.IsZero() || !recordedAt.IsZero() {
		if temporalStore, ok := store.(interface {
			ExtractSubgraphBitemporal(context.Context, string, graph.ExtractSubgraphOptions, time.Time, time.Time) (*graph.Graph, error)
		}); ok {
			return temporalStore.ExtractSubgraphBitemporal(ctx, entityID, opts, validAt, recordedAt)
		}
		return snapshotGraphView(ctx, store)
	}
	if provider, ok := store.(graphViewProvider); ok {
		view, err := provider.GraphView(ctx)
		if err != nil {
			return nil, err
		}
		if view != nil {
			return view, nil
		}
	}
	return snapshotGraphView(ctx, store)
}

func (s serverGraphIntelligenceService) MapperInitialized() bool {
	return s.deps != nil && s.deps.TapEventMapper != nil
}

func (s serverGraphIntelligenceService) MapperValidationMode() string {
	if s.deps == nil || s.deps.Config == nil {
		return string(graphingest.MapperValidationEnforce)
	}
	mode := strings.ToLower(strings.TrimSpace(s.deps.Config.GraphEventMapperValidationMode))
	if mode == "" {
		return string(graphingest.MapperValidationEnforce)
	}
	return mode
}

func (s serverGraphIntelligenceService) MapperDeadLetterPath() string {
	if s.deps == nil || s.deps.Config == nil {
		return ""
	}
	return strings.TrimSpace(s.deps.Config.GraphEventMapperDeadLetterPath)
}

func (s serverGraphIntelligenceService) MapperStats() graphingest.MapperStats {
	if s.deps == nil || s.deps.TapEventMapper == nil {
		return graphingest.MapperStats{}
	}
	return s.deps.TapEventMapper.Stats()
}

func (s serverGraphIntelligenceService) MapperContractCatalog(now time.Time) (graphingest.ContractCatalog, bool) {
	if s.deps == nil || s.deps.TapEventMapper == nil {
		return graphingest.ContractCatalog{}, false
	}
	return s.deps.TapEventMapper.ContractCatalog(now), true
}
