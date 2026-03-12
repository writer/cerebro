package api

import (
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graphingest"
)

// graphIntelligenceService narrows the handler dependency surface to the graph
// and mapper primitives consumed by the graph-intelligence routes.
type graphIntelligenceService interface {
	CurrentGraph() *graph.Graph
	MapperInitialized() bool
	MapperValidationMode() string
	MapperDeadLetterPath() string
	MapperStats() graphingest.MapperStats
	MapperContractCatalog(now time.Time) (graphingest.ContractCatalog, bool)
}

type serverGraphIntelligenceService struct {
	deps *serverDependencies
}

func newGraphIntelligenceService(deps *serverDependencies) graphIntelligenceService {
	return serverGraphIntelligenceService{deps: deps}
}

func (s serverGraphIntelligenceService) CurrentGraph() *graph.Graph {
	if s.deps == nil {
		return nil
	}
	return s.deps.CurrentSecurityGraph()
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
