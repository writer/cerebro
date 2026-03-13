package api

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
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

type appGraphIntelligenceService struct {
	app *app.App
}

func newAppGraphIntelligenceService(application *app.App) graphIntelligenceService {
	return appGraphIntelligenceService{app: application}
}

func (s appGraphIntelligenceService) CurrentGraph() *graph.Graph {
	if s.app == nil {
		return nil
	}
	return s.app.CurrentSecurityGraph()
}

func (s appGraphIntelligenceService) MapperInitialized() bool {
	return s.app != nil && s.app.TapEventMapper != nil
}

func (s appGraphIntelligenceService) MapperValidationMode() string {
	if s.app == nil || s.app.Config == nil {
		return string(graphingest.MapperValidationEnforce)
	}
	mode := strings.ToLower(strings.TrimSpace(s.app.Config.GraphEventMapperValidationMode))
	if mode == "" {
		return string(graphingest.MapperValidationEnforce)
	}
	return mode
}

func (s appGraphIntelligenceService) MapperDeadLetterPath() string {
	if s.app == nil || s.app.Config == nil {
		return ""
	}
	return strings.TrimSpace(s.app.Config.GraphEventMapperDeadLetterPath)
}

func (s appGraphIntelligenceService) MapperStats() graphingest.MapperStats {
	if s.app == nil || s.app.TapEventMapper == nil {
		return graphingest.MapperStats{}
	}
	return s.app.TapEventMapper.Stats()
}

func (s appGraphIntelligenceService) MapperContractCatalog(now time.Time) (graphingest.ContractCatalog, bool) {
	if s.app == nil || s.app.TapEventMapper == nil {
		return graphingest.ContractCatalog{}, false
	}
	return s.app.TapEventMapper.ContractCatalog(now), true
}
