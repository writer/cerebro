package bootstrap

import (
	"github.com/writer/cerebro/internal/complianceimpact"
	"github.com/writer/cerebro/internal/compliancemonitor"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) newComplianceImpactServices(jobs *platformjobs.Service) (*compliancemonitor.Service, *complianceimpact.GraphProjector, *complianceimpact.Scheduler) {
	if a == nil {
		return nil, nil, nil
	}
	var monitorService *compliancemonitor.Service
	if monitorStore, ok := a.deps.StateStore.(ports.ComplianceMonitorStore); ok && !isNilInterface(monitorStore) && a.deps.AppendLog != nil {
		monitorService, _ = compliancemonitor.New(monitorStore, a.deps.AppendLog)
		monitorService.WithJobs(jobs)
	}

	projectionStore, projectionOK := a.deps.GraphStore.(ports.ProjectionGraphStore)
	queryStore, queryOK := a.deps.GraphStore.(ports.GraphQueryStore)
	if !projectionOK || !queryOK || isNilInterface(projectionStore) || isNilInterface(queryStore) {
		return monitorService, nil, nil
	}
	projector, err := complianceimpact.NewGraphProjector(projectionStore)
	if err != nil {
		return monitorService, nil, nil
	}
	if monitorService == nil {
		return nil, projector, nil
	}
	graph, err := complianceimpact.NewProjectedGraph(queryStore)
	if err != nil {
		return monitorService, projector, nil
	}
	analyzer, err := complianceimpact.NewAnalyzer(graph, complianceimpact.DefaultLimits())
	if err != nil {
		return monitorService, projector, nil
	}
	scheduler, err := complianceimpact.NewScheduler(analyzer, monitorService)
	if err != nil {
		return monitorService, projector, nil
	}
	return monitorService, projector, scheduler
}
