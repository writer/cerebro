package bootstrap

import (
	"context"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceimpact"
	"github.com/writer/cerebro/internal/compliancemonitor"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) newComplianceImpactServices(jobs *platformjobs.Service, assessments *complianceassessment.Service) (*compliancemonitor.Service, *complianceimpact.GraphProjector, *complianceimpact.Scheduler) {
	if a == nil {
		return nil, nil, nil
	}
	var monitorService *compliancemonitor.Service
	if monitorStore, ok := a.deps.StateStore.(ports.ComplianceMonitorStore); ok && !isNilInterface(monitorStore) && a.deps.AppendLog != nil {
		monitorService, _ = compliancemonitor.New(monitorStore, a.deps.AppendLog)
		monitorService.WithJobs(jobs)
		if assessments != nil {
			monitorService.WithAssessmentRequester(scheduledAssessmentRequester{service: assessments})
		}
	}

	projectionStore, projectionOK := a.deps.GraphStore.(ports.ProjectionGraphStore)
	queryStore := dependencyGraphQueryStore(a.deps)
	if !projectionOK || isNilInterface(projectionStore) || isNilInterface(queryStore) {
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

type scheduledAssessmentRequester struct {
	service *complianceassessment.Service
}

func (r scheduledAssessmentRequester) RequestScheduledAssessment(ctx context.Context, request compliancemonitor.ScheduledAssessmentRequest) (compliancemonitor.ScheduledAssessment, error) {
	if r.service == nil {
		return compliancemonitor.ScheduledAssessment{}, compliancemonitor.ErrServiceUnavailable
	}
	run, _, err := r.service.RequestRunDeferred(ctx, complianceassessment.RunRequest{
		TenantID: request.TenantID, PlanRevisionID: request.PlanRevisionID,
		PeriodStart: request.PeriodStart, PeriodEnd: request.PeriodEnd,
		IdempotencyKey: request.IdempotencyKey, RequestedBy: request.RequestedBy,
		MonitorRun: &request.MonitorRun,
	})
	if err != nil {
		return compliancemonitor.ScheduledAssessment{}, err
	}
	return compliancemonitor.ScheduledAssessment{TenantID: run.TenantID, RunID: run.ID, JobID: run.JobID}, nil
}

func (r scheduledAssessmentRequester) StartScheduledAssessment(ctx context.Context, assessment compliancemonitor.ScheduledAssessment) error {
	if r.service == nil {
		return compliancemonitor.ErrServiceUnavailable
	}
	return r.service.StartRunJob(ctx, assessment.TenantID, assessment.RunID, assessment.JobID)
}
