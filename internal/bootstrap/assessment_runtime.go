package bootstrap

import (
	"github.com/writer/cerebro/internal/complianceassessment"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) newAssessmentService(jobs *platformjobs.Service) *complianceassessment.Service {
	if a == nil || jobs == nil || a.deps.AppendLog == nil {
		return nil
	}
	store := assessmentStore(a.deps.StateStore)
	replayer := eventReplayPager(a.deps.AppendLog)
	if store == nil || replayer == nil {
		return nil
	}
	return complianceassessment.NewAssessmentService(store, a.deps.AppendLog, jobs, assessmentCollector(a.deps.StateStore, store)).
		WithEventReplayPager(replayer)
}

func assessmentStore(store ports.StateStore) complianceassessment.Store {
	value, ok := store.(complianceassessment.Store)
	if !ok || isNilInterface(value) {
		return nil
	}
	return value
}

func assessmentCollector(store ports.StateStore, plans complianceassessment.AssessmentPlanReader) complianceassessment.Collector {
	runtimes, runtimesOK := store.(complianceassessment.SourceRuntimeLister)
	evaluations, evaluationsOK := store.(complianceassessment.FindingEvaluationRunLister)
	if !runtimesOK || !evaluationsOK || isNilInterface(runtimes) || isNilInterface(evaluations) || isNilInterface(plans) {
		return nil
	}
	return complianceassessment.NewFindingEvaluationCollector(plans, runtimes, evaluations)
}

func eventReplayPager(appendLog ports.AppendLog) ports.EventReplayPager {
	value, ok := appendLog.(ports.EventReplayPager)
	if !ok || isNilInterface(value) {
		return nil
	}
	return value
}
