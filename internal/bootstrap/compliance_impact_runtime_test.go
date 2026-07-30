package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/compliancemonitor"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
)

func TestComplianceImpactServiceComposition(t *testing.T) {
	t.Parallel()
	app := &App{deps: Dependencies{
		StateStore: &monitorStateStub{}, GraphStore: &impactGraphStub{}, AppendLog: bootstrapAppendOnlyLog{},
	}}
	monitors, projector, scheduler := app.newComplianceImpactServices(nil, nil)
	if monitors == nil || projector == nil || scheduler == nil {
		t.Fatalf("composed monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}

	app.deps.GraphStore = nil
	monitors, projector, scheduler = app.newComplianceImpactServices(nil, nil)
	if monitors == nil || projector != nil || scheduler != nil {
		t.Fatalf("without graph monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}

	app.deps.StateStore = nonEvidenceStateStub{}
	app.deps.GraphStore = &impactGraphStub{}
	monitors, projector, scheduler = app.newComplianceImpactServices(nil, nil)
	if monitors != nil || projector == nil || scheduler != nil {
		t.Fatalf("without monitor store monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}
}

func TestComplianceImpactUsesConfiguredReadAuthority(t *testing.T) {
	t.Parallel()
	app := &App{deps: Dependencies{
		StateStore:   &monitorStateStub{},
		GraphStore:   &projectionOnlyImpactGraphStub{},
		GraphQueries: &queryOnlyImpactGraphStub{},
		AppendLog:    bootstrapAppendOnlyLog{},
	}}

	monitors, projector, scheduler := app.newComplianceImpactServices(nil, nil)
	if monitors == nil || projector == nil || scheduler == nil {
		t.Fatalf("configured authority composition monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}
}

func TestScheduledAssessmentRequesterCreatesCanonicalRun(t *testing.T) {
	t.Parallel()
	store := newAssessmentHTTPStore()
	plan := complianceassessment.AssessmentPlanRevision{
		ID: "plan-1", RevisionID: "plan-revision-1", TenantID: "tenant-1", Status: complianceassessment.PlanPublished,
		Scope: complianceassessment.PlanScope{ProgramID: "program-1", ScopeRevisionID: "scope-revision-1"},
	}
	store.plans[assessmentHTTPKey(plan.TenantID, plan.RevisionID)] = plan
	jobs := platformjobs.New(store.a2ATestJobStore)
	assessments := complianceassessment.NewAssessmentService(store, &assessmentHTTPLog{}, jobs, nil)
	jobs.WithRunner(complianceassessment.JobKindComplianceAssessment, assessments.Runner())
	requester := scheduledAssessmentRequester{service: assessments}
	periodEnd := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	result, err := requester.RequestScheduledAssessment(context.Background(), compliancemonitor.ScheduledAssessmentRequest{
		TenantID: "tenant-1", PlanRevisionID: plan.RevisionID,
		PeriodStart: periodEnd.Add(-time.Hour), PeriodEnd: periodEnd,
		IdempotencyKey: "monitor-occurrence-1", RequestedBy: "compliance_monitor:monitor-1",
		MonitorRun: ports.ComplianceMonitorRun{TenantID: "tenant-1", MonitorID: "monitor-1", PlanRevisionID: plan.RevisionID, OccurrenceKey: "monitor-occurrence-1", LeaseOwner: "lease-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.GetRun(context.Background(), "tenant-1", result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.JobID != result.JobID || run.MonitorRun == nil || run.MonitorRun.OccurrenceKey != "monitor-occurrence-1" {
		t.Fatalf("scheduled run = %#v result = %#v", run, result)
	}
	job, err := jobs.Get(context.Background(), result.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Payload["run_id"] != run.ID || job.Payload["monitor_id"] != "monitor-1" || job.SubjectType != "assessment_run" {
		t.Fatalf("assessment job = %#v", job)
	}
}

type monitorStateStub struct {
	ports.ComplianceMonitorStore
}

func (*monitorStateStub) Ping(context.Context) error { return nil }

type impactGraphStub struct {
	ports.ProjectionGraphStore
	ports.GraphQueryStore
}

func (*impactGraphStub) Ping(context.Context) error { return nil }

type projectionOnlyImpactGraphStub struct {
	ports.ProjectionGraphStore
}

func (*projectionOnlyImpactGraphStub) Ping(context.Context) error { return nil }

type queryOnlyImpactGraphStub struct {
	ports.GraphQueryStore
}

func (*queryOnlyImpactGraphStub) Ping(context.Context) error { return nil }
