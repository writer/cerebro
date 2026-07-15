package complianceimpact

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestAssessmentPlanAdapterProcessesExactUpdateLineage(t *testing.T) {
	projector := &processorProjector{}
	scheduler := &processorScheduler{projector: projector}
	processor, err := NewProcessor(projector, scheduler)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAssessmentPlanAdapter(processor)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	previous := compliance.RevisionRef{
		ID: "plan-1", RevisionID: "plan-r1", Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), LastModified: now.Add(-time.Hour),
	}
	scope := compliance.RevisionRef{
		ID: "scope-1", RevisionID: "scope-r1", Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), LastModified: now.Add(-2 * time.Hour),
	}
	implementation := compliance.RevisionRef{
		ID: "implementation-1", RevisionID: "implementation-r1", Version: 1,
		ContentDigest: compliance.ContentDigest("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), LastModified: now.Add(-2 * time.Hour),
	}
	plan := complianceassessment.AssessmentPlanRevision{
		ID: "plan-1", TenantID: "tenant-1", RevisionID: "plan-r2", Version: 2,
		PredecessorRevision: &previous, RevisionModifiedAt: now,
		ContentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Scope:         complianceassessment.PlanScope{ExactScopeRevision: &scope, ExactImplementationRevisions: []compliance.RevisionRef{implementation}},
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindCompliancePlanPublished, TenantID: plan.TenantID,
		AggregateType: "assessment_plan", AggregateID: plan.ID, RevisionID: plan.RevisionID,
		AggregateVersion: 2, Operation: "plan_published", ContentDigest: plan.ContentDigest,
		PayloadJSON: string(payload), ActorID: "actor-1", RecordedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.ProcessAssessmentPlanEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if scheduler.signal.Kind() != complianceintegration.ChangeUpdated || !scheduler.signal.Revision().Canonical().LastModified.Equal(previous.LastModified) {
		t.Fatalf("signal = %#v", scheduler.signal)
	}
	replacement, ok := scheduler.signal.Replacement()
	if !ok || replacement.RevisionID() != plan.RevisionID {
		t.Fatalf("replacement = %#v, %v", replacement, ok)
	}
	if dependencies := projector.fact.Dependencies(); len(dependencies) != 2 {
		t.Fatalf("dependencies = %#v, want exact scope and implementation", dependencies)
	}
}
