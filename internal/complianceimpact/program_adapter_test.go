package complianceimpact

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestComplianceProgramAdapterProjectsScopeDependencies(t *testing.T) {
	projector := &processorProjector{}
	processor, err := NewProcessor(projector, &processorScheduler{projector: projector})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewComplianceProgramAdapter(processor)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	scope := grcprogram.ProgramScopeRevisionRecord{
		TenantID: "tenant-1", ProgramID: "program-1",
		Version: compliance.VersionMetadata{
			ID: "scope-1", RevisionID: "scope-r1", Version: 1, LastModified: now,
			ContentDigest: compliance.ContentDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		},
		Specification: grcprogram.ProgramScopeSpecification{FrameworkRevisions: []compliance.RevisionRef{{
			ID: "framework-1", RevisionID: "framework-r1", Version: 1, LastModified: now.Add(-time.Hour),
			ContentDigest: compliance.ContentDigest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		}}},
	}
	payload, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceProgramScopeRecorded, TenantID: scope.TenantID,
		AggregateType: "program", AggregateID: scope.ProgramID, RevisionID: scope.Version.RevisionID,
		AggregateVersion: 1, Operation: "scope_recorded", ContentDigest: string(scope.Version.ContentDigest),
		PayloadJSON: string(payload), RecordedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.ProcessComplianceProgramEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	dependencies := projector.fact.Dependencies()
	if len(dependencies) != 1 || dependencies[0].Relation() != "scope_framework" {
		t.Fatalf("dependencies = %#v", dependencies)
	}
}
