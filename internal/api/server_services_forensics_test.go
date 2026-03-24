package api

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/forensics"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/workloadscan"
)

type fakeForensicsProvider struct {
	volumes []workloadscan.SourceVolume
}

func (p fakeForensicsProvider) Kind() workloadscan.ProviderKind { return workloadscan.ProviderAWS }

func (p fakeForensicsProvider) InventoryVolumes(context.Context, workloadscan.VMTarget) ([]workloadscan.SourceVolume, error) {
	return append([]workloadscan.SourceVolume(nil), p.volumes...), nil
}

func (p fakeForensicsProvider) CreateSnapshot(_ context.Context, target workloadscan.VMTarget, volume workloadscan.SourceVolume, _ map[string]string) (*workloadscan.SnapshotArtifact, error) {
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	return &workloadscan.SnapshotArtifact{
		ID:        "snap-" + volume.ID,
		VolumeID:  volume.ID,
		Region:    target.Region,
		Scope:     workloadscan.SnapshotScopeSource,
		CreatedAt: now,
	}, nil
}

func (p fakeForensicsProvider) ShareSnapshot(context.Context, workloadscan.VMTarget, workloadscan.ScannerHost, workloadscan.SnapshotArtifact) (*workloadscan.SnapshotArtifact, error) {
	return nil, nil
}

func (p fakeForensicsProvider) CreateInspectionVolume(context.Context, workloadscan.VMTarget, workloadscan.ScannerHost, workloadscan.SnapshotArtifact) (*workloadscan.InspectionVolume, error) {
	return nil, nil
}

func (p fakeForensicsProvider) AttachInspectionVolume(context.Context, workloadscan.VMTarget, workloadscan.ScannerHost, workloadscan.InspectionVolume, int) (*workloadscan.VolumeAttachment, error) {
	return nil, nil
}

func (p fakeForensicsProvider) DetachInspectionVolume(context.Context, workloadscan.VolumeAttachment) error {
	return nil
}

func (p fakeForensicsProvider) DeleteInspectionVolume(context.Context, workloadscan.InspectionVolume) error {
	return nil
}

func (p fakeForensicsProvider) DeleteSnapshot(context.Context, workloadscan.SnapshotArtifact) error {
	return nil
}

func TestForensicsServiceCreateCapturePersistsAndMaterializes(t *testing.T) {
	store, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	g := graph.New()
	svc := serverForensicsService{
		deps: &serverDependencies{
			ExecutionStore: store,
			graphMutator:   stubGraphMutator{graph: g},
		},
		providerResolver: func(context.Context, workloadscan.VMTarget) (workloadscan.Provider, error) {
			return fakeForensicsProvider{volumes: []workloadscan.SourceVolume{{ID: "vol-1", SizeGiB: 10}}}, nil
		},
	}

	record, err := svc.CreateCapture(t.Context(), forensicsCaptureRequest{
		IncidentID:  "incident:sev1",
		RequestedBy: "analyst:alice",
		Reason:      "Critical incident",
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-123",
		},
	})
	if err != nil {
		t.Fatalf("CreateCapture() error = %v", err)
	}
	if record.Status != forensics.CaptureStatusCaptured {
		t.Fatalf("capture status = %q, want %q", record.Status, forensics.CaptureStatusCaptured)
	}

	forensicsStore := forensics.NewSQLiteStoreWithExecutionStore(store)
	loaded, err := forensicsStore.LoadCapture(t.Context(), record.ID)
	if err != nil {
		t.Fatalf("LoadCapture() error = %v", err)
	}
	if loaded == nil || len(loaded.Snapshots) != 1 {
		t.Fatalf("loaded capture = %#v, want one preserved snapshot", loaded)
	}

	if node, ok := g.GetNode("evidence:forensic_capture:" + record.ID); !ok || node == nil {
		t.Fatalf("expected capture evidence node in graph, got %#v", node)
	}
}

func TestForensicsServiceExportEvidencePackageLoadsCapture(t *testing.T) {
	store, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	forensicsStore := forensics.NewSQLiteStoreWithExecutionStore(store)
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	if err := forensicsStore.SaveCapture(t.Context(), &forensics.CaptureRecord{
		ID:          "forensic_capture:1",
		IncidentID:  "incident:sev1",
		WorkloadID:  "workload:aws:i-123",
		Status:      forensics.CaptureStatusCaptured,
		SubmittedAt: now,
	}); err != nil {
		t.Fatalf("SaveCapture() error = %v", err)
	}
	if err := forensicsStore.SaveEvidence(t.Context(), &forensics.RemediationEvidenceRecord{
		ID:              "remediation_evidence:1",
		IncidentID:      "incident:sev1",
		WorkloadID:      "workload:aws:i-123",
		BeforeCaptureID: "forensic_capture:1",
		ActionSummary:   "Contain host",
		Status:          forensics.EvidenceStatusRecorded,
		CreatedAt:       now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveEvidence() error = %v", err)
	}

	svc := serverForensicsService{
		deps: &serverDependencies{
			ExecutionStore: store,
		},
	}

	pkg, err := svc.ExportEvidencePackage(t.Context(), "remediation_evidence:1")
	if err != nil {
		t.Fatalf("ExportEvidencePackage() error = %v", err)
	}
	if len(pkg.Captures) != 1 || pkg.Captures[0].ID != "forensic_capture:1" {
		t.Fatalf("expected one capture in package, got %#v", pkg.Captures)
	}
}

func TestForensicsServiceCreateCaptureRecordsFailureWhenNoVolumesExist(t *testing.T) {
	store, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	g := graph.New()
	svc := serverForensicsService{
		deps: &serverDependencies{
			ExecutionStore: store,
			graphMutator:   stubGraphMutator{graph: g},
		},
		providerResolver: func(context.Context, workloadscan.VMTarget) (workloadscan.Provider, error) {
			return fakeForensicsProvider{}, nil
		},
	}

	_, err = svc.CreateCapture(t.Context(), forensicsCaptureRequest{
		ID:          "forensic_capture:empty",
		IncidentID:  "incident:sev1",
		RequestedBy: "analyst:alice",
		Reason:      "Preserve host state",
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-empty",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "no source volumes discovered for target") {
		t.Fatalf("CreateCapture() error = %v, want no source volumes error", err)
	}

	forensicsStore := forensics.NewSQLiteStoreWithExecutionStore(store)
	record, err := forensicsStore.LoadCapture(t.Context(), "forensic_capture:empty")
	if err != nil {
		t.Fatalf("LoadCapture() error = %v", err)
	}
	if record == nil {
		t.Fatal("expected failed capture record to be persisted")
	}
	if record.Status != forensics.CaptureStatusFailed {
		t.Fatalf("capture status = %q, want %q", record.Status, forensics.CaptureStatusFailed)
	}
	if record.CompletedAt == nil || record.CompletedAt.IsZero() {
		t.Fatalf("expected CompletedAt to be recorded, got %#v", record.CompletedAt)
	}
	if !hasCustodyStep(record.ChainOfCustody, "inventory_empty") {
		t.Fatalf("expected inventory_empty custody step, got %#v", record.ChainOfCustody)
	}

	if node, ok := g.GetNode("evidence:forensic_capture:forensic_capture:empty"); !ok || node == nil {
		t.Fatalf("expected failed capture to materialize evidence node, got %#v", node)
	}
}

func TestForensicsServiceRecordRemediationEvidenceHydratesCaptureAndExecution(t *testing.T) {
	store, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	forensicsStore := forensics.NewSQLiteStoreWithExecutionStore(store)
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	capture := &forensics.CaptureRecord{
		ID:          "forensic_capture:before",
		IncidentID:  "incident:sev1",
		WorkloadID:  "workload:aws:i-123",
		Status:      forensics.CaptureStatusCaptured,
		SubmittedAt: now,
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-123",
		},
	}
	if err := forensicsStore.SaveCapture(t.Context(), capture); err != nil {
		t.Fatalf("SaveCapture() error = %v", err)
	}

	engine := remediation.NewEngine(slog.New(slog.NewTextHandler(io.Discard, nil)))
	executions, err := engine.Evaluate(t.Context(), remediation.Event{
		Type:      remediation.TriggerFindingCreated,
		FindingID: "finding:critical",
		Severity:  "critical",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected remediation engine to produce at least one execution")
	}

	g := graph.New()
	svc := serverForensicsService{
		deps: &serverDependencies{
			ExecutionStore: store,
			Remediation:    engine,
			graphMutator:   stubGraphMutator{graph: g},
		},
	}

	record, err := svc.RecordRemediationEvidence(t.Context(), forensicsRemediationEvidenceRequest{
		ID:                     "remediation_evidence:hydrated",
		BeforeCaptureID:        capture.ID,
		RemediationExecutionID: executions[0].ID,
		Actor:                  "operator:bob",
		Notes:                  "Applied containment",
	})
	if err != nil {
		t.Fatalf("RecordRemediationEvidence() error = %v", err)
	}
	if record.IncidentID != capture.IncidentID {
		t.Fatalf("IncidentID = %q, want %q", record.IncidentID, capture.IncidentID)
	}
	if record.WorkloadID != capture.WorkloadID {
		t.Fatalf("WorkloadID = %q, want %q", record.WorkloadID, capture.WorkloadID)
	}
	if record.ActionSummary != executions[0].RuleName {
		t.Fatalf("ActionSummary = %q, want %q", record.ActionSummary, executions[0].RuleName)
	}
	if record.Status != forensics.EvidenceStatusRecorded {
		t.Fatalf("Status = %q, want %q", record.Status, forensics.EvidenceStatusRecorded)
	}

	loaded, err := forensicsStore.LoadEvidence(t.Context(), record.ID)
	if err != nil {
		t.Fatalf("LoadEvidence() error = %v", err)
	}
	if loaded == nil || loaded.ActionSummary != executions[0].RuleName {
		t.Fatalf("expected hydrated evidence to persist summary, got %#v", loaded)
	}

	pkg, err := svc.ExportEvidencePackage(t.Context(), record.ID)
	if err != nil {
		t.Fatalf("ExportEvidencePackage() error = %v", err)
	}
	if pkg.RemediationExecution == nil || pkg.RemediationExecution.ID != executions[0].ID {
		t.Fatalf("expected remediation execution summary in evidence package, got %#v", pkg.RemediationExecution)
	}

	if node, ok := g.GetNode("action:forensics:remediation_evidence:hydrated"); !ok || node == nil {
		t.Fatalf("expected remediation action node in graph, got %#v", node)
	}
}

func hasCustodyStep(events []forensics.CustodyEvent, step string) bool {
	for _, event := range events {
		if event.Step == step {
			return true
		}
	}
	return false
}
