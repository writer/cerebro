package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/forensics"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
)

func TestMaterializePersistedForensicsAddsEvidenceNodes(t *testing.T) {
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
		Status:      forensics.CaptureStatusCaptured,
		SubmittedAt: now,
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-123",
		},
		Snapshots: []workloadscan.SnapshotArtifact{{
			ID:        "snap-1",
			VolumeID:  "vol-1",
			Scope:     workloadscan.SnapshotScopeSource,
			CreatedAt: now,
		}},
	}); err != nil {
		t.Fatalf("SaveCapture() error = %v", err)
	}

	application := &App{
		Config:         &Config{ExecutionStoreFile: filepath.Join(t.TempDir(), "executions.db")},
		ExecutionStore: store,
	}
	g := graph.New()
	result, err := application.materializePersistedForensics(t.Context(), g)
	if err != nil {
		t.Fatalf("materializePersistedForensics() error = %v", err)
	}
	if result.CapturesMaterialized != 1 {
		t.Fatalf("CapturesMaterialized = %d, want 1", result.CapturesMaterialized)
	}
	if node, ok := g.GetNode("evidence:forensic_capture:forensic_capture:1"); !ok || node == nil {
		t.Fatalf("expected forensic capture evidence node, got %#v", node)
	}
}
