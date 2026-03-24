package forensics

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/workloadscan"
)

func TestSQLiteStoreCaptureAndEvidenceRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "forensics.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	retainUntil := now.Add(90 * 24 * time.Hour)
	capture := &CaptureRecord{
		ID:            "forensic_capture:1",
		IncidentID:    "incident:1",
		WorkloadID:    "workload:aws:i-123",
		Status:        CaptureStatusCaptured,
		RequestedBy:   "analyst:alice",
		Reason:        "Critical finding detected",
		RetentionDays: 90,
		SubmittedAt:   now,
		RetainUntil:   &retainUntil,
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			Region:     "us-east-1",
			InstanceID: "i-123",
		},
		Snapshots: []workloadscan.SnapshotArtifact{{
			ID:        "snap-123",
			VolumeID:  "vol-1",
			Scope:     workloadscan.SnapshotScopeSource,
			CreatedAt: now,
		}},
		ChainOfCustody: []CustodyEvent{{
			Step:       "requested",
			Actor:      "analyst:alice",
			RecordedAt: now,
		}},
	}
	if err := store.SaveCapture(t.Context(), capture); err != nil {
		t.Fatalf("SaveCapture() error = %v", err)
	}

	loadedCapture, err := store.LoadCapture(t.Context(), capture.ID)
	if err != nil {
		t.Fatalf("LoadCapture() error = %v", err)
	}
	if loadedCapture == nil || loadedCapture.ID != capture.ID {
		t.Fatalf("LoadCapture() = %#v, want capture id %q", loadedCapture, capture.ID)
	}

	evidence := &RemediationEvidenceRecord{
		ID:                     "remediation_evidence:1",
		IncidentID:             "incident:1",
		WorkloadID:             "workload:aws:i-123",
		BeforeCaptureID:        capture.ID,
		RemediationExecutionID: "exec-1",
		ActionSummary:          "Rotate credentials and redeploy",
		Actor:                  "operator:bob",
		Status:                 EvidenceStatusRecorded,
		CreatedAt:              now.Add(5 * time.Minute),
	}
	if err := store.SaveEvidence(t.Context(), evidence); err != nil {
		t.Fatalf("SaveEvidence() error = %v", err)
	}

	loadedEvidence, err := store.LoadEvidence(t.Context(), evidence.ID)
	if err != nil {
		t.Fatalf("LoadEvidence() error = %v", err)
	}
	if loadedEvidence == nil || loadedEvidence.ID != evidence.ID {
		t.Fatalf("LoadEvidence() = %#v, want evidence id %q", loadedEvidence, evidence.ID)
	}

	captures, err := store.ListCaptures(t.Context(), CaptureListOptions{IncidentID: "incident:1", Limit: 10})
	if err != nil {
		t.Fatalf("ListCaptures() error = %v", err)
	}
	if len(captures) != 1 || captures[0].ID != capture.ID {
		t.Fatalf("ListCaptures() = %#v, want capture %q", captures, capture.ID)
	}

	evidenceRecords, err := store.ListEvidence(t.Context(), EvidenceListOptions{WorkloadID: "workload:aws:i-123", Limit: 10})
	if err != nil {
		t.Fatalf("ListEvidence() error = %v", err)
	}
	if len(evidenceRecords) != 1 || evidenceRecords[0].ID != evidence.ID {
		t.Fatalf("ListEvidence() = %#v, want evidence %q", evidenceRecords, evidence.ID)
	}
}
