package forensics

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
)

func TestMaterializeIntoGraphAddsCaptureEvidenceAndRemediationAction(t *testing.T) {
	g := graph.New()
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)

	capture := CaptureRecord{
		ID:            "forensic_capture:1",
		IncidentID:    "incident:sev1",
		Status:        CaptureStatusCaptured,
		RequestedBy:   "analyst:alice",
		Reason:        "Preserve workload state",
		RetentionDays: 90,
		SubmittedAt:   now,
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
	}
	evidence := RemediationEvidenceRecord{
		ID:              "remediation_evidence:1",
		IncidentID:      "incident:sev1",
		WorkloadID:      inferredWorkloadNodeID(capture.Target),
		BeforeCaptureID: capture.ID,
		ActionSummary:   "Apply containment rule",
		Actor:           "operator:bob",
		Status:          EvidenceStatusRecorded,
		CreatedAt:       now.Add(10 * time.Minute),
	}

	result := MaterializeIntoGraph(g, []CaptureRecord{capture}, []RemediationEvidenceRecord{evidence}, now)
	if result.CapturesMaterialized != 1 {
		t.Fatalf("CapturesMaterialized = %d, want 1", result.CapturesMaterialized)
	}
	if result.EvidenceNodesUpserted != 1 {
		t.Fatalf("EvidenceNodesUpserted = %d, want 1", result.EvidenceNodesUpserted)
	}
	if result.ActionNodesUpserted != 1 {
		t.Fatalf("ActionNodesUpserted = %d, want 1", result.ActionNodesUpserted)
	}

	if node, ok := g.GetNode(captureEvidenceNodeID(capture.ID)); !ok || node == nil || node.Kind != graph.NodeKindEvidence {
		t.Fatalf("expected forensic evidence node, got %#v", node)
	}
	if node, ok := g.GetNode(remediationActionNodeID(evidence.ID)); !ok || node == nil || node.Kind != graph.NodeKindAction {
		t.Fatalf("expected remediation action node, got %#v", node)
	}
	if node, ok := g.GetNode(inferredWorkloadNodeID(capture.Target)); !ok || node == nil || node.Kind != graph.NodeKindWorkload {
		t.Fatalf("expected inferred workload node, got %#v", node)
	}
	if node, ok := g.GetNode("incident:sev1"); !ok || node == nil || node.Kind != graph.NodeKindIncident {
		t.Fatalf("expected incident node, got %#v", node)
	}
}
