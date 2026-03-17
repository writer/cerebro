package graph

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWriteObservationHydratesObservationProperties(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})

	observedAt := time.Date(2026, 3, 17, 8, 0, 0, 0, time.UTC)
	if _, err := WriteObservation(g, ObservationWriteRequest{
		ID:              "observation:payments:runtime",
		SubjectID:       "service:payments",
		ObservationType: "runtime_signal",
		Summary:         "Error rate increased after deploy",
		SourceSystem:    "agent",
		SourceEventID:   "evt-1",
		ObservedAt:      observedAt,
		ValidFrom:       observedAt,
		RecordedAt:      observedAt.Add(30 * time.Second),
		TransactionFrom: observedAt.Add(30 * time.Second),
		Confidence:      0.91,
		Metadata: map[string]any{
			"severity": "high",
		},
	}); err != nil {
		t.Fatalf("WriteObservation returned error: %v", err)
	}

	node, ok := g.GetNode("observation:payments:runtime")
	if !ok {
		t.Fatal("expected observation node to exist")
	}
	props, ok := node.ObservationProperties()
	if !ok {
		t.Fatal("expected typed observation properties")
	}
	if props.ObservationType != "runtime_signal" {
		t.Fatalf("ObservationType = %q, want runtime_signal", props.ObservationType)
	}
	if props.SubjectID != "service:payments" {
		t.Fatalf("SubjectID = %q, want service:payments", props.SubjectID)
	}
	if props.Detail != "Error rate increased after deploy" {
		t.Fatalf("Detail = %q, want Error rate increased after deploy", props.Detail)
	}
	if props.SourceSystem != "agent" {
		t.Fatalf("SourceSystem = %q, want agent", props.SourceSystem)
	}
	if props.SourceEventID != "evt-1" {
		t.Fatalf("SourceEventID = %q, want evt-1", props.SourceEventID)
	}
	if props.Confidence != 0.91 {
		t.Fatalf("Confidence = %f, want 0.91", props.Confidence)
	}
	if !props.ObservedAt.Equal(observedAt) {
		t.Fatalf("ObservedAt = %s, want %s", props.ObservedAt, observedAt)
	}
}

func TestSetNodePropertyRefreshesObservationProperties(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 17, 9, 0, 0, 0, time.UTC)
	g.AddNode(&Node{
		ID:   "observation:payments:runtime",
		Kind: NodeKindObservation,
		Name: "runtime_signal",
		Properties: map[string]any{
			"observation_type": "runtime_signal",
			"subject_id":       "service:payments",
			"detail":           "old detail",
			"source_system":    "agent",
			"observed_at":      observedAt.Format(time.RFC3339),
		},
	})

	if !g.SetNodeProperty("observation:payments:runtime", "detail", "new detail") {
		t.Fatal("expected SetNodeProperty to succeed")
	}

	node, ok := g.GetNode("observation:payments:runtime")
	if !ok {
		t.Fatal("expected observation node to exist")
	}
	props, ok := node.ObservationProperties()
	if !ok {
		t.Fatal("expected typed observation properties")
	}
	if props.Detail != "new detail" {
		t.Fatalf("Detail = %q, want new detail", props.Detail)
	}
}

func TestRestoreFromSnapshotHydratesObservationProperties(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	observedAt := time.Date(2026, 3, 17, 10, 0, 0, 0, time.UTC)
	if _, err := WriteObservation(g, ObservationWriteRequest{
		ID:              "observation:payments:restored",
		SubjectID:       "service:payments",
		ObservationType: "runtime_signal",
		Summary:         "Restored from snapshot",
		SourceSystem:    "agent",
		ObservedAt:      observedAt,
		ValidFrom:       observedAt,
		RecordedAt:      observedAt,
		TransactionFrom: observedAt,
	}); err != nil {
		t.Fatalf("WriteObservation returned error: %v", err)
	}

	snapshot := CreateSnapshot(g)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal snapshot: %v", err)
	}

	var restoredSnapshot Snapshot
	if err := json.Unmarshal(payload, &restoredSnapshot); err != nil {
		t.Fatalf("Unmarshal snapshot: %v", err)
	}

	restored := RestoreFromSnapshot(&restoredSnapshot)
	node, ok := restored.GetNode("observation:payments:restored")
	if !ok {
		t.Fatal("expected restored observation node to exist")
	}
	props, ok := node.ObservationProperties()
	if !ok {
		t.Fatal("expected typed observation properties after restore")
	}
	if props.SubjectID != "service:payments" {
		t.Fatalf("SubjectID = %q, want service:payments", props.SubjectID)
	}
	if props.Detail != "Restored from snapshot" {
		t.Fatalf("Detail = %q, want Restored from snapshot", props.Detail)
	}
	if !props.ObservedAt.Equal(observedAt) {
		t.Fatalf("ObservedAt = %s, want %s", props.ObservedAt, observedAt)
	}
}
