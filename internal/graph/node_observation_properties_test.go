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

func TestObservationPropertiesUseCompactLiveStorage(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	g.AddNode(&Node{
		ID:   "observation:payments:compact",
		Kind: NodeKindObservation,
		Name: "runtime_signal",
		Properties: map[string]any{
			"observation_type": "runtime_signal",
			"subject_id":       "service:payments",
			"detail":           "compacted",
			"source_system":    "agent",
			"source_event_id":  "evt-compact",
			"confidence":       0.75,
			"observed_at":      observedAt.Format(time.RFC3339),
			"valid_from":       observedAt.Format(time.RFC3339),
			"metadata_only":    "kept",
		},
	})

	node, ok := g.GetNode("observation:payments:compact")
	if !ok {
		t.Fatal("expected compact observation node")
	}
	if _, ok := node.Properties["observation_type"]; ok {
		t.Fatalf("expected compact live properties without observation_type, got %#v", node.Properties)
	}
	if got := node.Properties["metadata_only"]; got != "kept" {
		t.Fatalf("metadata_only = %#v, want kept", got)
	}
	if got, ok := node.PropertyValue("observation_type"); !ok || got != "runtime_signal" {
		t.Fatalf("PropertyValue(observation_type) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("confidence"); !ok || got != 0.75 {
		t.Fatalf("PropertyValue(confidence) = %#v, %v", got, ok)
	}
	props := node.PropertyMap()
	if got := props["observation_type"]; got != "runtime_signal" {
		t.Fatalf("PropertyMap observation_type = %#v, want runtime_signal", got)
	}
	if got := props["metadata_only"]; got != "kept" {
		t.Fatalf("PropertyMap metadata_only = %#v, want kept", got)
	}
}

func TestSetNodePropertyStoresObservationFieldsOutsideLiveMap(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 17, 13, 0, 0, 0, time.UTC)
	g.AddNode(&Node{
		ID:   "observation:payments:updated",
		Kind: NodeKindObservation,
		Name: "runtime_signal",
		Properties: map[string]any{
			"observation_type": "runtime_signal",
			"subject_id":       "service:payments",
			"detail":           "old detail",
			"confidence":       0.4,
			"observed_at":      observedAt.Format(time.RFC3339),
		},
	})

	if !g.SetNodeProperty("observation:payments:updated", "confidence", 0.9) {
		t.Fatal("expected SetNodeProperty(confidence) to succeed")
	}
	node, ok := g.GetNode("observation:payments:updated")
	if !ok {
		t.Fatal("expected updated observation node after confidence change")
	}
	if got := node.PreviousProperties["confidence"]; got != 0.4 {
		t.Fatalf("PreviousProperties[confidence] = %#v, want 0.4", got)
	}
	if !g.SetNodeProperty("observation:payments:updated", "detail", "new detail") {
		t.Fatal("expected SetNodeProperty(detail) to succeed")
	}

	node, ok = g.GetNode("observation:payments:updated")
	if !ok {
		t.Fatal("expected updated observation node")
	}
	if _, ok := node.Properties["confidence"]; ok {
		t.Fatalf("expected live map to omit compact confidence, got %#v", node.Properties)
	}
	if _, ok := node.Properties["detail"]; ok {
		t.Fatalf("expected live map to omit compact detail, got %#v", node.Properties)
	}
	if got := node.PreviousProperties["detail"]; got != "old detail" {
		t.Fatalf("PreviousProperties[detail] = %#v, want old detail", got)
	}
	if got, ok := node.PropertyValue("confidence"); !ok || got != 0.9 {
		t.Fatalf("PropertyValue(confidence) = %#v, %v", got, ok)
	}
	props, ok := node.ObservationProperties()
	if !ok {
		t.Fatal("expected observation properties")
	}
	if props.Detail != "new detail" || props.Confidence != 0.9 {
		t.Fatalf("unexpected typed observation properties: %+v", props)
	}
}

func TestSetNodePropertyRejectsInvalidObservationTemporalValue(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 17, 13, 0, 0, 0, time.UTC)
	g.AddNode(&Node{
		ID:   "observation:payments:invalid-time",
		Kind: NodeKindObservation,
		Name: "runtime_signal",
		Properties: map[string]any{
			"observation_type": "runtime_signal",
			"subject_id":       "service:payments",
			"detail":           "kept detail",
			"observed_at":      observedAt.Format(time.RFC3339),
			"valid_from":       observedAt.Format(time.RFC3339),
			"recorded_at":      observedAt.Format(time.RFC3339),
			"transaction_from": observedAt.Format(time.RFC3339),
		},
	})

	node, ok := g.GetNode("observation:payments:invalid-time")
	if !ok {
		t.Fatal("expected compact observation node")
	}
	beforeVersion := node.Version
	beforeObservedAt, ok := node.PropertyValue("observed_at")
	if !ok {
		t.Fatal("expected observed_at property")
	}
	beforeHistory := g.GetNodePropertyHistory("observation:payments:invalid-time", "observed_at", 0)

	if g.SetNodeProperty("observation:payments:invalid-time", "observed_at", "not-a-timestamp") {
		t.Fatal("expected SetNodeProperty(observed_at) to reject invalid timestamp")
	}

	node, ok = g.GetNode("observation:payments:invalid-time")
	if !ok {
		t.Fatal("expected observation node after rejected update")
	}
	if node.Version != beforeVersion {
		t.Fatalf("node version = %d, want unchanged %d", node.Version, beforeVersion)
	}
	if got, ok := node.PropertyValue("observed_at"); !ok || got != beforeObservedAt {
		t.Fatalf("PropertyValue(observed_at) = %#v, %v; want %#v", got, ok, beforeObservedAt)
	}
	if node.PreviousProperties != nil {
		t.Fatalf("expected previous_properties to stay nil after rejected update, got %#v", node.PreviousProperties)
	}
	if history := g.GetNodePropertyHistory("observation:payments:invalid-time", "observed_at", 0); len(history) != len(beforeHistory) {
		t.Fatalf("expected property history length to stay %d, got %+v", len(beforeHistory), history)
	} else if len(history) > 0 && history[0].Value != beforeHistory[0].Value {
		t.Fatalf("expected property history to stay unchanged, got %+v", history)
	}
}
