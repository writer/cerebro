package graph

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAttackSequencePropertiesUseCompactLiveStorage(t *testing.T) {
	sequenceStart := time.Date(2026, 3, 17, 18, 0, 0, 0, time.UTC)
	sequenceEnd := sequenceStart.Add(2 * time.Minute)
	g := New()
	g.AddNode(&Node{
		ID:   "attack_sequence:runtime:checkout",
		Kind: NodeKindAttackSequence,
		Name: "Attack sequence checkout",
		Properties: map[string]any{
			"sequence_type":           "runtime_observation_window",
			"workload_ref":            "deployment:prod/checkout",
			"detail":                  "correlated runtime observations",
			"severity":                "high",
			"observation_count":       3,
			"sequence_start":          sequenceStart.Format(time.RFC3339),
			"sequence_end":            sequenceEnd.Format(time.RFC3339),
			"window_seconds":          int64(120),
			"observation_types":       []string{"process_exec", "network_flow"},
			"ordered_observation_ids": []string{"observation:1", "observation:2"},
			"mitre_attack":            []string{"T1046"},
			"source_system":           "runtime_sequences",
			"source_event_id":         "attack_sequence:runtime:checkout",
			"observed_at":             sequenceEnd.Format(time.RFC3339),
			"valid_from":              sequenceStart.Format(time.RFC3339),
			"valid_to":                sequenceEnd.Format(time.RFC3339),
			"recorded_at":             sequenceEnd.Add(5 * time.Second).Format(time.RFC3339),
			"transaction_from":        sequenceEnd.Add(5 * time.Second).Format(time.RFC3339),
			"confidence":              1.0,
			"metadata_only":           "kept",
		},
	})

	node, ok := g.GetNode("attack_sequence:runtime:checkout")
	if !ok {
		t.Fatal("expected attack_sequence node")
	}
	if node.propertyColumns == nil {
		t.Fatal("expected attack sequence node to be backed by graph property columns")
	}
	if node.attackSequenceProps != nil {
		t.Fatalf("expected live attack sequence node to avoid per-node typed struct, got %+v", node.attackSequenceProps)
	}
	if _, ok := node.Properties["sequence_type"]; ok {
		t.Fatalf("expected compact live properties without sequence_type, got %#v", node.Properties)
	}
	if got := node.Properties["metadata_only"]; got != "kept" {
		t.Fatalf("metadata_only = %#v, want kept", got)
	}
	if got, ok := node.PropertyValue("sequence_type"); !ok || got != "runtime_observation_window" {
		t.Fatalf("PropertyValue(sequence_type) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("window_seconds"); !ok || got != int64(120) {
		t.Fatalf("PropertyValue(window_seconds) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("observation_types"); !ok || len(got.([]string)) != 2 {
		t.Fatalf("PropertyValue(observation_types) = %#v, %v", got, ok)
	}
	props, ok := node.AttackSequenceProperties()
	if !ok {
		t.Fatal("expected typed attack sequence properties")
	}
	if props.WorkloadRef != "deployment:prod/checkout" {
		t.Fatalf("WorkloadRef = %q, want deployment:prod/checkout", props.WorkloadRef)
	}
	if props.ObservationCount != 3 {
		t.Fatalf("ObservationCount = %d, want 3", props.ObservationCount)
	}
	if !props.SequenceStart.Equal(sequenceStart) || !props.SequenceEnd.Equal(sequenceEnd) {
		t.Fatalf("unexpected sequence bounds: %+v", props)
	}
	propertyMap := node.PropertyMap()
	if got := propertyMap["sequence_type"]; got != "runtime_observation_window" {
		t.Fatalf("PropertyMap(sequence_type) = %#v, want runtime_observation_window", got)
	}
	if got := propertyMap["workload_ref"]; got != "deployment:prod/checkout" {
		t.Fatalf("PropertyMap(workload_ref) = %#v, want deployment:prod/checkout", got)
	}
	if got := propertyMap["metadata_only"]; got != "kept" {
		t.Fatalf("PropertyMap(metadata_only) = %#v, want kept", got)
	}
}

func TestSetNodePropertyRefreshesAttackSequenceProperties(t *testing.T) {
	sequenceStart := time.Date(2026, 3, 17, 19, 0, 0, 0, time.UTC)
	sequenceEnd := sequenceStart.Add(90 * time.Second)
	g := New()
	g.AddNode(&Node{
		ID:   "attack_sequence:runtime:payments",
		Kind: NodeKindAttackSequence,
		Name: "Attack sequence payments",
		Properties: map[string]any{
			"sequence_type":           "runtime_observation_window",
			"workload_ref":            "deployment:prod/payments",
			"severity":                "medium",
			"observation_count":       2,
			"sequence_start":          sequenceStart.Format(time.RFC3339),
			"sequence_end":            sequenceEnd.Format(time.RFC3339),
			"ordered_observation_ids": []string{"observation:1"},
			"observed_at":             sequenceEnd.Format(time.RFC3339),
			"valid_from":              sequenceStart.Format(time.RFC3339),
			"recorded_at":             sequenceEnd.Format(time.RFC3339),
			"transaction_from":        sequenceEnd.Format(time.RFC3339),
		},
	})

	if !g.SetNodeProperty("attack_sequence:runtime:payments", "severity", "critical") {
		t.Fatal("expected SetNodeProperty(severity) to succeed")
	}
	if !g.SetNodeProperty("attack_sequence:runtime:payments", "observation_count", 4) {
		t.Fatal("expected SetNodeProperty(observation_count) to succeed")
	}
	node, ok := g.GetNode("attack_sequence:runtime:payments")
	if !ok {
		t.Fatal("expected attack_sequence node after observation_count change")
	}
	if got := node.PreviousProperties["observation_count"]; got != 2 {
		t.Fatalf("PreviousProperties[observation_count] = %#v, want 2", got)
	}
	if !g.SetNodeProperty("attack_sequence:runtime:payments", "ordered_observation_ids", []string{"observation:1", "observation:2"}) {
		t.Fatal("expected SetNodeProperty(ordered_observation_ids) to succeed")
	}

	node, ok = g.GetNode("attack_sequence:runtime:payments")
	if !ok {
		t.Fatal("expected attack_sequence node")
	}
	if node.propertyColumns == nil {
		t.Fatal("expected attack sequence node to remain column-backed")
	}
	if _, ok := node.Properties["severity"]; ok {
		t.Fatalf("expected compact live map without severity, got %#v", node.Properties)
	}
	props, ok := node.AttackSequenceProperties()
	if !ok {
		t.Fatal("expected typed attack sequence properties")
	}
	if props.Severity != "critical" || props.ObservationCount != 4 {
		t.Fatalf("unexpected typed properties: %+v", props)
	}
	if len(props.OrderedObservationIDs) != 2 {
		t.Fatalf("OrderedObservationIDs = %#v, want 2 entries", props.OrderedObservationIDs)
	}
}

func TestSetNodePropertyRejectsInvalidAttackSequenceTemporalValue(t *testing.T) {
	sequenceStart := time.Date(2026, 3, 17, 20, 0, 0, 0, time.UTC)
	sequenceEnd := sequenceStart.Add(time.Minute)
	g := New()
	g.AddNode(&Node{
		ID:   "attack_sequence:runtime:invalid-time",
		Kind: NodeKindAttackSequence,
		Name: "Attack sequence invalid",
		Properties: map[string]any{
			"sequence_type":    "runtime_observation_window",
			"workload_ref":     "deployment:prod/api",
			"sequence_start":   sequenceStart.Format(time.RFC3339),
			"sequence_end":     sequenceEnd.Format(time.RFC3339),
			"observed_at":      sequenceEnd.Format(time.RFC3339),
			"valid_from":       sequenceStart.Format(time.RFC3339),
			"recorded_at":      sequenceEnd.Format(time.RFC3339),
			"transaction_from": sequenceEnd.Format(time.RFC3339),
		},
	})

	node, ok := g.GetNode("attack_sequence:runtime:invalid-time")
	if !ok {
		t.Fatal("expected attack_sequence node")
	}
	beforeVersion := node.Version
	beforeSequenceEnd, ok := node.PropertyValue("sequence_end")
	if !ok {
		t.Fatal("expected sequence_end property")
	}

	if g.SetNodeProperty("attack_sequence:runtime:invalid-time", "sequence_end", "not-a-time") {
		t.Fatal("expected SetNodeProperty(sequence_end) to reject invalid timestamp")
	}

	node, ok = g.GetNode("attack_sequence:runtime:invalid-time")
	if !ok {
		t.Fatal("expected attack_sequence node after rejected update")
	}
	if node.Version != beforeVersion {
		t.Fatalf("Version = %d, want unchanged %d", node.Version, beforeVersion)
	}
	if got, ok := node.PropertyValue("sequence_end"); !ok || got != beforeSequenceEnd {
		t.Fatalf("PropertyValue(sequence_end) = %#v, %v; want %#v", got, ok, beforeSequenceEnd)
	}
}

func TestRestoreFromSnapshotHydratesAttackSequenceProperties(t *testing.T) {
	sequenceStart := time.Date(2026, 3, 17, 21, 0, 0, 0, time.UTC)
	sequenceEnd := sequenceStart.Add(3 * time.Minute)
	g := New()
	g.AddNode(&Node{
		ID:   "attack_sequence:runtime:restore",
		Kind: NodeKindAttackSequence,
		Name: "Attack sequence restore",
		Properties: map[string]any{
			"sequence_type":           "runtime_observation_window",
			"workload_ref":            "deployment:prod/restore",
			"observation_count":       5,
			"sequence_start":          sequenceStart.Format(time.RFC3339),
			"sequence_end":            sequenceEnd.Format(time.RFC3339),
			"observation_types":       []string{"process_exec", "dns_query"},
			"ordered_observation_ids": []string{"observation:a", "observation:b"},
			"observed_at":             sequenceEnd.Format(time.RFC3339),
			"valid_from":              sequenceStart.Format(time.RFC3339),
			"valid_to":                sequenceEnd.Format(time.RFC3339),
			"recorded_at":             sequenceEnd.Format(time.RFC3339),
			"transaction_from":        sequenceEnd.Format(time.RFC3339),
			"confidence":              0.95,
		},
	})

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
	node, ok := restored.GetNode("attack_sequence:runtime:restore")
	if !ok {
		t.Fatal("expected restored attack_sequence node")
	}
	props, ok := node.AttackSequenceProperties()
	if !ok {
		t.Fatal("expected typed attack sequence properties after restore")
	}
	if props.WorkloadRef != "deployment:prod/restore" {
		t.Fatalf("WorkloadRef = %q, want deployment:prod/restore", props.WorkloadRef)
	}
	if props.ObservationCount != 5 {
		t.Fatalf("ObservationCount = %d, want 5", props.ObservationCount)
	}
	if len(props.ObservationTypes) != 2 || len(props.OrderedObservationIDs) != 2 {
		t.Fatalf("unexpected restored slices: %+v", props)
	}
	if !props.SequenceStart.Equal(sequenceStart) || !props.SequenceEnd.Equal(sequenceEnd) {
		t.Fatalf("unexpected restored times: %+v", props)
	}
}
