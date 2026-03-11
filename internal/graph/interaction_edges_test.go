package graph

import (
	"testing"
	"time"
)

func TestUpsertInteractionEdge_CreatesAndAggregates(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 8, 18, 0, 0, 0, time.UTC)

	created := UpsertInteractionEdge(g, InteractionEdge{
		SourcePersonID: "person:bob@example.com",
		TargetPersonID: "alice@example.com",
		Channel:        "slack",
		Type:           "message",
		Timestamp:      now.Add(-2 * time.Hour),
		Duration:       5 * time.Minute,
	})
	if created == nil {
		t.Fatal("expected interaction edge to be created")
	}

	updated := UpsertInteractionEdge(g, InteractionEdge{
		SourcePersonID: "alice@example.com",
		TargetPersonID: "person:bob@example.com",
		Channel:        "gong",
		Type:           "call",
		Timestamp:      now,
		Duration:       30 * time.Minute,
		Weight:         2.5,
	})
	if updated == nil {
		t.Fatal("expected interaction edge to be updated")
	}

	if updated.Source != "person:alice@example.com" || updated.Target != "person:bob@example.com" {
		t.Fatalf("expected canonical pair ordering, got %s -> %s", updated.Source, updated.Target)
	}
	if got := readInt(updated.Properties, "frequency"); got != 2 {
		t.Fatalf("expected frequency=2, got %d", got)
	}
	if got := readInt(updated.Properties, "previous_frequency"); got != 1 {
		t.Fatalf("expected previous_frequency=1, got %d", got)
	}
	if got := readFloat(updated.Properties, "total_duration_seconds"); int(got) != int((35 * time.Minute).Seconds()) {
		t.Fatalf("expected total_duration_seconds=%d, got %.2f", int((35 * time.Minute).Seconds()), got)
	}
	if !containsString(stringSliceFromValue(updated.Properties["interaction_channels"]), "slack") ||
		!containsString(stringSliceFromValue(updated.Properties["interaction_channels"]), "gong") {
		t.Fatalf("expected channels to contain slack and gong, got %+v", updated.Properties["interaction_channels"])
	}
	if !containsString(stringSliceFromValue(updated.Properties["interaction_types"]), "message") ||
		!containsString(stringSliceFromValue(updated.Properties["interaction_types"]), "call") {
		t.Fatalf("expected types to contain message and call, got %+v", updated.Properties["interaction_types"])
	}
	if got := firstTimeFromMap(updated.Properties, "last_seen", "last_interaction"); !got.Equal(now.UTC()) {
		t.Fatalf("expected last_seen=%s, got %s", now.UTC().Format(time.RFC3339), got.Format(time.RFC3339))
	}
	if got := readFloat(updated.Properties, "strength"); got <= 0 {
		t.Fatalf("expected positive strength, got %.4f", got)
	}

	out := g.GetOutEdges("person:alice@example.com")
	if len(out) != 1 {
		t.Fatalf("expected one active interaction edge for alice, got %d", len(out))
	}
}

func TestUpsertInteractionEdge_UsesExistingEdgeAsBaseline(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 8, 19, 0, 0, 0, time.UTC)

	g.AddEdge(&Edge{
		ID:     "person_interaction:person:alice@example.com<->person:bob@example.com",
		Source: "person:alice@example.com",
		Target: "person:bob@example.com",
		Kind:   EdgeKindInteractedWith,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"frequency":                4,
			"weighted_frequency":       4.5,
			"strength":                 1.4,
			"last_seen":                now.Add(-24 * time.Hour),
			"total_duration_seconds":   600.0,
			"interaction_source_types": []string{"gong_calls"},
			"interaction_types":        []string{"call"},
		},
	})

	updated := UpsertInteractionEdge(g, InteractionEdge{
		SourcePersonID: "person:bob@example.com",
		TargetPersonID: "person:alice@example.com",
		Channel:        "slack",
		Type:           "message",
		Timestamp:      now,
		Duration:       2 * time.Minute,
	})
	if updated == nil {
		t.Fatal("expected interaction edge update")
	}

	if got := readInt(updated.Properties, "frequency"); got != 5 {
		t.Fatalf("expected frequency=5, got %d", got)
	}
	if got := readInt(updated.Properties, "previous_frequency"); got != 4 {
		t.Fatalf("expected previous_frequency=4, got %d", got)
	}
	if got := readFloat(updated.Properties, "previous_strength"); got != 1.4 {
		t.Fatalf("expected previous_strength=1.4, got %.3f", got)
	}
	if !containsString(stringSliceFromValue(updated.Properties["interaction_channels"]), "gong_calls") ||
		!containsString(stringSliceFromValue(updated.Properties["interaction_channels"]), "slack") {
		t.Fatalf("expected merged channels, got %+v", updated.Properties["interaction_channels"])
	}
}
