package graph

import (
	"testing"
	"time"
)

func TestGenericMetadataUsesCompactLiveStorage(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC)
	validTo := observedAt.Add(2 * time.Hour)

	g.AddNode(&Node{
		ID:   "source:github",
		Kind: NodeKindSource,
		Name: "GitHub",
		Properties: map[string]any{
			"source_type":     "scm",
			"source_system":   "github",
			"source_event_id": "evt-compact",
			"confidence":      0.75,
			"observed_at":     observedAt.Format(time.RFC3339),
			"valid_from":      observedAt.Format(time.RFC3339),
			"valid_to":        validTo.Format(time.RFC3339),
			"metadata_only":   "kept",
		},
	})

	node, ok := g.GetNode("source:github")
	if !ok {
		t.Fatal("expected source node")
	}
	if node.propertyColumns == nil {
		t.Fatal("expected source node to be backed by graph property columns")
	}
	if node.metadataProps != nil {
		t.Fatalf("expected live source node to avoid per-node metadata struct, got %+v", node.metadataProps)
	}
	for _, key := range []string{"source_system", "source_event_id", "confidence", "observed_at", "valid_from", "valid_to"} {
		if _, ok := node.Properties[key]; ok {
			t.Fatalf("expected compact live properties without %s, got %#v", key, node.Properties)
		}
	}
	if got := node.Properties["metadata_only"]; got != "kept" {
		t.Fatalf("metadata_only = %#v, want kept", got)
	}

	props, ok := node.MetadataProperties()
	if !ok {
		t.Fatal("expected typed node metadata properties")
	}
	if props.SourceSystem != "github" {
		t.Fatalf("SourceSystem = %q, want github", props.SourceSystem)
	}
	if props.SourceEventID != "evt-compact" {
		t.Fatalf("SourceEventID = %q, want evt-compact", props.SourceEventID)
	}
	if props.Confidence != 0.75 {
		t.Fatalf("Confidence = %f, want 0.75", props.Confidence)
	}
	if !props.ObservedAt.Equal(observedAt) {
		t.Fatalf("ObservedAt = %s, want %s", props.ObservedAt, observedAt)
	}
	if props.ValidTo == nil || !props.ValidTo.Equal(validTo) {
		t.Fatalf("ValidTo = %v, want %v", props.ValidTo, validTo)
	}

	if got, ok := node.PropertyValue("source_system"); !ok || got != "github" {
		t.Fatalf("PropertyValue(source_system) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("observed_at"); !ok || got != observedAt.Format(time.RFC3339) {
		t.Fatalf("PropertyValue(observed_at) = %#v, %v", got, ok)
	}

	propertyMap := node.PropertyMap()
	if got := propertyMap["source_system"]; got != "github" {
		t.Fatalf("PropertyMap(source_system) = %#v, want github", got)
	}
	if got := propertyMap["metadata_only"]; got != "kept" {
		t.Fatalf("PropertyMap(metadata_only) = %#v, want kept", got)
	}
}

func TestSetNodePropertyStoresMetadataOutsideLiveMap(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 21, 11, 0, 0, 0, time.UTC)
	g.AddNode(&Node{
		ID:   "alias:github:alice",
		Kind: NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"confidence":    0.4,
			"observed_at":   observedAt.Format(time.RFC3339),
			"valid_from":    observedAt.Format(time.RFC3339),
		},
	})

	if !g.SetNodeProperty("alias:github:alice", "confidence", 0.9) {
		t.Fatal("expected SetNodeProperty(confidence) to succeed")
	}
	node, ok := g.GetNode("alias:github:alice")
	if !ok {
		t.Fatal("expected updated alias node after confidence change")
	}
	if got := node.PreviousProperties["confidence"]; got != 0.4 {
		t.Fatalf("PreviousProperties[confidence] = %#v, want 0.4", got)
	}
	if !g.SetNodeProperty("alias:github:alice", "source_event_id", "evt-updated") {
		t.Fatal("expected SetNodeProperty(source_event_id) to succeed")
	}

	node, ok = g.GetNode("alias:github:alice")
	if !ok {
		t.Fatal("expected updated alias node")
	}
	if _, ok := node.Properties["confidence"]; ok {
		t.Fatalf("expected compact live map without confidence, got %#v", node.Properties)
	}
	if _, ok := node.Properties["source_event_id"]; ok {
		t.Fatalf("expected compact live map without source_event_id, got %#v", node.Properties)
	}
	if got, ok := node.PropertyValue("confidence"); !ok || got != 0.9 {
		t.Fatalf("PropertyValue(confidence) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("source_event_id"); !ok || got != "evt-updated" {
		t.Fatalf("PropertyValue(source_event_id) = %#v, %v", got, ok)
	}

	props, ok := node.MetadataProperties()
	if !ok {
		t.Fatal("expected typed alias metadata properties")
	}
	if props.SourceEventID != "evt-updated" {
		t.Fatalf("SourceEventID = %q, want evt-updated", props.SourceEventID)
	}
	if props.Confidence != 0.9 {
		t.Fatalf("Confidence = %f, want 0.9", props.Confidence)
	}
}

func TestIdentityAssertionUsesPromotedMetadataProperties(t *testing.T) {
	g := New()
	observedAt := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	g.AddNode(&Node{
		ID:   "alias:github:alice",
		Kind: NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system":   "github",
			"source_event_id": "evt-assertion",
			"external_id":     "alice",
			"email":           "alice@example.com",
			"observed_at":     observedAt.Format(time.RFC3339),
			"valid_from":      observedAt.Format(time.RFC3339),
			"confidence":      0.82,
		},
	})

	node, ok := g.GetNode("alias:github:alice")
	if !ok {
		t.Fatal("expected alias node")
	}
	if _, ok := node.Properties["source_system"]; ok {
		t.Fatalf("expected compact live map without source_system, got %#v", node.Properties)
	}

	assertion := identityAssertionFromAliasNode(node)
	if assertion.SourceSystem != "github" {
		t.Fatalf("SourceSystem = %q, want github", assertion.SourceSystem)
	}
	if assertion.SourceEventID != "evt-assertion" {
		t.Fatalf("SourceEventID = %q, want evt-assertion", assertion.SourceEventID)
	}
	if !assertion.ObservedAt.Equal(observedAt) {
		t.Fatalf("ObservedAt = %s, want %s", assertion.ObservedAt, observedAt)
	}
	if assertion.Confidence != 0.82 {
		t.Fatalf("Confidence = %f, want 0.82", assertion.Confidence)
	}
}
