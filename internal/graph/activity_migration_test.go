package graph

import (
	"testing"
	"time"
)

func TestMigrateLegacyActivityNodes(t *testing.T) {
	now := time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC)
	g := New()

	g.AddNode(&Node{
		ID:       "activity:calendar:meeting_recorded:evt-1",
		Kind:     NodeKindActivity,
		Name:     "Weekly Payments Sync",
		Provider: "calendar",
		Properties: map[string]any{
			"activity_type": "meeting_recorded",
			"timestamp":     now.Add(-time.Hour).Format(time.RFC3339),
			"source_system": "calendar",
		},
	})
	g.AddNode(&Node{
		ID:       "activity:custom:audit_ping:evt-2",
		Kind:     NodeKindActivity,
		Name:     "Audit ping",
		Provider: "custom",
		Properties: map[string]any{
			"activity_type": "audit_ping",
			"timestamp":     now.Add(-30 * time.Minute).Format(time.RFC3339),
			"source_system": "custom",
		},
	})

	result := MigrateLegacyActivityNodes(g, LegacyActivityMigrationOptions{Now: now})
	if result.Scanned != 2 || result.Migrated != 2 {
		t.Fatalf("unexpected migration result: %#v", result)
	}
	if result.MarkedForReview != 1 {
		t.Fatalf("expected one review-required migration, got %#v", result)
	}

	meetingNode, ok := g.GetNode("activity:calendar:meeting_recorded:evt-1")
	if !ok || meetingNode == nil {
		t.Fatal("expected migrated meeting node")
	}
	if meetingNode.Kind != NodeKindMeeting {
		t.Fatalf("expected meeting kind, got %q", meetingNode.Kind)
	}
	if _, ok := meetingNode.Properties["meeting_id"]; !ok {
		t.Fatalf("expected migrated meeting_id, got %#v", meetingNode.Properties)
	}

	actionNode, ok := g.GetNode("activity:custom:audit_ping:evt-2")
	if !ok || actionNode == nil {
		t.Fatal("expected migrated action node")
	}
	if actionNode.Kind != NodeKindAction {
		t.Fatalf("expected action fallback kind, got %q", actionNode.Kind)
	}
	if needsReview, _ := actionNode.Properties["migration_needs_review"].(bool); !needsReview {
		t.Fatalf("expected migration_needs_review=true, got %#v", actionNode.Properties)
	}
}
