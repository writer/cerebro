package entities

import (
	"testing"
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

func TestGetEntityRecordAtTimeAndDiff(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded node")
	}
	node.PropertyHistory = map[string][]graph.PropertySnapshot{
		"status": {
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
		"owner": {
			{Timestamp: base.Add(2 * time.Hour), Value: "team-payments"},
		},
	}

	record, ok := GetEntityRecordAtTime(g, "service:payments", base.Add(30*time.Minute), base.Add(30*time.Minute))
	if !ok {
		t.Fatal("expected entity record at time")
	}
	if got := record.Entity.Properties["status"]; got != "healthy" {
		t.Fatalf("expected historical status healthy, got %#v", got)
	}
	if _, ok := record.Entity.Properties["owner"]; ok {
		t.Fatalf("did not expect owner before it existed, got %#v", record.Entity.Properties["owner"])
	}
	if !record.Reconstruction.PropertyHistoryApplied {
		t.Fatalf("expected property history reconstruction, got %+v", record.Reconstruction)
	}
	if record.Reconstruction.HistoricalCoreFields {
		t.Fatalf("expected core field reconstruction to remain false, got %+v", record.Reconstruction)
	}

	diff, ok := GetEntityTimeDiff(g, "service:payments", base, base.Add(3*time.Hour), base.Add(3*time.Hour))
	if !ok {
		t.Fatal("expected entity time diff")
	}
	if len(diff.ChangedKeys) < 2 {
		t.Fatalf("expected multiple changed keys, got %+v", diff)
	}
	foundStatus := false
	foundOwner := false
	for _, change := range diff.PropertyChanges {
		switch change.Key {
		case "status":
			foundStatus = true
			if change.Before != "healthy" || change.After != "degraded" {
				t.Fatalf("unexpected status diff: %+v", change)
			}
		case "owner":
			foundOwner = true
			if change.Before != nil || change.After != "team-payments" {
				t.Fatalf("unexpected owner diff: %+v", change)
			}
		}
	}
	if !foundStatus || !foundOwner {
		t.Fatalf("expected status and owner diffs, got %+v", diff.PropertyChanges)
	}
}

func TestGetEntityRecordAtTimeHonorsTransactionTo(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	transactionTo := base.Add(2 * time.Hour)
	g := New()
	g.AddNode(&Node{
		ID:        "service:ephemeral",
		Kind:      NodeKindService,
		Name:      "Ephemeral",
		Provider:  "aws",
		CreatedAt: base,
		UpdatedAt: base,
		Properties: map[string]any{
			"status":           "active",
			"observed_at":      base.Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
			"transaction_to":   transactionTo.Format(time.RFC3339),
		},
	})

	if _, ok := GetEntityRecordAtTime(g, "service:ephemeral", base.Add(time.Hour), transactionTo.Add(-time.Minute)); !ok {
		t.Fatal("expected entity record before transaction window closed")
	}
	if _, ok := GetEntityRecordAtTime(g, "service:ephemeral", base.Add(time.Hour), transactionTo.Add(time.Minute)); ok {
		t.Fatal("did not expect entity record after transaction_to")
	}
}

func TestGetEntityRecordAtTimeUsesRecordedAtHistoryAndTombstones(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	correctionAt := base.Add(2 * time.Hour)
	g := New()
	g.SetTemporalHistoryConfig(graph.DefaultTemporalHistoryMaxEntries, 30*24*time.Hour)
	g.AddNode(&Node{
		ID:        "service:checkout",
		Kind:      NodeKindService,
		Name:      "Checkout",
		Provider:  "aws",
		CreatedAt: base,
		UpdatedAt: base,
		Properties: map[string]any{
			"status":           "healthy",
			"owner":            "team-checkout",
			"observed_at":      base.Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:        "service:checkout",
		Kind:      NodeKindService,
		Name:      "Checkout",
		Provider:  "aws",
		CreatedAt: base,
		UpdatedAt: correctionAt,
		Properties: map[string]any{
			"status":           "degraded",
			"observed_at":      correctionAt.Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
		},
	})

	node, ok := g.GetNode("service:checkout")
	if !ok || node == nil {
		t.Fatal("expected updated node")
	}
	history := node.PropertyHistory["owner"]
	if len(history) == 0 || !history[len(history)-1].Deleted {
		t.Fatalf("expected owner tombstone in property history, got %#v", history)
	}

	beforeCorrection, ok := GetEntityRecordAtTime(g, "service:checkout", correctionAt.Add(time.Minute), base.Add(time.Minute))
	if !ok {
		t.Fatal("expected entity record before later correction was recorded")
	}
	if got := beforeCorrection.Entity.Properties["status"]; got != "healthy" {
		t.Fatalf("expected status healthy before correction recorded, got %#v", got)
	}
	if got := beforeCorrection.Entity.Properties["owner"]; got != "team-checkout" {
		t.Fatalf("expected owner before tombstone, got %#v", got)
	}

	afterCorrection, ok := GetEntityRecordAtTime(g, "service:checkout", correctionAt.Add(time.Minute), correctionAt.Add(time.Minute))
	if !ok {
		t.Fatal("expected entity record after correction was recorded")
	}
	if got := afterCorrection.Entity.Properties["status"]; got != "degraded" {
		t.Fatalf("expected degraded status after correction, got %#v", got)
	}
	if _, ok := afterCorrection.Entity.Properties["owner"]; ok {
		t.Fatalf("did not expect owner after tombstone, got %#v", afterCorrection.Entity.Properties["owner"])
	}
}

func TestGetEntityTimeDiffAcrossDeletion(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	deletedAt := base.Add(2 * time.Hour)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:legacy",
		Kind:     graph.NodeKindService,
		Name:     "Legacy",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "retiring",
			"observed_at":      base.Format(time.RFC3339),
			"valid_from":       base.Format(time.RFC3339),
			"valid_to":         deletedAt.Format(time.RFC3339),
			"recorded_at":      base.Format(time.RFC3339),
			"transaction_from": base.Format(time.RFC3339),
			"transaction_to":   deletedAt.Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:legacy")
	if !ok || node == nil {
		t.Fatal("expected seeded deleted node")
	}
	node.CreatedAt = base
	node.UpdatedAt = base
	node.DeletedAt = &deletedAt
	node.PropertyHistory = nil

	record, ok := GetEntityRecordAtTime(g, "service:legacy", base.Add(time.Hour), base.Add(3*time.Hour))
	if !ok {
		t.Fatal("expected entity record before deletion")
	}
	if got := record.Entity.Name; got != "Legacy" {
		t.Fatalf("expected historical entity before deletion, got %#v", record.Entity)
	}
	if _, ok := GetEntityRecordAtTime(g, "service:legacy", base.Add(3*time.Hour), base.Add(3*time.Hour)); ok {
		t.Fatal("did not expect entity record after deletion")
	}

	diff, ok := GetEntityTimeDiff(g, "service:legacy", base.Add(time.Hour), base.Add(3*time.Hour), base.Add(3*time.Hour))
	if !ok {
		t.Fatal("expected entity diff across deletion")
	}
	if diff.After.Entity.ID != "service:legacy" {
		t.Fatalf("expected tombstone after record to keep entity id, got %#v", diff.After.Entity)
	}
	foundStatus := false
	for _, change := range diff.PropertyChanges {
		if change.Key != "status" {
			continue
		}
		foundStatus = true
		if change.Before != "retiring" || change.After != nil {
			t.Fatalf("unexpected deleted status diff: %+v", change)
		}
	}
	if !foundStatus {
		t.Fatalf("expected property removal in deletion diff, got %+v", diff.PropertyChanges)
	}
	if len(diff.ChangedKeys) == 0 {
		t.Fatalf("expected changed keys across deletion, got %+v", diff)
	}
}
