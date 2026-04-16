package findings

import (
	"testing"
	"time"
)

func TestSnapshotDirtyFindingsDetachesMutableState(t *testing.T) {
	dueAt := time.Date(2026, time.April, 16, 12, 0, 0, 0, time.UTC)
	original := &Finding{
		ID:                 "finding-1",
		Status:             "OPEN",
		DueAt:              &dueAt,
		Resource:           map[string]interface{}{"nested": map[string]interface{}{"name": "before"}},
		ResourceJSON:       map[string]interface{}{"nested": map[string]interface{}{"state": "before"}},
		ResourceTags:       map[string]string{"env": "prod"},
		ObservedFindingIDs: []string{"obs-1"},
		Evidence: []Evidence{{
			Type: "snapshot",
			Data: map[string]interface{}{"status": "before"},
		}},
		resourceJSONRaw: []byte(`{"name":"before"}`),
	}

	snapshots, err := snapshotDirtyFindings(
		map[string]*Finding{original.ID: original},
		map[string]bool{original.ID: true},
	)
	if err != nil {
		t.Fatalf("snapshotDirtyFindings() error = %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("len(snapshots) = %d, want 1", len(snapshots))
	}

	snapshot := snapshots[0]
	updatedDueAt := dueAt.Add(2 * time.Hour)
	original.Status = "RESOLVED"
	original.DueAt = &updatedDueAt
	original.Resource["nested"].(map[string]interface{})["name"] = "after"
	original.ResourceJSON["nested"].(map[string]interface{})["state"] = "after"
	original.ResourceTags["env"] = "stage"
	original.ObservedFindingIDs[0] = "obs-2"
	original.Evidence[0].Data["status"] = "after"
	original.resourceJSONRaw[2] = 'X'

	if snapshot.Status != "OPEN" {
		t.Fatalf("snapshot status = %q, want OPEN", snapshot.Status)
	}
	if snapshot.DueAt == nil || !snapshot.DueAt.Equal(dueAt) {
		t.Fatalf("snapshot DueAt = %v, want %s", snapshot.DueAt, dueAt)
	}
	if got := snapshot.Resource["nested"].(map[string]interface{})["name"]; got != "before" {
		t.Fatalf("snapshot resource name = %#v, want before", got)
	}
	if got := snapshot.ResourceJSON["nested"].(map[string]interface{})["state"]; got != "before" {
		t.Fatalf("snapshot resource json state = %#v, want before", got)
	}
	if got := snapshot.ResourceTags["env"]; got != "prod" {
		t.Fatalf("snapshot resource tag = %q, want prod", got)
	}
	if got := snapshot.ObservedFindingIDs[0]; got != "obs-1" {
		t.Fatalf("snapshot observed finding id = %q, want obs-1", got)
	}
	if got := snapshot.Evidence[0].Data["status"]; got != "before" {
		t.Fatalf("snapshot evidence status = %#v, want before", got)
	}
	if got := string(snapshot.resourceJSONRaw); got != `{"name":"before"}` {
		t.Fatalf("snapshot resourceJSONRaw = %q, want original bytes", got)
	}
}
