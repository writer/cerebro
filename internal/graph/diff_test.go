package graph

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestDiffSnapshots_DetectsStructuralChanges(t *testing.T) {
	beforeAt := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)
	afterAt := beforeAt.Add(1 * time.Hour)
	deletedAt := afterAt

	before := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: beforeAt,
		Nodes: []*Node{
			{ID: "role-a", Kind: NodeKindRole, Name: "role-a", Properties: map[string]any{"level": "read"}},
			{ID: "bucket-b", Kind: NodeKindBucket, Name: "bucket-b"},
		},
		Edges: []*Edge{
			{ID: "e1", Source: "role-a", Target: "bucket-b", Kind: EdgeKindCanRead},
		},
	}
	after := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: afterAt,
		Nodes: []*Node{
			{ID: "role-a", Kind: NodeKindRole, Name: "role-a", Properties: map[string]any{"level": "admin"}},
			{ID: "bucket-b", Kind: NodeKindBucket, Name: "bucket-b", DeletedAt: &deletedAt},
			{ID: "bucket-c", Kind: NodeKindBucket, Name: "bucket-c"},
		},
		Edges: []*Edge{
			{ID: "e1", Source: "role-a", Target: "bucket-b", Kind: EdgeKindCanRead, DeletedAt: &deletedAt},
			{ID: "e2", Source: "role-a", Target: "bucket-c", Kind: EdgeKindCanRead},
		},
	}

	diff := DiffSnapshots(before, after)
	if diff.FromTimestamp != beforeAt || diff.ToTimestamp != afterAt {
		t.Fatalf("unexpected diff timestamps: from=%s to=%s", diff.FromTimestamp, diff.ToTimestamp)
	}

	if len(diff.NodesAdded) != 1 || diff.NodesAdded[0].ID != "bucket-c" {
		t.Fatalf("expected one added node bucket-c, got %+v", diff.NodesAdded)
	}
	if len(diff.NodesRemoved) != 1 || diff.NodesRemoved[0].ID != "bucket-b" {
		t.Fatalf("expected one removed node bucket-b, got %+v", diff.NodesRemoved)
	}
	if len(diff.NodesModified) != 1 || diff.NodesModified[0].NodeID != "role-a" {
		t.Fatalf("expected one modified node role-a, got %+v", diff.NodesModified)
	}
	if !containsStringValue(diff.NodesModified[0].ChangedKeys, "level") {
		t.Fatalf("expected changed keys to include level, got %v", diff.NodesModified[0].ChangedKeys)
	}

	if len(diff.EdgesAdded) != 1 || diff.EdgesAdded[0].ID != "e2" {
		t.Fatalf("expected one added edge e2, got %+v", diff.EdgesAdded)
	}
	if len(diff.EdgesRemoved) != 1 || diff.EdgesRemoved[0].ID != "e1" {
		t.Fatalf("expected one removed edge e1, got %+v", diff.EdgesRemoved)
	}
}

func TestSnapshotStore_DiffByTime_SelectsClosestSnapshots(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)

	mustSaveSnapshot(t, dir, &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base,
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
		},
	})
	mustSaveSnapshot(t, dir, &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(1 * time.Hour),
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: NodeKindBucket, Name: "b"},
		},
	})
	mustSaveSnapshot(t, dir, &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(2 * time.Hour),
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: NodeKindBucket, Name: "b"},
			{ID: "node-c", Kind: NodeKindBucket, Name: "c"},
		},
	})

	store := NewSnapshotStore(dir, 10)
	diff, err := store.DiffByTime(base.Add(20*time.Minute), base.Add(70*time.Minute))
	if err != nil {
		t.Fatalf("DiffByTime failed: %v", err)
	}

	if diff.FromTimestamp != base {
		t.Fatalf("expected from snapshot at %s, got %s", base, diff.FromTimestamp)
	}
	if diff.ToTimestamp != base.Add(1*time.Hour) {
		t.Fatalf("expected to snapshot at %s, got %s", base.Add(1*time.Hour), diff.ToTimestamp)
	}
	if len(diff.NodesAdded) != 1 || diff.NodesAdded[0].ID != "node-b" {
		t.Fatalf("expected node-b added between selected snapshots, got %+v", diff.NodesAdded)
	}
}

func mustSaveSnapshot(t *testing.T, dir string, snapshot *Snapshot) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("graph-%s.json.gz", snapshot.CreatedAt.Format("20060102-150405")))
	if err := snapshot.SaveToFile(path); err != nil {
		t.Fatalf("save snapshot %s: %v", path, err)
	}
}

func containsStringValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
