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

func TestSnapshotStore_DiffByTimeForTenantFiltersForeignTenantChanges(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)

	mustSaveSnapshot(t, dir, &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base,
		Nodes: []*Node{
			{ID: "service:tenant-a", Kind: NodeKindService, Name: "tenant-a", TenantID: "tenant-a"},
			{ID: "service:tenant-b", Kind: NodeKindService, Name: "tenant-b", TenantID: "tenant-b"},
		},
	})
	mustSaveSnapshot(t, dir, &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(1 * time.Hour),
		Nodes: []*Node{
			{ID: "service:tenant-a", Kind: NodeKindService, Name: "tenant-a", TenantID: "tenant-a"},
			{ID: "service:tenant-b", Kind: NodeKindService, Name: "tenant-b", TenantID: "tenant-b"},
			{ID: "db:tenant-b", Kind: NodeKindDatabase, Name: "tenant-b-db", TenantID: "tenant-b"},
		},
		Edges: []*Edge{{ID: "tenant-b-edge", Source: "service:tenant-b", Target: "db:tenant-b", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow}},
	})

	store := NewSnapshotStore(dir, 10)
	diff, err := store.DiffByTimeForTenant(base.Add(5*time.Minute), base.Add(65*time.Minute), "tenant-a")
	if err != nil {
		t.Fatalf("DiffByTimeForTenant failed: %v", err)
	}
	if len(diff.NodesAdded) != 0 || len(diff.EdgesAdded) != 0 || len(diff.NodesRemoved) != 0 || len(diff.EdgesRemoved) != 0 {
		t.Fatalf("expected tenant-a diff to exclude tenant-b changes, got %+v", diff)
	}

	tenantBDiff, err := store.DiffByTimeForTenant(base.Add(5*time.Minute), base.Add(65*time.Minute), "tenant-b")
	if err != nil {
		t.Fatalf("DiffByTimeForTenant tenant-b failed: %v", err)
	}
	if len(tenantBDiff.NodesAdded) != 1 || tenantBDiff.NodesAdded[0].ID != "db:tenant-b" {
		t.Fatalf("expected tenant-b diff to include tenant-b database, got %+v", tenantBDiff.NodesAdded)
	}
}

func TestSnapshotStore_LoadSnapshotByRecordID(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)
	snapshot := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
		},
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
		},
	}
	mustSaveSnapshot(t, dir, snapshot)

	store := NewSnapshotStore(dir, 10)
	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("ListGraphSnapshotRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one snapshot record, got %d", len(records))
	}
	loaded, record, err := store.LoadSnapshotByRecordID(records[0].ID)
	if err != nil {
		t.Fatalf("LoadSnapshotByRecordID failed: %v", err)
	}
	if record == nil || record.ID != records[0].ID {
		t.Fatalf("expected matching record id %q, got %+v", records[0].ID, record)
	}
	if loaded == nil || len(loaded.Nodes) != 1 || loaded.Nodes[0].ID != "node-a" {
		t.Fatalf("expected snapshot node-a, got %+v", loaded)
	}
}

func TestSnapshotStore_LoadSnapshotsByRecordIDs(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)
	first := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
		},
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
		},
	}
	second := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(10 * time.Minute),
		Metadata: Metadata{
			BuiltAt:   base.Add(5 * time.Minute),
			NodeCount: 1,
			EdgeCount: 0,
		},
		Nodes: []*Node{
			{ID: "node-b", Kind: NodeKindBucket, Name: "b"},
		},
	}
	mustSaveSnapshot(t, dir, first)
	mustSaveSnapshot(t, dir, second)

	store := NewSnapshotStore(dir, 10)
	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("ListGraphSnapshotRecords failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two snapshot records, got %d", len(records))
	}

	snapshots, loadedRecords, err := store.LoadSnapshotsByRecordIDs(records[0].ID, records[1].ID)
	if err != nil {
		t.Fatalf("LoadSnapshotsByRecordIDs failed: %v", err)
	}
	if len(snapshots) != 2 || len(loadedRecords) != 2 {
		t.Fatalf("expected two loaded snapshots and records, got %d and %d", len(snapshots), len(loadedRecords))
	}
}

func TestGraphSnapshotAncestryFromCollection(t *testing.T) {
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)
	firstBuiltAt := base
	secondBuiltAt := base.Add(1 * time.Hour)
	collection := GraphSnapshotCollection{
		GeneratedAt: base.Add(2 * time.Hour),
		Count:       2,
		Snapshots: []GraphSnapshotRecord{
			{ID: "graph_snapshot:newer", BuiltAt: &secondBuiltAt},
			{ID: "graph_snapshot:older", BuiltAt: &firstBuiltAt, Diffable: true},
		},
	}

	ancestry, ok := GraphSnapshotAncestryFromCollection(collection, "graph_snapshot:newer")
	if !ok {
		t.Fatal("expected ancestry for newer snapshot")
	}
	if ancestry.Count != 2 || ancestry.Position != 2 {
		t.Fatalf("unexpected ancestry counters: %+v", ancestry)
	}
	if ancestry.Previous == nil || ancestry.Previous.ID != "graph_snapshot:older" {
		t.Fatalf("expected previous older snapshot, got %+v", ancestry.Previous)
	}
	if ancestry.Next != nil {
		t.Fatalf("expected no next snapshot, got %+v", ancestry.Next)
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
