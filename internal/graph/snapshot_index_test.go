package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotStore_PersistsManifestIndexAndLineage(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)

	older := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(5 * time.Minute),
		Metadata: Metadata{
			BuiltAt:   base,
			NodeCount: 1,
			EdgeCount: 0,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
		},
	}
	newer := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: base.Add(65 * time.Minute),
		Metadata: Metadata{
			BuiltAt:   base.Add(1 * time.Hour),
			NodeCount: 2,
			EdgeCount: 1,
			Providers: []string{"aws"},
			Accounts:  []string{"acct-a"},
		},
		Nodes: []*Node{
			{ID: "node-a", Kind: NodeKindUser, Name: "a"},
			{ID: "node-b", Kind: NodeKindBucket, Name: "b"},
		},
		Edges: []*Edge{
			{ID: "edge-1", Source: "node-a", Target: "node-b", Kind: EdgeKindCanRead},
		},
	}
	mustSaveSnapshot(t, dir, older)
	mustSaveSnapshot(t, dir, newer)

	store := NewSnapshotStore(dir, 10)
	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("ListGraphSnapshotRecords failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two graph snapshot records, got %d", len(records))
	}

	olderID := buildSnapshotRecordID(older)
	newerID := buildSnapshotRecordID(newer)
	recordByID := make(map[string]GraphSnapshotRecord, len(records))
	for _, record := range records {
		recordByID[record.ID] = record
	}
	newerRecord, ok := recordByID[newerID]
	if !ok {
		t.Fatalf("expected newer snapshot record %q", newerID)
	}
	if got := newerRecord.ParentSnapshotID; got != olderID {
		t.Fatalf("expected newer parent snapshot %q, got %q", olderID, got)
	}
	if got := newerRecord.RetentionClass; got != graphSnapshotRetentionLocal {
		t.Fatalf("expected retention class %q, got %q", graphSnapshotRetentionLocal, got)
	}
	if got := newerRecord.StorageClass; got != graphSnapshotStorageLocalStore {
		t.Fatalf("expected storage class %q, got %q", graphSnapshotStorageLocalStore, got)
	}
	if !strings.HasPrefix(newerRecord.IntegrityHash, "sha256:") {
		t.Fatalf("expected sha256 integrity hash, got %q", newerRecord.IntegrityHash)
	}

	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		t.Fatalf("expected snapshot index file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifests")); err != nil {
		t.Fatalf("expected snapshot manifest dir: %v", err)
	}
	if _, err := os.Stat(store.snapshotManifestPath(newerID)); err != nil {
		t.Fatalf("expected newer snapshot manifest: %v", err)
	}
	if _, err := os.Stat(store.snapshotManifestPath(olderID)); err != nil {
		t.Fatalf("expected older snapshot manifest: %v", err)
	}

	snapshots, loadedRecords, err := store.LoadSnapshotsByRecordIDs(olderID, newerID)
	if err != nil {
		t.Fatalf("LoadSnapshotsByRecordIDs failed: %v", err)
	}
	if len(snapshots) != 2 || len(loadedRecords) != 2 {
		t.Fatalf("expected two loaded snapshots and records, got %d and %d", len(snapshots), len(loadedRecords))
	}
	if snapshots[newerID] == nil || len(snapshots[newerID].Nodes) != 2 {
		t.Fatalf("expected newer snapshot payload with two nodes, got %+v", snapshots[newerID])
	}
}

func TestGraphSnapshotAncestryFromCollection_UsesExplicitParentChildLineage(t *testing.T) {
	base := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)
	firstBuiltAt := base
	secondBuiltAt := base.Add(1 * time.Hour)
	thirdBuiltAt := base.Add(2 * time.Hour)
	collection := GraphSnapshotCollection{
		GeneratedAt: base.Add(3 * time.Hour),
		Count:       3,
		Snapshots: []GraphSnapshotRecord{
			{ID: "graph_snapshot:branch-a", ParentSnapshotID: "graph_snapshot:root", BuiltAt: &secondBuiltAt},
			{ID: "graph_snapshot:branch-b", ParentSnapshotID: "graph_snapshot:root", BuiltAt: &thirdBuiltAt},
			{ID: "graph_snapshot:root", BuiltAt: &firstBuiltAt, Diffable: true},
		},
	}

	rootAncestry, ok := GraphSnapshotAncestryFromCollection(collection, "graph_snapshot:root")
	if !ok {
		t.Fatal("expected ancestry for root snapshot")
	}
	if len(rootAncestry.Children) != 2 {
		t.Fatalf("expected two explicit children, got %+v", rootAncestry.Children)
	}
	if len(rootAncestry.Descendants) != 2 {
		t.Fatalf("expected two descendants, got %+v", rootAncestry.Descendants)
	}
	if rootAncestry.Parent != nil {
		t.Fatalf("expected no parent for root snapshot, got %+v", rootAncestry.Parent)
	}

	childAncestry, ok := GraphSnapshotAncestryFromCollection(collection, "graph_snapshot:branch-b")
	if !ok {
		t.Fatal("expected ancestry for branch-b snapshot")
	}
	if childAncestry.Parent == nil || childAncestry.Parent.ID != "graph_snapshot:root" {
		t.Fatalf("expected explicit parent root, got %+v", childAncestry.Parent)
	}
	if len(childAncestry.Ancestors) != 1 || childAncestry.Ancestors[0].ID != "graph_snapshot:root" {
		t.Fatalf("expected root ancestor, got %+v", childAncestry.Ancestors)
	}
}
