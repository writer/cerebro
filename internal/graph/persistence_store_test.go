package graph

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGraphPersistenceStoreReplicatesAndRecoversFromFileReplica(t *testing.T) {
	localDir := t.TempDir()
	replicaDir := t.TempDir()

	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "payments"})
	g.SetMetadata(Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 22, 0, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: 2 * time.Second,
	})

	record, err := store.SaveGraph(g)
	if err != nil {
		t.Fatalf("save graph snapshot: %v", err)
	}
	if record == nil || record.ID == "" {
		t.Fatalf("expected persisted snapshot record, got %#v", record)
	}

	status := store.Status()
	if status.LastReplicatedSnapshot != record.ID {
		t.Fatalf("expected last replicated snapshot %q, got %#v", record.ID, status)
	}

	if err := os.RemoveAll(localDir); err != nil {
		t.Fatalf("remove local snapshot dir: %v", err)
	}

	recoveredStore, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new recovered graph persistence store: %v", err)
	}

	snapshot, recoveredRecord, source, err := recoveredStore.LoadLatestSnapshot()
	if err != nil {
		t.Fatalf("load latest snapshot from replica: %v", err)
	}
	if source != graphRecoverySourceReplica {
		t.Fatalf("expected replica recovery source, got %q", source)
	}
	if recoveredRecord == nil || recoveredRecord.ID != record.ID {
		t.Fatalf("expected recovered record %q, got %#v", record.ID, recoveredRecord)
	}
	if snapshot == nil || len(snapshot.Nodes) != 1 {
		t.Fatalf("expected one-node recovered snapshot, got %#v", snapshot)
	}

	records, err := recoveredStore.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("list graph snapshot records from replica: %v", err)
	}
	if len(records) != 1 || records[0].ID != record.ID {
		t.Fatalf("expected persisted record list to include %q, got %#v", record.ID, records)
	}

	replicaIndex := filepath.Join(replicaDir, "index.json")
	if _, err := os.Stat(replicaIndex); err != nil {
		t.Fatalf("expected replica index at %s: %v", replicaIndex, err)
	}
}

func TestGraphPersistenceStoreSaveGraphReturnsRecordWhenReplicaSyncFails(t *testing.T) {
	localDir := t.TempDir()
	badReplicaBase := filepath.Join(t.TempDir(), "replica-file")
	if err := os.WriteFile(badReplicaBase, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("seed bad replica path: %v", err)
	}

	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   badReplicaBase,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := New()
	g.AddNode(&Node{ID: "service:billing", Kind: NodeKindService, Name: "billing"})
	g.SetMetadata(Metadata{
		BuiltAt:       time.Date(2026, 3, 12, 23, 0, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: time.Second,
	})

	record, err := store.SaveGraph(g)
	if err == nil {
		t.Fatal("expected replica sync failure")
	}
	if record == nil || record.ID == "" {
		t.Fatalf("expected local persisted record despite replica failure, got %#v", record)
	}
	status := store.Status()
	if status.LastPersistedSnapshot != record.ID {
		t.Fatalf("expected persisted snapshot id %q in status, got %#v", record.ID, status)
	}
	if status.LastReplicationError == "" {
		t.Fatalf("expected replication error in status, got %#v", status)
	}
}

func TestGraphPersistenceStorePeekLatestSnapshotDoesNotRecordRecovery(t *testing.T) {
	localDir := t.TempDir()
	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "payments"})
	g.SetMetadata(Metadata{
		BuiltAt:       time.Date(2026, 3, 19, 5, 0, 0, 0, time.UTC),
		NodeCount:     1,
		EdgeCount:     0,
		Providers:     []string{"aws"},
		Accounts:      []string{"prod"},
		BuildDuration: time.Second,
	})
	record, err := store.SaveGraph(g)
	if err != nil {
		t.Fatalf("save graph snapshot: %v", err)
	}

	snapshot, recoveredRecord, source, err := store.PeekLatestSnapshot()
	if err != nil {
		t.Fatalf("peek latest snapshot: %v", err)
	}
	if source != graphRecoverySourceLocal {
		t.Fatalf("expected local recovery source, got %q", source)
	}
	if recoveredRecord == nil || recoveredRecord.ID != record.ID {
		t.Fatalf("expected peek record %q, got %#v", record.ID, recoveredRecord)
	}
	if snapshot == nil || len(snapshot.Nodes) != 1 {
		t.Fatalf("expected one-node snapshot, got %#v", snapshot)
	}
	if status := store.Status(); status.LastRecoveredAt != nil || status.LastRecoveredSnapshot != "" || status.LastRecoverySource != "" {
		t.Fatalf("expected peek to avoid recovery bookkeeping, got %#v", status)
	}
}

func TestGraphPersistenceStoreRejectsTraversalArtifactPathFromReplicaIndex(t *testing.T) {
	localDir := t.TempDir()
	replicaDir := t.TempDir()
	index := graphSnapshotIndex{
		APIVersion:  graphSnapshotIndexAPIVersion,
		GeneratedAt: time.Now().UTC(),
		Snapshots: []GraphSnapshotManifest{
			{
				APIVersion:   graphSnapshotManifestAPIVersion,
				Kind:         graphSnapshotManifestKind,
				SnapshotID:   "snap-1",
				ArtifactPath: "../escape.json.gz",
				Record: GraphSnapshotRecord{
					ID: "snap-1",
				},
			},
		},
	}
	payload, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal replica index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replicaDir, "index.json"), payload, 0o600); err != nil {
		t.Fatalf("write replica index: %v", err)
	}
	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}
	if _, err := store.ListGraphSnapshotRecords(); err == nil || !strings.Contains(err.Error(), "invalid replica snapshot artifact path") {
		t.Fatalf("expected invalid artifact path error, got %v", err)
	}
}

func TestFileGraphSnapshotReplicaRejectsTraversalKeys(t *testing.T) {
	replica := newFileGraphSnapshotReplica(t.TempDir())
	if err := replica.PutBytes(context.Background(), "../escape", []byte("payload"), "application/octet-stream"); err == nil {
		t.Fatal("expected traversal key rejection on put")
	}
	if _, err := replica.Open(context.Background(), "../escape"); err == nil {
		t.Fatal("expected traversal key rejection on open")
	}
	if err := replica.DeleteKeys(context.Background(), "../escape"); err == nil {
		t.Fatal("expected traversal key rejection on delete")
	}
}

func TestParseBucketURIAllowsBucketRootTrailingSlash(t *testing.T) {
	tests := []struct {
		raw          string
		prefix       string
		wantBucket   string
		wantObjPrfix string
	}{
		{raw: "s3://bucket/", prefix: "s3://", wantBucket: "bucket", wantObjPrfix: ""},
		{raw: "gcs://bucket/", prefix: "gcs://", wantBucket: "bucket", wantObjPrfix: ""},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			bucket, objectPrefix, err := parseBucketURI(tt.raw, tt.prefix)
			if err != nil {
				t.Fatalf("parseBucketURI(%q): %v", tt.raw, err)
			}
			if bucket != tt.wantBucket {
				t.Fatalf("expected bucket %q, got %q", tt.wantBucket, bucket)
			}
			if objectPrefix != tt.wantObjPrfix {
				t.Fatalf("expected object prefix %q, got %q", tt.wantObjPrfix, objectPrefix)
			}
		})
	}
}

func TestGraphPersistenceStoreSyncReplicaDeletesOnlyPreviouslyTrackedKeys(t *testing.T) {
	localDir := t.TempDir()
	replicaDir := t.TempDir()

	previousIndex := graphSnapshotIndex{
		APIVersion:  graphSnapshotIndexAPIVersion,
		GeneratedAt: time.Now().UTC(),
		Snapshots: []GraphSnapshotManifest{
			{
				APIVersion:   graphSnapshotManifestAPIVersion,
				Kind:         graphSnapshotManifestKind,
				SnapshotID:   "old-snap",
				ArtifactPath: "graph-old.json.gz",
				Record: GraphSnapshotRecord{
					ID: "old-snap",
				},
			},
		},
	}
	indexPayload, err := json.Marshal(previousIndex)
	if err != nil {
		t.Fatalf("marshal previous index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replicaDir, "index.json"), indexPayload, 0o600); err != nil {
		t.Fatalf("write previous replica index: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(replicaDir, "manifests"), 0o750); err != nil {
		t.Fatalf("create replica manifests dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replicaDir, "graph-old.json.gz"), []byte("old"), 0o600); err != nil {
		t.Fatalf("write previous snapshot artifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replicaDir, "manifests", "old-snap.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write previous manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replicaDir, "shared.json.gz"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("write unrelated shared object: %v", err)
	}

	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    localDir,
		MaxSnapshots: 4,
		ReplicaURI:   replicaDir,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := New()
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "payments"})
	g.SetMetadata(Metadata{
		BuiltAt:   time.Now().UTC(),
		NodeCount: 1,
	})
	if _, err := store.SaveGraph(g); err != nil {
		t.Fatalf("save graph with replica sync: %v", err)
	}

	if _, err := os.Stat(filepath.Join(replicaDir, "shared.json.gz")); err != nil {
		t.Fatalf("expected unrelated shared object to remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(replicaDir, "graph-old.json.gz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected previously tracked stale artifact to be removed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(replicaDir, "manifests", "old-snap.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected previously tracked stale manifest to be removed, got %v", err)
	}
}

type failOnSecondWriteWriter struct {
	writes int
}

func (w *failOnSecondWriteWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes >= 2 {
		return 0, errors.New("flush failed")
	}
	return len(p), nil
}

func TestSnapshotWriteCompressedPropagatesCloseError(t *testing.T) {
	snapshot := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: time.Unix(0, 0).UTC(),
	}
	err := snapshot.writeCompressed(&failOnSecondWriteWriter{})
	if err == nil {
		t.Fatal("expected close error from compressed writer")
	}
	if !strings.Contains(err.Error(), "close compressed snapshot") {
		t.Fatalf("expected close compressed snapshot error, got %v", err)
	}
}
