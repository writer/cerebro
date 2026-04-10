package graph

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGraphPersistenceStoreLoadLatestSnapshotUsesLocalRecovery(t *testing.T) {
	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    t.TempDir(),
		MaxSnapshots: 4,
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

	snapshot, recoveredRecord, source, err := store.LoadLatestSnapshot()
	if err != nil {
		t.Fatalf("load latest snapshot: %v", err)
	}
	if source != graphRecoverySourceLocal {
		t.Fatalf("expected local recovery source, got %q", source)
	}
	if recoveredRecord == nil || recoveredRecord.ID != record.ID {
		t.Fatalf("expected recovered record %q, got %#v", record.ID, recoveredRecord)
	}
	if snapshot == nil || len(snapshot.Nodes) != 1 {
		t.Fatalf("expected one-node recovered snapshot, got %#v", snapshot)
	}

	status := store.Status()
	if status.LastPersistedSnapshot != record.ID {
		t.Fatalf("expected last persisted snapshot %q, got %#v", record.ID, status)
	}
	if status.LastRecoverySource != graphRecoverySourceLocal {
		t.Fatalf("expected local recovery status, got %#v", status)
	}
	if status.LastRecoveredSnapshot != record.ID {
		t.Fatalf("expected recovered snapshot %q, got %#v", record.ID, status)
	}
}

func TestGraphPersistenceStoreLoadSnapshotsByRecordIDsUsesLocalStore(t *testing.T) {
	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    t.TempDir(),
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	first := New()
	first.AddNode(&Node{ID: "service:first", Kind: NodeKindService, Name: "first"})
	first.SetMetadata(Metadata{
		BuiltAt:   time.Date(2026, 3, 12, 22, 0, 0, 0, time.UTC),
		NodeCount: 1,
	})
	firstRecord, err := store.SaveGraph(first)
	if err != nil {
		t.Fatalf("save first graph snapshot: %v", err)
	}

	second := New()
	second.AddNode(&Node{ID: "service:second", Kind: NodeKindService, Name: "second"})
	second.SetMetadata(Metadata{
		BuiltAt:   time.Date(2026, 3, 12, 23, 0, 0, 0, time.UTC),
		NodeCount: 1,
	})
	secondRecord, err := store.SaveGraph(second)
	if err != nil {
		t.Fatalf("save second graph snapshot: %v", err)
	}

	snapshots, records, err := store.LoadSnapshotsByRecordIDs(firstRecord.ID, secondRecord.ID)
	if err != nil {
		t.Fatalf("LoadSnapshotsByRecordIDs() error = %v", err)
	}
	if len(snapshots) != 2 || len(records) != 2 {
		t.Fatalf("expected two snapshots and two records, got snapshots=%d records=%d", len(snapshots), len(records))
	}
	if _, ok := snapshots[firstRecord.ID]; !ok {
		t.Fatalf("expected snapshot %q", firstRecord.ID)
	}
	if _, ok := snapshots[secondRecord.ID]; !ok {
		t.Fatalf("expected snapshot %q", secondRecord.ID)
	}
	if records[firstRecord.ID] == nil || records[firstRecord.ID].ID != firstRecord.ID {
		t.Fatalf("expected record %q, got %#v", firstRecord.ID, records[firstRecord.ID])
	}
	if records[secondRecord.ID] == nil || records[secondRecord.ID].ID != secondRecord.ID {
		t.Fatalf("expected record %q, got %#v", secondRecord.ID, records[secondRecord.ID])
	}
}

func TestGraphPersistenceStorePeekLatestSnapshotDoesNotRecordRecovery(t *testing.T) {
	store, err := NewGraphPersistenceStore(GraphPersistenceOptions{
		LocalPath:    t.TempDir(),
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
