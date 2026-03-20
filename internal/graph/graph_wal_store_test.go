package graph

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGraphMutationLogAppendAndLoadAll(t *testing.T) {
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	records := []GraphMutationRecord{
		{
			Sequence:   1,
			RecordedAt: time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node: &Node{
				ID:        "workload:payments",
				Kind:      NodeKindWorkload,
				UpdatedAt: time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
				Version:   1,
			},
		},
		{
			Sequence:      2,
			RecordedAt:    time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "workload:payments",
			PropertyKey:   "internet_exposed",
			PropertyValue: true,
		},
	}
	for _, record := range records {
		if err := log.Append(record); err != nil {
			t.Fatalf("Append(%d): %v", record.Sequence, err)
		}
	}

	loaded, err := log.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != len(records) {
		t.Fatalf("len(loaded) = %d, want %d", len(loaded), len(records))
	}
	if loaded[0].Sequence != 1 || loaded[1].Sequence != 2 {
		t.Fatalf("unexpected sequences: %#v", loaded)
	}
}

func TestLoadGraphMutationRecordsFromReadCloserPreservesLoadedRecordsOnCloseError(t *testing.T) {
	var payload bytes.Buffer
	if err := AppendGraphMutationRecord(&payload, GraphMutationRecord{
		Sequence:   1,
		RecordedAt: time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
		Type:       GraphMutationRemoveNode,
		NodeID:     "workload:queue",
	}); err != nil {
		t.Fatalf("AppendGraphMutationRecord: %v", err)
	}

	records, err := loadGraphMutationRecordsFromReadCloser(&stubReadCloser{
		Reader:   bytes.NewReader(payload.Bytes()),
		closeErr: errors.New("close failed"),
	})
	if err == nil {
		t.Fatal("expected close error")
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].Sequence != 1 {
		t.Fatalf("records[0].Sequence = %d, want 1", records[0].Sequence)
	}
	if !strings.Contains(err.Error(), "close graph mutation log") {
		t.Fatalf("error = %v, want close graph mutation log context", err)
	}
}

func TestLoadGraphMutationRecordsFromReadCloserPreservesLoadErrorOnCloseFailure(t *testing.T) {
	records, err := loadGraphMutationRecordsFromReadCloser(&stubReadCloser{
		Reader:   strings.NewReader("{"),
		closeErr: errors.New("close failed"),
	})
	if err == nil {
		t.Fatal("expected load/close error")
	}
	if len(records) != 0 {
		t.Fatalf("len(records) = %d, want 0", len(records))
	}
	if !strings.Contains(err.Error(), "decode graph mutation record") {
		t.Fatalf("error = %v, want decode graph mutation record context", err)
	}
	if !strings.Contains(err.Error(), "close graph mutation log") {
		t.Fatalf("error = %v, want close graph mutation log context", err)
	}
}

func TestGraphMutationLogLoadAfterSequence(t *testing.T) {
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	for i := 1; i <= 4; i++ {
		if err := log.Append(GraphMutationRecord{
			Sequence:   uint64(i),
			RecordedAt: time.Date(2026, 3, 16, 20, i, 0, 0, time.UTC),
			Type:       GraphMutationRemoveNode,
			NodeID:     "workload:queue",
		}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}

	loaded, err := log.LoadAfterSequence(2)
	if err != nil {
		t.Fatalf("LoadAfterSequence: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("len(loaded) = %d, want 2", len(loaded))
	}
	if loaded[0].Sequence != 3 || loaded[1].Sequence != 4 {
		t.Fatalf("unexpected sequences after filter: %#v", loaded)
	}
}

func TestGraphMutationLogCompactThroughSequence(t *testing.T) {
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	for i := 1; i <= 4; i++ {
		if err := log.Append(GraphMutationRecord{
			Sequence:   uint64(i),
			RecordedAt: time.Date(2026, 3, 16, 20, i, 0, 0, time.UTC),
			Type:       GraphMutationRemoveNode,
			NodeID:     "workload:queue",
		}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}

	if err := log.CompactThroughSequence(2); err != nil {
		t.Fatalf("CompactThroughSequence: %v", err)
	}

	loaded, err := log.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("len(loaded) = %d, want 2", len(loaded))
	}
	if loaded[0].Sequence != 3 || loaded[1].Sequence != 4 {
		t.Fatalf("unexpected sequences after compaction: %#v", loaded)
	}
}

func TestGraphMutationLogLoadSequenceWindow(t *testing.T) {
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	for i := 1; i <= 5; i++ {
		if err := log.Append(GraphMutationRecord{
			Sequence:   uint64(i),
			RecordedAt: time.Date(2026, 3, 16, 20, i, 0, 0, time.UTC),
			Type:       GraphMutationRemoveNode,
			NodeID:     "workload:queue",
		}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}

	loaded, err := log.LoadSequenceWindow(2, 4)
	if err != nil {
		t.Fatalf("LoadSequenceWindow: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("len(loaded) = %d, want 2", len(loaded))
	}
	if loaded[0].Sequence != 3 || loaded[1].Sequence != 4 {
		t.Fatalf("unexpected sequences in window: %#v", loaded)
	}
}

func TestGraphMutationLogCompactThroughSequenceRemovesFullyCheckpointedLog(t *testing.T) {
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	if err := log.Append(GraphMutationRecord{
		Sequence:   1,
		RecordedAt: time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
		Type:       GraphMutationRemoveNode,
		NodeID:     "workload:queue",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if err := log.CompactThroughSequence(1); err != nil {
		t.Fatalf("CompactThroughSequence: %v", err)
	}

	loaded, err := log.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("len(loaded) = %d, want 0", len(loaded))
	}
}

func TestGraphMutationLogCheckpointReplayMatchesLiveGraph(t *testing.T) {
	base := New()
	base.AddNode(&Node{
		ID:        "workload:payments",
		Kind:      NodeKindWorkload,
		UpdatedAt: time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
		Version:   1,
	})
	checkpoint := CreateSnapshot(base)
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))

	live := RestoreFromSnapshot(checkpoint)
	queue := &Node{
		ID:        "workload:queue",
		Kind:      NodeKindWorkload,
		UpdatedAt: time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
		Version:   1,
	}
	live.AddNode(queue)
	if err := log.Append(GraphMutationRecord{
		Sequence:   1,
		RecordedAt: time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
		Type:       GraphMutationAddNode,
		Node:       queue,
	}); err != nil {
		t.Fatalf("Append add_node: %v", err)
	}
	if !live.SetNodeProperty("workload:payments", "internet_exposed", true) {
		t.Fatal("SetNodeProperty returned false")
	}
	if err := log.Append(GraphMutationRecord{
		Sequence:      2,
		RecordedAt:    time.Date(2026, 3, 16, 20, 2, 0, 0, time.UTC),
		Type:          GraphMutationSetNodeProperty,
		NodeID:        "workload:payments",
		PropertyKey:   "internet_exposed",
		PropertyValue: true,
	}); err != nil {
		t.Fatalf("Append set_node_property: %v", err)
	}

	replayed := RestoreFromSnapshot(checkpoint)
	records, err := log.LoadAfterSequence(0)
	if err != nil {
		t.Fatalf("LoadAfterSequence: %v", err)
	}
	if err := ReplayGraphMutationRecords(replayed, records); err != nil {
		t.Fatalf("ReplayGraphMutationRecords: %v", err)
	}

	if live.NodeCount() != replayed.NodeCount() {
		t.Fatalf("NodeCount = %d, want %d", replayed.NodeCount(), live.NodeCount())
	}
	node, ok := replayed.GetNode("workload:payments")
	if !ok {
		t.Fatal("expected replayed node to exist")
	}
	if got := node.Properties["internet_exposed"]; got != true {
		t.Fatalf("node.Properties[internet_exposed] = %#v, want true", got)
	}
}

type stubReadCloser struct {
	io.Reader
	closeErr error
}

func (s *stubReadCloser) Close() error {
	return s.closeErr
}

func TestGraphMutationLogRestoreGraphFromSnapshotAtSequence(t *testing.T) {
	base := New()
	user := &Node{
		ID:        "user:payments",
		Kind:      NodeKindUser,
		UpdatedAt: time.Date(2026, 3, 16, 20, 0, 0, 0, time.UTC),
		Version:   1,
	}
	base.AddNode(user)
	checkpoint := CreateSnapshot(base)
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))

	role := &Node{
		ID:        "role:queue",
		Kind:      NodeKindRole,
		UpdatedAt: time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
		Version:   1,
	}
	records := []GraphMutationRecord{
		{
			Sequence:   2,
			RecordedAt: time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node:       role,
		},
		{
			Sequence:      3,
			RecordedAt:    time.Date(2026, 3, 16, 20, 2, 0, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "user:payments",
			PropertyKey:   "internet_exposed",
			PropertyValue: true,
		},
		{
			Sequence:   4,
			RecordedAt: time.Date(2026, 3, 16, 20, 3, 0, 0, time.UTC),
			Type:       GraphMutationAddEdge,
			Edge: &Edge{
				ID:     "edge:payments-queue",
				Source: "user:payments",
				Target: "role:queue",
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
			},
		},
		{
			Sequence:   5,
			RecordedAt: time.Date(2026, 3, 16, 20, 4, 0, 0, time.UTC),
			Type:       GraphMutationRemoveNode,
			NodeID:     "role:queue",
		},
	}
	for _, record := range records {
		if err := log.Append(record); err != nil {
			t.Fatalf("Append(%d): %v", record.Sequence, err)
		}
	}

	recovered, err := log.RestoreGraphFromSnapshot(checkpoint, 1, 4)
	if err != nil {
		t.Fatalf("RestoreGraphFromSnapshot(through=4): %v", err)
	}
	if _, ok := recovered.GetNode("role:queue"); !ok {
		t.Fatal("expected role:queue before sequence 5 removal")
	}
	if got := len(recovered.GetOutEdges("user:payments")); got != 1 {
		t.Fatalf("len(GetOutEdges(user:payments)) = %d, want 1", got)
	}
	paymentsNode, ok := recovered.GetNode("user:payments")
	if !ok {
		t.Fatal("expected user:payments to exist")
	}
	if got := paymentsNode.Properties["internet_exposed"]; got != true {
		t.Fatalf("payments.Properties[internet_exposed] = %#v, want true", got)
	}

	recovered, err = log.RestoreGraphFromSnapshot(checkpoint, 1, 5)
	if err != nil {
		t.Fatalf("RestoreGraphFromSnapshot(through=5): %v", err)
	}
	if _, ok := recovered.GetNode("role:queue"); ok {
		t.Fatal("expected role:queue to be removed by sequence 5")
	}
	if got := len(recovered.GetOutEdges("user:payments")); got != 0 {
		t.Fatalf("len(GetOutEdges(user:payments)) = %d, want 0", got)
	}
}

func TestGraphMutationLogRestoreGraphFromSnapshotRejectsSequenceBeforeCheckpoint(t *testing.T) {
	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	_, err := log.RestoreGraphFromSnapshot(CreateSnapshot(New()), 5, 4)
	if err == nil {
		t.Fatal("expected RestoreGraphFromSnapshot to reject through sequence before checkpoint")
	}
}

func TestGraphMutationLogRestoreGraphFromSnapshotAllowsCheckpointOnlyWithoutLog(t *testing.T) {
	base := New()
	base.AddNode(&Node{ID: "workload:payments", Kind: NodeKindWorkload})
	checkpoint := CreateSnapshot(base)

	recovered, err := (*GraphMutationLog)(nil).RestoreGraphFromSnapshot(checkpoint, 3, 3)
	if err != nil {
		t.Fatalf("RestoreGraphFromSnapshot checkpoint-only: %v", err)
	}
	if recovered.NodeCount() != 1 {
		t.Fatalf("NodeCount = %d, want 1", recovered.NodeCount())
	}
}

func TestGraphMutationLogRestoreGraphFromSnapshotRequiresWALWhenReplayRequested(t *testing.T) {
	base := New()
	base.AddNode(&Node{ID: "workload:payments", Kind: NodeKindWorkload})
	checkpoint := CreateSnapshot(base)

	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	_, err := log.RestoreGraphFromSnapshot(checkpoint, 3, 4)
	if err == nil {
		t.Fatal("expected missing WAL recovery records error")
	}
	if !strings.Contains(err.Error(), "missing recovery records") {
		t.Fatalf("error = %v, want missing recovery records", err)
	}
}

func TestGraphMutationLogRestoreGraphFromSnapshotRejectsIncompleteSequenceWindow(t *testing.T) {
	base := New()
	base.AddNode(&Node{ID: "workload:payments", Kind: NodeKindWorkload})
	checkpoint := CreateSnapshot(base)

	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	if err := log.Append(GraphMutationRecord{
		Sequence:      2,
		RecordedAt:    time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
		Type:          GraphMutationSetNodeProperty,
		NodeID:        "workload:payments",
		PropertyKey:   "state",
		PropertyValue: "warm",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	_, err := log.RestoreGraphFromSnapshot(checkpoint, 1, 3)
	if err == nil {
		t.Fatal("expected incomplete WAL recovery error")
	}
	if !strings.Contains(err.Error(), "missing recovery records") {
		t.Fatalf("error = %v, want missing recovery records", err)
	}
}

func TestGraphMutationLogRestoreGraphFromSnapshotRejectsDuplicateSequenceWindow(t *testing.T) {
	base := New()
	base.AddNode(&Node{ID: "workload:payments", Kind: NodeKindWorkload})
	checkpoint := CreateSnapshot(base)

	log := NewGraphMutationLog(filepath.Join(t.TempDir(), "graph.wal"))
	duplicate := GraphMutationRecord{
		Sequence:      2,
		RecordedAt:    time.Date(2026, 3, 16, 20, 1, 0, 0, time.UTC),
		Type:          GraphMutationSetNodeProperty,
		NodeID:        "workload:payments",
		PropertyKey:   "state",
		PropertyValue: "warm",
	}
	if err := log.Append(duplicate); err != nil {
		t.Fatalf("Append first duplicate: %v", err)
	}
	if err := log.Append(duplicate); err != nil {
		t.Fatalf("Append second duplicate: %v", err)
	}

	_, err := log.RestoreGraphFromSnapshot(checkpoint, 1, 2)
	if err == nil {
		t.Fatal("expected duplicate WAL recovery error")
	}
	if !strings.Contains(err.Error(), "out of order") {
		t.Fatalf("error = %v, want out of order", err)
	}
}

func BenchmarkGraphMutationLogRestoreGraphFromSnapshot(b *testing.B) {
	base := New()
	for i := 0; i < 500; i++ {
		base.AddNode(&Node{
			ID:      "workload:base:" + strconv.Itoa(i),
			Kind:    NodeKindWorkload,
			Version: 1,
		})
	}
	checkpoint := CreateSnapshot(base)
	log := NewGraphMutationLog(filepath.Join(b.TempDir(), "graph.wal"))
	for i := 1; i <= 500; i++ {
		if err := log.Append(GraphMutationRecord{
			Sequence:      uint64(i),
			RecordedAt:    time.Date(2026, 3, 16, 21, 0, i, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "workload:base:" + strconv.Itoa((i-1)%500),
			PropertyKey:   "score",
			PropertyValue: i,
		}); err != nil {
			b.Fatalf("Append(%d): %v", i, err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recovered, err := log.RestoreGraphFromSnapshot(checkpoint, 0, 500)
		if err != nil {
			b.Fatalf("RestoreGraphFromSnapshot: %v", err)
		}
		if recovered.NodeCount() != 500 {
			b.Fatalf("NodeCount = %d, want 500", recovered.NodeCount())
		}
	}
}
