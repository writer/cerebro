package graph

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
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
