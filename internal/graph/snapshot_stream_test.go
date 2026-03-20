package graph

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadSnapshotFromFileSupportsLegacyArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-snapshot.json.gz")
	createdAt := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	snapshot := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: createdAt,
		Metadata: Metadata{
			NodeCount: 1,
			EdgeCount: 0,
			Providers: []string{"aws"},
			Accounts:  []string{"123456789012"},
		},
		Nodes: []*Node{{ID: "workload:legacy", Kind: NodeKindWorkload}},
	}

	if err := snapshot.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	loaded, err := LoadSnapshotFromFile(path)
	if err != nil {
		t.Fatalf("LoadSnapshotFromFile: %v", err)
	}
	if loaded.Version != snapshotVersion {
		t.Fatalf("Version = %q, want %q", loaded.Version, snapshotVersion)
	}
	if !loaded.CreatedAt.Equal(createdAt) {
		t.Fatalf("CreatedAt = %s, want %s", loaded.CreatedAt, createdAt)
	}
	if len(loaded.Nodes) != 1 || loaded.Nodes[0] == nil || loaded.Nodes[0].ID != "workload:legacy" {
		t.Fatalf("loaded nodes = %#v, want legacy node", loaded.Nodes)
	}
}

func TestSnapshotStoreSaveGraphWritesStreamingArtifacts(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "workload:root", Kind: NodeKindWorkload})
	g.AddNode(&Node{ID: "bucket:child", Kind: NodeKindBucket})
	g.AddEdge(&Edge{ID: "root-child", Source: "workload:root", Target: "bucket:child", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	store := NewSnapshotStore(t.TempDir(), 2)
	record, _, err := store.SaveGraph(g)
	if err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}
	if record == nil {
		t.Fatal("expected snapshot record")
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}

	file, err := os.Open(records[0].Path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	magic, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if magic != snapshotStreamMagic {
		t.Fatalf("stream magic = %q, want %q", magic, snapshotStreamMagic)
	}

	loaded, err := LoadSnapshotFromFile(records[0].Path)
	if err != nil {
		t.Fatalf("LoadSnapshotFromFile: %v", err)
	}
	if len(loaded.Nodes) != 2 {
		t.Fatalf("len(nodes) = %d, want 2", len(loaded.Nodes))
	}
	if len(loaded.Edges) != 1 {
		t.Fatalf("len(edges) = %d, want 1", len(loaded.Edges))
	}
	if loaded.Metadata.NodeCount != 2 || loaded.Metadata.EdgeCount != 1 {
		t.Fatalf("metadata counts = %#v, want nodes=2 edges=1", loaded.Metadata)
	}
}

func TestLoadSnapshotFromFileRejectsStreamingArtifactsWithoutFooter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "truncated-stream.json.gz")
	err := writeRawCompressedSnapshotFile(path, []any{
		snapshotStreamHeader{
			Type:      "header",
			Version:   snapshotStreamVersion,
			CreatedAt: time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC),
			Metadata:  Metadata{NodeCount: 1},
			NodeCount: 1,
			EdgeCount: 0,
		},
		snapshotStreamNodeRecord{
			Type: "node",
			Node: &Node{ID: "workload:root", Kind: NodeKindWorkload},
		},
	})
	if err != nil {
		t.Fatalf("writeRawCompressedSnapshotFile: %v", err)
	}

	_, err = LoadSnapshotFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "missing footer record") {
		t.Fatalf("LoadSnapshotFromFile() error = %v, want missing footer record", err)
	}
}

func TestLoadSnapshotFromFileRejectsOversizedStreamingHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-stream.json.gz")
	err := writeRawCompressedSnapshotFile(path, []any{
		snapshotStreamHeader{
			Type:      "header",
			Version:   snapshotStreamVersion,
			CreatedAt: time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC),
			NodeCount: snapshotStreamMaxRecordCount + 1,
			EdgeCount: 0,
		},
		snapshotStreamFooter{Type: "footer", NodeCount: 0, EdgeCount: 0},
	})
	if err != nil {
		t.Fatalf("writeRawCompressedSnapshotFile: %v", err)
	}

	_, err = LoadSnapshotFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "invalid node count") {
		t.Fatalf("LoadSnapshotFromFile() error = %v, want invalid node count", err)
	}
}

func TestWriteGraphCompressedSnapshotReleasesGraphLockBeforeIO(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "workload:root", Kind: NodeKindWorkload})

	started := make(chan struct{})
	release := make(chan struct{})
	snapshotStreamBeforeWriteHook = func() {
		close(started)
		<-release
	}
	t.Cleanup(func() { snapshotStreamBeforeWriteHook = nil })

	var buf bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeGraphCompressedSnapshot(g, &buf, time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC))
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot writer did not reach pre-write hook")
	}

	addDone := make(chan struct{})
	go func() {
		g.AddNode(&Node{ID: "workload:late", Kind: NodeKindWorkload})
		close(addDone)
	}()

	select {
	case <-addDone:
	case <-time.After(2 * time.Second):
		t.Fatal("AddNode blocked while snapshot writer was paused before I/O")
	}

	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("writeGraphCompressedSnapshot: %v", err)
	}

	loaded, err := loadSnapshotFromCompressedReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("loadSnapshotFromCompressedReader: %v", err)
	}
	for _, node := range loaded.Nodes {
		if node != nil && node.ID == "workload:late" {
			t.Fatalf("snapshot unexpectedly included node added after capture: %#v", node)
		}
	}
}

func BenchmarkSnapshotCompressedWrite(b *testing.B) {
	g := RestoreFromSnapshot(benchmarkGraphSnapshot(2000, 4000))
	createdAt := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	b.Run("legacy_monolithic", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			snapshot := CreateSnapshot(g)
			if err := snapshot.writeCompressed(io.Discard); err != nil {
				b.Fatalf("writeCompressed: %v", err)
			}
		}
	})

	b.Run("streaming_graph", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := writeGraphCompressedSnapshot(g, io.Discard, createdAt); err != nil {
				b.Fatalf("writeGraphCompressedSnapshot: %v", err)
			}
		}
	})
}

func writeRawCompressedSnapshotFile(path string, records []any) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	writer := gzip.NewWriter(file)
	if _, err := io.WriteString(writer, snapshotStreamMagic); err != nil {
		_ = writer.Close()
		return err
	}
	encoder := json.NewEncoder(writer)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			_ = writer.Close()
			return err
		}
	}
	return writer.Close()
}
