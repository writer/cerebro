package graph

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Snapshot represents a serializable graph snapshot
type Snapshot struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Metadata  Metadata  `json:"metadata"`
	Nodes     []*Node   `json:"nodes"`
	Edges     []*Edge   `json:"edges"`
}

const snapshotVersion = "1.0"

// CreateSnapshot creates a snapshot of the current graph state
func CreateSnapshot(g *Graph) *Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}

	edgeCount := 0
	for _, edgeList := range g.outEdges {
		edgeCount += len(edgeList)
	}
	edges := make([]*Edge, 0, edgeCount)
	for _, edgeList := range g.outEdges {
		edges = append(edges, edgeList...)
	}

	return &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: time.Now(),
		Metadata:  g.metadata,
		Nodes:     nodes,
		Edges:     edges,
	}
}

// RestoreFromSnapshot restores a graph from a snapshot
func RestoreFromSnapshot(snapshot *Snapshot) *Graph {
	g := New()

	for _, node := range snapshot.Nodes {
		g.AddNode(node)
	}

	for _, edge := range snapshot.Edges {
		g.AddEdge(edge)
	}

	g.SetMetadata(snapshot.Metadata)

	return g
}

// SaveToFile saves a snapshot to a compressed file
func (s *Snapshot) SaveToFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.Create(path) // #nosec G304 -- snapshot path is controlled by caller-facing API and intentionally file-system based
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	encoder := json.NewEncoder(gw)
	if err := encoder.Encode(s); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}

	return nil
}

// LoadSnapshotFromFile loads a snapshot from a compressed file
func LoadSnapshotFromFile(path string) (*Snapshot, error) {
	f, err := os.Open(path) // #nosec G304 -- snapshot path is controlled by caller-facing API and intentionally file-system based
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	var snapshot Snapshot
	decoder := json.NewDecoder(gr)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}

	if snapshot.Version != snapshotVersion {
		return nil, fmt.Errorf("incompatible snapshot version: %s (expected %s)", snapshot.Version, snapshotVersion)
	}

	return &snapshot, nil
}

// SnapshotStore manages graph snapshots
type SnapshotStore struct {
	basePath     string
	maxSnapshots int
}

// NewSnapshotStore creates a new snapshot store
func NewSnapshotStore(basePath string, maxSnapshots int) *SnapshotStore {
	if maxSnapshots <= 0 {
		maxSnapshots = 10
	}
	return &SnapshotStore{
		basePath:     basePath,
		maxSnapshots: maxSnapshots,
	}
}

// Save saves a graph snapshot
func (s *SnapshotStore) Save(g *Graph) error {
	snapshot := CreateSnapshot(g)
	filename := fmt.Sprintf("graph-%s.json.gz", snapshot.CreatedAt.Format("20060102-150405"))
	path := filepath.Join(s.basePath, filename)

	if err := snapshot.SaveToFile(path); err != nil {
		return err
	}

	// Clean up old snapshots
	return s.cleanup()
}

// LoadLatest loads the most recent snapshot
func (s *SnapshotStore) LoadLatest() (*Graph, error) {
	files, err := filepath.Glob(filepath.Join(s.basePath, "graph-*.json.gz"))
	if err != nil {
		return nil, fmt.Errorf("glob snapshots: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no snapshots found")
	}

	// Find most recent by filename (sorted by timestamp)
	var latest string
	for _, f := range files {
		if f > latest {
			latest = f
		}
	}

	snapshot, err := LoadSnapshotFromFile(latest)
	if err != nil {
		return nil, err
	}

	return RestoreFromSnapshot(snapshot), nil
}

// List returns all available snapshots
func (s *SnapshotStore) List() ([]SnapshotInfo, error) {
	files, err := filepath.Glob(filepath.Join(s.basePath, "graph-*.json.gz"))
	if err != nil {
		return nil, fmt.Errorf("glob snapshots: %w", err)
	}

	infos := make([]SnapshotInfo, 0, len(files))
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		infos = append(infos, SnapshotInfo{
			Path:      f,
			Filename:  filepath.Base(f),
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
		})
	}

	return infos, nil
}

func (s *SnapshotStore) cleanup() error {
	files, err := filepath.Glob(filepath.Join(s.basePath, "graph-*.json.gz"))
	if err != nil {
		return err
	}

	if len(files) <= s.maxSnapshots {
		return nil
	}

	// Sort ascending (oldest first)
	// Files are named with timestamp, so lexical sort works
	toDelete := len(files) - s.maxSnapshots
	for i := 0; i < toDelete; i++ {
		_ = os.Remove(files[i])
	}

	return nil
}

// SnapshotInfo contains metadata about a snapshot file
type SnapshotInfo struct {
	Path      string    `json:"path"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// ExportJSON exports the graph to a JSON writer (uncompressed)
func ExportJSON(g *Graph, w io.Writer) error {
	snapshot := CreateSnapshot(g)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(snapshot)
}

// ImportJSON imports a graph from a JSON reader
func ImportJSON(r io.Reader) (*Graph, error) {
	var snapshot Snapshot
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, err
	}
	return RestoreFromSnapshot(&snapshot), nil
}
