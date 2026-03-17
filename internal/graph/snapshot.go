package graph

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
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
	start := time.Now()
	defer func() {
		metrics.ObserveGraphSnapshot("create", time.Since(start))
	}()

	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, cloneNode(n))
	}

	edgeCount := 0
	for _, edgeList := range g.outEdges {
		edgeCount += len(edgeList)
	}
	edges := make([]*Edge, 0, edgeCount)
	for _, edgeList := range g.outEdges {
		for _, edge := range edgeList {
			edges = append(edges, cloneEdge(edge))
		}
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
	start := time.Now()
	defer func() {
		metrics.ObserveGraphSnapshot("restore", time.Since(start))
	}()

	g := New()
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, node := range snapshot.Nodes {
		if node == nil || node.ID == "" {
			continue
		}
		g.addNodeLocked(node)
	}

	for _, edge := range snapshot.Edges {
		if edge == nil || edge.Source == "" || edge.Target == "" {
			continue
		}
		g.addEdgeLocked(edge)
	}

	g.metadata = snapshot.Metadata

	return g
}

// GraphViewFromSnapshot restores the active portion of a snapshot into a graph
// view suitable for read/query flows. Deleted nodes and edges are excluded.
func GraphViewFromSnapshot(snapshot *Snapshot) *Graph {
	if snapshot == nil {
		return nil
	}
	g := New()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, node := range snapshot.Nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		cloned := cloneNode(node)
		cloned.DeletedAt = nil
		g.addNodeLocked(cloned)
	}
	for _, edge := range snapshot.Edges {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		if source, ok := g.nodes[edge.Source]; !ok || source == nil || source.DeletedAt != nil {
			continue
		}
		if target, ok := g.nodes[edge.Target]; !ok || target == nil || target.DeletedAt != nil {
			continue
		}
		cloned := cloneEdge(edge)
		cloned.DeletedAt = nil
		g.addEdgeLocked(cloned)
	}
	g.metadata = snapshot.Metadata
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

	if err := s.writeCompressed(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close snapshot file: %w", err)
	}
	return nil
}

func (s *Snapshot) writeCompressed(w io.Writer) error {
	gw := gzip.NewWriter(w)
	encoder := json.NewEncoder(gw)
	if err := encoder.Encode(s); err != nil {
		_ = gw.Close()
		return fmt.Errorf("encode snapshot: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close compressed snapshot: %w", err)
	}
	return nil
}

func loadSnapshotFromCompressedReader(r io.Reader) (*Snapshot, error) {
	gr, err := gzip.NewReader(bufio.NewReader(r))
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

// LoadSnapshotFromFile loads a snapshot from a compressed file
func LoadSnapshotFromFile(path string) (*Snapshot, error) {
	f, err := os.Open(path) // #nosec G304 -- snapshot path is controlled by caller-facing API and intentionally file-system based
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	return loadSnapshotFromCompressedReader(f)
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
	_, _, err := s.SaveGraph(g)
	return err
}

// SaveGraph saves a graph snapshot and returns the typed snapshot record and
// manifest generated for the newest retained artifact.
func (s *SnapshotStore) SaveGraph(g *Graph) (*GraphSnapshotRecord, *GraphSnapshotManifest, error) {
	snapshot := CreateSnapshot(g)
	filename := fmt.Sprintf("graph-%s.json.gz", snapshot.CreatedAt.Format("20060102-150405.000000000"))
	path := filepath.Join(s.basePath, filename)

	if err := snapshot.SaveToFile(path); err != nil {
		return nil, nil, err
	}
	if info, err := os.Stat(path); err == nil {
		metrics.SetGraphSnapshotSizeBytes(info.Size())
	}

	// Clean up old snapshots
	if err := s.cleanup(); err != nil {
		return nil, nil, err
	}
	index, err := s.rebuildSnapshotIndex(nil)
	if err != nil {
		return nil, nil, err
	}
	if index == nil || len(index.Snapshots) == 0 {
		return nil, nil, fmt.Errorf("snapshot index missing saved record")
	}
	manifest := index.Snapshots[len(index.Snapshots)-1]
	record := manifest.Record
	return &record, &manifest, nil
}

// LoadLatest loads the most recent snapshot
func (s *SnapshotStore) LoadLatest() (*Graph, error) {
	snapshot, _, err := s.LoadLatestSnapshot()
	if err != nil {
		return nil, err
	}

	return RestoreFromSnapshot(snapshot), nil
}

// LoadLatestSnapshot loads the newest retained snapshot and its typed record.
func (s *SnapshotStore) LoadLatestSnapshot() (*Snapshot, *GraphSnapshotRecord, error) {
	index, err := s.loadOrRebuildSnapshotIndex()
	if err != nil {
		return nil, nil, err
	}
	if index == nil || len(index.Snapshots) == 0 {
		return nil, nil, fmt.Errorf("no snapshots found")
	}
	manifest := index.Snapshots[len(index.Snapshots)-1]
	path := manifest.ArtifactPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.basePath, path)
	}
	snapshot, err := LoadSnapshotFromFile(path)
	if err != nil {
		return nil, nil, err
	}
	record := manifest.Record
	return snapshot, &record, nil
}

func (s *SnapshotStore) BasePath() string {
	if s == nil {
		return ""
	}
	return s.basePath
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

// ListGraphSnapshotRecords returns typed graph snapshot records for file-backed snapshot artifacts.
func (s *SnapshotStore) ListGraphSnapshotRecords() ([]GraphSnapshotRecord, error) {
	index, err := s.loadOrRebuildSnapshotIndex()
	if err != nil {
		return nil, err
	}
	records := make([]GraphSnapshotRecord, 0, len(index.Snapshots))
	for _, manifest := range index.Snapshots {
		record := manifest.Record
		records = append(records, record)
	}
	return records, nil
}

// LoadSnapshotsByRecordIDs loads one or more file-backed graph snapshots by typed snapshot record ID in a single store scan.
func (s *SnapshotStore) LoadSnapshotsByRecordIDs(snapshotIDs ...string) (map[string]*Snapshot, map[string]*GraphSnapshotRecord, error) {
	requested := make(map[string]struct{}, len(snapshotIDs))
	for _, snapshotID := range snapshotIDs {
		snapshotID = strings.TrimSpace(snapshotID)
		if snapshotID != "" {
			requested[snapshotID] = struct{}{}
		}
	}
	if len(requested) == 0 {
		return nil, nil, fmt.Errorf("at least one snapshot id required")
	}

	index, err := s.loadOrRebuildSnapshotIndex()
	if err != nil {
		return nil, nil, err
	}

	snapshots := make(map[string]*Snapshot, len(requested))
	records := make(map[string]*GraphSnapshotRecord, len(requested))
	for _, manifest := range index.Snapshots {
		if len(records) == len(requested) {
			break
		}
		recordID := strings.TrimSpace(manifest.Record.ID)
		if _, ok := requested[recordID]; !ok {
			continue
		}
		path := manifest.ArtifactPath
		if !filepath.IsAbs(path) {
			path = filepath.Join(s.basePath, path)
		}
		snapshot, err := LoadSnapshotFromFile(path)
		if err != nil {
			return nil, nil, err
		}
		record := manifest.Record
		snapshots[recordID] = snapshot
		recordCopy := record
		records[recordID] = &recordCopy
	}

	for snapshotID := range requested {
		if _, ok := snapshots[snapshotID]; !ok {
			return nil, nil, fmt.Errorf("snapshot %q not found", snapshotID)
		}
	}

	return snapshots, records, nil
}

// LoadSnapshotByRecordID loads one file-backed graph snapshot by its typed snapshot record ID.
func (s *SnapshotStore) LoadSnapshotByRecordID(snapshotID string) (*Snapshot, *GraphSnapshotRecord, error) {
	snapshotID = strings.TrimSpace(snapshotID)
	if snapshotID == "" {
		return nil, nil, fmt.Errorf("snapshot id required")
	}
	snapshots, records, err := s.LoadSnapshotsByRecordIDs(snapshotID)
	if err != nil {
		return nil, nil, err
	}
	return snapshots[snapshotID], records[snapshotID], nil
}

// DiffByTime loads snapshots nearest to the provided timestamps and computes a structural diff.
func (s *SnapshotStore) DiffByTime(t1, t2 time.Time) (*GraphDiff, error) {
	if t1.IsZero() || t2.IsZero() {
		return nil, fmt.Errorf("both timestamps are required")
	}
	from := t1
	to := t2
	if from.After(to) {
		from, to = to, from
	}

	before, err := s.loadClosestSnapshotAt(from)
	if err != nil {
		return nil, err
	}
	after, err := s.loadClosestSnapshotAt(to)
	if err != nil {
		return nil, err
	}

	return DiffSnapshots(before, after), nil
}

func (s *SnapshotStore) loadClosestSnapshotAt(ts time.Time) (*Snapshot, error) {
	files, err := filepath.Glob(filepath.Join(s.basePath, "graph-*.json.gz"))
	if err != nil {
		return nil, fmt.Errorf("glob snapshots: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no snapshots found")
	}

	var closestBefore *Snapshot
	var closestAfter *Snapshot
	for _, file := range files {
		snapshot, err := LoadSnapshotFromFile(file)
		if err != nil {
			continue
		}
		if snapshot.CreatedAt.IsZero() {
			info, statErr := os.Stat(file)
			if statErr == nil {
				snapshot.CreatedAt = info.ModTime()
			}
		}

		switch {
		case !snapshot.CreatedAt.After(ts):
			if closestBefore == nil || snapshot.CreatedAt.After(closestBefore.CreatedAt) {
				closestBefore = snapshot
			}
		default:
			if closestAfter == nil || snapshot.CreatedAt.Before(closestAfter.CreatedAt) {
				closestAfter = snapshot
			}
		}
	}

	if closestBefore != nil {
		return closestBefore, nil
	}
	if closestAfter != nil {
		return closestAfter, nil
	}
	return nil, fmt.Errorf("no readable snapshots found")
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

func cloneNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	cloned := *node
	cloned.Properties = cloneAnyMap(node.Properties)
	cloned.PreviousProperties = cloneAnyMap(node.PreviousProperties)
	cloned.PropertyHistory = clonePropertyHistoryMap(node.PropertyHistory)
	cloned.Tags = cloneStringMap(node.Tags)
	cloned.Findings = append([]string(nil), node.Findings...)
	return &cloned
}

func cloneEdge(edge *Edge) *Edge {
	if edge == nil {
		return nil
	}
	cloned := *edge
	cloned.Properties = cloneAnyMap(edge.Properties)
	return &cloned
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = cloneAny(value)
	}
	return cloned
}

func buildGraphSnapshotRecordFromSnapshot(snapshot *Snapshot, info SnapshotInfo) *GraphSnapshotRecord {
	if snapshot == nil {
		return nil
	}
	record := &GraphSnapshotRecord{
		ID:                      buildSnapshotRecordID(snapshot),
		Materialized:            true,
		Diffable:                true,
		StorageClass:            graphSnapshotStorageLocalStore,
		RetentionClass:          graphSnapshotRetentionLocal,
		ByteSize:                info.Size,
		NodeCount:               snapshot.Metadata.NodeCount,
		EdgeCount:               snapshot.Metadata.EdgeCount,
		Providers:               append([]string(nil), snapshot.Metadata.Providers...),
		Accounts:                append([]string(nil), snapshot.Metadata.Accounts...),
		BuildDurationMS:         snapshot.Metadata.BuildDuration.Milliseconds(),
		GraphSchemaVersion:      SchemaVersion(),
		OntologyContractVersion: GraphOntologyContractVersion,
	}
	if record.ID == "" {
		return nil
	}
	if !snapshot.Metadata.BuiltAt.IsZero() {
		builtAt := snapshot.Metadata.BuiltAt.UTC()
		record.BuiltAt = &builtAt
	}
	capturedAt := snapshot.CreatedAt
	if capturedAt.IsZero() {
		capturedAt = info.CreatedAt
	}
	if !capturedAt.IsZero() {
		capturedAt = capturedAt.UTC()
		record.CapturedAt = &capturedAt
	}
	if record.NodeCount == 0 {
		record.NodeCount = len(snapshot.Nodes)
	}
	if record.EdgeCount == 0 {
		record.EdgeCount = len(snapshot.Edges)
	}
	return record
}

func buildSnapshotRecordID(snapshot *Snapshot) string {
	if snapshot == nil {
		return ""
	}
	if id := buildReportGraphSnapshotID(snapshot.Metadata); id != "" {
		return id
	}
	payload := fmt.Sprintf("%s|%d|%d|%d|%d",
		snapshot.CreatedAt.UTC().Format(time.RFC3339Nano),
		len(snapshot.Nodes),
		len(snapshot.Edges),
		snapshot.Metadata.NodeCount,
		snapshot.Metadata.EdgeCount,
	)
	sum := sha256.Sum256([]byte(payload))
	return "graph_snapshot_artifact:" + hex.EncodeToString(sum[:12])
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func clonePropertyHistoryMap(values map[string][]PropertySnapshot) map[string][]PropertySnapshot {
	if values == nil {
		return nil
	}
	cloned := make(map[string][]PropertySnapshot, len(values))
	for property, history := range values {
		cloned[property] = clonePropertySnapshots(history)
	}
	return cloned
}

func clonePropertySnapshots(history []PropertySnapshot) []PropertySnapshot {
	if history == nil {
		return nil
	}
	cloned := make([]PropertySnapshot, len(history))
	for i, snapshot := range history {
		cloned[i] = PropertySnapshot{
			Timestamp: snapshot.Timestamp,
			Value:     cloneAny(snapshot.Value),
		}
	}
	return cloned
}

func cloneAny(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneAnyMap(v)
	case []any:
		cloned := make([]any, len(v))
		for i := range v {
			cloned[i] = cloneAny(v[i])
		}
		return cloned
	case []string:
		return append([]string(nil), v...)
	default:
		return value
	}
}
