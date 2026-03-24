package graph

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/metrics"
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
const snapshotStreamVersion = "2.0"
const snapshotStreamMagic = "cerebro_snapshot_stream_v1\n"
const (
	snapshotStreamMaxRecordCount  = 50_000_000
	snapshotStreamPreallocCapHint = 1_000_000
)

type snapshotStreamHeader struct {
	Type      string    `json:"type"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Metadata  Metadata  `json:"metadata"`
	NodeCount int       `json:"node_count"`
	EdgeCount int       `json:"edge_count"`
}

type snapshotStreamNodeRecord struct {
	Type string `json:"type"`
	Node *Node  `json:"node,omitempty"`
}

type snapshotStreamEdgeRecord struct {
	Type string `json:"type"`
	Edge *Edge  `json:"edge,omitempty"`
}

type snapshotStreamFooter struct {
	Type      string `json:"type"`
	NodeCount int    `json:"node_count"`
	EdgeCount int    `json:"edge_count"`
}

type capturedGraphSnapshot struct {
	metadata Metadata
	nodes    []*Node
	edges    []*Edge
}

// snapshotStreamBeforeWriteHook is used by tests to verify that snapshot disk
// I/O happens after the graph read lock has been released.
var snapshotStreamBeforeWriteHook func()

// CreateSnapshot creates a snapshot of the current graph state
func CreateSnapshot(g *Graph) *Snapshot {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphSnapshot("create", time.Since(start))
	}()

	captured := captureGraphSnapshot(g)

	return &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: time.Now(),
		Metadata:  captured.metadata,
		Nodes:     captured.nodes,
		Edges:     captured.edges,
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

	g.restoreSnapshotLocked(snapshot, false)
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
	g.restoreSnapshotLocked(snapshot, true)
	return g
}

func (g *Graph) restoreSnapshotLocked(snapshot *Snapshot, activeOnly bool) {
	if g == nil || snapshot == nil {
		return
	}

	for _, node := range snapshot.Nodes {
		g.restoreSnapshotNodeLocked(node, activeOnly)
	}
	for _, edge := range snapshot.Edges {
		g.restoreSnapshotEdgeLocked(edge, activeOnly)
	}

	g.buildIndexLocked()
	g.metadata = cloneMetadata(snapshot.Metadata)
}

func (g *Graph) restoreSnapshotNodeLocked(node *Node, activeOnly bool) bool {
	if g == nil || node == nil || node.ID == "" {
		return false
	}

	restored := cloneNode(node)
	if activeOnly {
		if restored.DeletedAt != nil {
			return false
		}
		restored.DeletedAt = nil
	}

	normalizeNodeTenantID(restored)
	if !g.applyNodeSchemaValidationLocked(restored) {
		return false
	}
	restored.ordinal = g.internNodeOrdinalLocked(restored.ID)
	hydrateNodeTypedProperties(restored)
	g.bindNodePropertyColumnsLocked(restored)

	if existing := g.nodes[restored.ID]; existing != nil && existing.DeletedAt == nil {
		g.activeNodeCount.Add(-1)
	}
	g.nodes[restored.ID] = restored
	if restored.DeletedAt == nil {
		g.activeNodeCount.Add(1)
	}
	return true
}

func (g *Graph) restoreSnapshotEdgeLocked(edge *Edge, activeOnly bool) bool {
	if g == nil || edge == nil || edge.Source == "" || edge.Target == "" {
		return false
	}

	restored := cloneEdge(edge)
	if activeOnly {
		if restored.DeletedAt != nil {
			return false
		}
		source, ok := g.nodes[restored.Source]
		if !ok || source == nil || source.DeletedAt != nil {
			return false
		}
		target, ok := g.nodes[restored.Target]
		if !ok || target == nil || target.DeletedAt != nil {
			return false
		}
		restored.DeletedAt = nil
	}

	if !g.applyEdgeSchemaValidationLocked(restored) {
		return false
	}
	restored.sourceOrd = g.internNodeOrdinalLocked(restored.Source)
	restored.targetOrd = g.internNodeOrdinalLocked(restored.Target)

	if restored.ID != "" {
		if existing := g.edgeByID[restored.ID]; existing != nil {
			g.outEdges[existing.Source] = removeEdgePointerLocked(g.outEdges[existing.Source], existing)
			if len(g.outEdges[existing.Source]) == 0 {
				delete(g.outEdges, existing.Source)
			}
			g.inEdges[existing.Target] = removeEdgePointerLocked(g.inEdges[existing.Target], existing)
			if len(g.inEdges[existing.Target]) == 0 {
				delete(g.inEdges, existing.Target)
			}
			if g.activeRestoredEdgeLocked(existing) {
				g.activeEdgeCount.Add(-1)
			}
		}
		g.edgeByID[restored.ID] = restored
	}

	g.outEdges[restored.Source] = append(g.outEdges[restored.Source], restored)
	g.inEdges[restored.Target] = append(g.inEdges[restored.Target], restored)
	if g.activeRestoredEdgeLocked(restored) {
		g.activeEdgeCount.Add(1)
	}
	return true
}

func (g *Graph) activeRestoredEdgeLocked(edge *Edge) bool {
	if !g.activeEdgeLocked(edge) {
		return false
	}
	source, ok := g.nodes[edge.Source]
	if !ok || source == nil {
		return false
	}
	target, ok := g.nodes[edge.Target]
	if !ok || target == nil {
		return false
	}
	return true
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

func saveGraphToFile(g *Graph, path string, createdAt time.Time) error {
	if g == nil {
		return fmt.Errorf("graph is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.Create(path) // #nosec G304 -- snapshot path is controlled by caller-facing API and intentionally file-system based
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	if err := writeGraphCompressedSnapshot(g, f, createdAt); err != nil {
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

func writeGraphCompressedSnapshot(g *Graph, w io.Writer, createdAt time.Time) error {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphSnapshot("create", time.Since(start))
	}()

	if g == nil {
		return fmt.Errorf("graph is required")
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	} else {
		createdAt = createdAt.UTC()
	}

	captured := captureGraphSnapshot(g)
	header := snapshotStreamHeader{
		Type:      "header",
		Version:   snapshotStreamVersion,
		CreatedAt: createdAt,
		Metadata:  captured.metadata,
		NodeCount: len(captured.nodes),
		EdgeCount: len(captured.edges),
	}

	if snapshotStreamBeforeWriteHook != nil {
		snapshotStreamBeforeWriteHook()
	}

	return writeCapturedGraphCompressedSnapshot(w, header, captured.nodes, captured.edges)
}

func captureGraphSnapshot(g *Graph) capturedGraphSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edgeCount := 0
	for _, edgeList := range g.outEdges {
		edgeCount += len(edgeList)
	}

	captured := capturedGraphSnapshot{
		metadata: cloneMetadata(g.metadata),
		nodes:    make([]*Node, 0, len(g.nodes)),
		edges:    make([]*Edge, 0, edgeCount),
	}
	for _, node := range g.nodes {
		captured.nodes = append(captured.nodes, cloneNode(node))
	}
	for _, edgeList := range g.outEdges {
		for _, edge := range edgeList {
			captured.edges = append(captured.edges, cloneEdge(edge))
		}
	}

	return captured
}

func writeCapturedGraphCompressedSnapshot(w io.Writer, header snapshotStreamHeader, nodes []*Node, edges []*Edge) error {
	gw := gzip.NewWriter(w)
	if _, err := io.WriteString(gw, snapshotStreamMagic); err != nil {
		_ = gw.Close()
		return fmt.Errorf("write snapshot stream magic: %w", err)
	}
	encoder := json.NewEncoder(gw)
	if err := encoder.Encode(header); err != nil {
		_ = gw.Close()
		return fmt.Errorf("encode snapshot header: %w", err)
	}

	for _, node := range nodes {
		if err := encoder.Encode(snapshotStreamNodeRecord{Type: "node", Node: node}); err != nil {
			_ = gw.Close()
			return fmt.Errorf("encode snapshot node: %w", err)
		}
	}
	for _, edge := range edges {
		if err := encoder.Encode(snapshotStreamEdgeRecord{Type: "edge", Edge: edge}); err != nil {
			_ = gw.Close()
			return fmt.Errorf("encode snapshot edge: %w", err)
		}
	}
	if err := encoder.Encode(snapshotStreamFooter{Type: "footer", NodeCount: header.NodeCount, EdgeCount: header.EdgeCount}); err != nil {
		_ = gw.Close()
		return fmt.Errorf("encode snapshot footer: %w", err)
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

	buffered := bufio.NewReader(gr)
	prefix, err := buffered.Peek(len(snapshotStreamMagic))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, fmt.Errorf("peek snapshot stream magic: %w", err)
	}
	if len(prefix) == len(snapshotStreamMagic) && string(prefix) == snapshotStreamMagic {
		if _, err := buffered.Discard(len(snapshotStreamMagic)); err != nil {
			return nil, fmt.Errorf("discard snapshot stream magic: %w", err)
		}
		return loadSnapshotFromStreamReader(buffered)
	}

	return loadSnapshotFromJSONReader(buffered)
}

func loadSnapshotFromJSONReader(r io.Reader) (*Snapshot, error) {
	var snapshot Snapshot
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}

	if snapshot.Version != snapshotVersion {
		return nil, fmt.Errorf("incompatible snapshot version: %s (expected %s)", snapshot.Version, snapshotVersion)
	}

	return &snapshot, nil
}

func loadSnapshotFromStreamReader(r io.Reader) (*Snapshot, error) {
	decoder := json.NewDecoder(r)

	var header snapshotStreamHeader
	if err := decoder.Decode(&header); err != nil {
		return nil, fmt.Errorf("decode snapshot stream header: %w", err)
	}
	if strings.TrimSpace(header.Type) != "header" {
		return nil, fmt.Errorf("decode snapshot stream header: unexpected record type %q", header.Type)
	}
	if version := strings.TrimSpace(header.Version); version != snapshotStreamVersion {
		return nil, fmt.Errorf("incompatible snapshot stream version: %s (expected %s)", version, snapshotStreamVersion)
	}
	if header.NodeCount < 0 || header.NodeCount > snapshotStreamMaxRecordCount {
		return nil, fmt.Errorf("decode snapshot stream header: invalid node count %d", header.NodeCount)
	}
	if header.EdgeCount < 0 || header.EdgeCount > snapshotStreamMaxRecordCount {
		return nil, fmt.Errorf("decode snapshot stream header: invalid edge count %d", header.EdgeCount)
	}

	snapshot := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: header.CreatedAt.UTC(),
		Metadata:  header.Metadata,
		Nodes:     make([]*Node, 0, min(header.NodeCount, snapshotStreamPreallocCapHint)),
		Edges:     make([]*Edge, 0, min(header.EdgeCount, snapshotStreamPreallocCapHint)),
	}
	if snapshot.Metadata.NodeCount == 0 {
		snapshot.Metadata.NodeCount = header.NodeCount
	}
	if snapshot.Metadata.EdgeCount == 0 {
		snapshot.Metadata.EdgeCount = header.EdgeCount
	}

	for {
		var probe struct {
			Type      string `json:"type"`
			Node      *Node  `json:"node,omitempty"`
			Edge      *Edge  `json:"edge,omitempty"`
			NodeCount int    `json:"node_count,omitempty"`
			EdgeCount int    `json:"edge_count,omitempty"`
		}
		if err := decoder.Decode(&probe); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode snapshot stream record: %w", err)
		}
		switch strings.TrimSpace(probe.Type) {
		case "node":
			snapshot.Nodes = append(snapshot.Nodes, probe.Node)
		case "edge":
			snapshot.Edges = append(snapshot.Edges, probe.Edge)
		case "footer":
			if probe.NodeCount != len(snapshot.Nodes) || probe.EdgeCount != len(snapshot.Edges) {
				return nil, fmt.Errorf("decode snapshot stream footer: count mismatch nodes=%d/%d edges=%d/%d", probe.NodeCount, len(snapshot.Nodes), probe.EdgeCount, len(snapshot.Edges))
			}
			return snapshot, nil
		default:
			return nil, fmt.Errorf("decode snapshot stream record: unexpected record type %q", probe.Type)
		}
	}

	return nil, fmt.Errorf("decode snapshot stream footer: missing footer record")
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
	createdAt := time.Now().UTC()
	filename := fmt.Sprintf("graph-%s.json.gz", createdAt.Format("20060102-150405.000000000"))
	path := filepath.Join(s.basePath, filename)

	if err := saveGraphToFile(g, path, createdAt); err != nil {
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

// DiffByTimeForTenant loads snapshots nearest to the provided timestamps,
// scopes both graphs to one tenant, and computes a structural diff.
func (s *SnapshotStore) DiffByTimeForTenant(t1, t2 time.Time, tenantID string) (*GraphDiff, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return s.DiffByTime(t1, t2)
	}
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

	return diffSnapshotsForTenant(before, after, tenantID), nil
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

func diffSnapshotsForTenant(before, after *Snapshot, tenantID string) *GraphDiff {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return DiffSnapshots(before, after)
	}
	beforeGraph := GraphViewFromSnapshot(before)
	afterGraph := GraphViewFromSnapshot(after)
	if beforeGraph == nil {
		beforeGraph = New()
	}
	if afterGraph == nil {
		afterGraph = New()
	}
	return DiffSnapshots(
		CreateSnapshot(beforeGraph.SubgraphForTenant(tenantID)),
		CreateSnapshot(afterGraph.SubgraphForTenant(tenantID)),
	)
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
	cloned.Properties = cloneNodeProperties(node)
	cloned.PreviousProperties = cloneAnyMap(node.PreviousProperties)
	cloned.PropertyHistory = clonePropertyHistoryMap(node.PropertyHistory)
	cloned.Tags = cloneStringMap(node.Tags)
	cloned.Findings = append([]string(nil), node.Findings...)
	cloned.ordinal = InvalidNodeOrdinal
	cloned.propertyColumns = nil
	cloned.commonProps = nil
	cloned.observationProps = nil
	cloned.attackSequenceProps = nil
	return &cloned
}

func cloneMetadata(meta Metadata) Metadata {
	return Metadata{
		BuiltAt:       meta.BuiltAt,
		NodeCount:     meta.NodeCount,
		EdgeCount:     meta.EdgeCount,
		Providers:     append([]string(nil), meta.Providers...),
		Accounts:      append([]string(nil), meta.Accounts...),
		BuildDuration: meta.BuildDuration,
	}
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
			Deleted:   snapshot.Deleted,
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
