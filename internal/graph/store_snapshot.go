package graph

import (
	"context"
	"sync"
)

// SnapshotGraphStore serves graph reads directly from a persisted snapshot.
// It only materializes a full Graph view when a traversal requires graph-native
// algorithms, keeping simple cold-path reads lighter than a full restore.
type SnapshotGraphStore struct {
	snapshot *Snapshot

	indexesOnce sync.Once
	nodeByID    map[string]*Node
	outEdges    map[string][]*Edge
	inEdges     map[string][]*Edge
	nodesByKind map[NodeKind][]*Node
	nodeCount   int
	edgeCount   int

	viewMu sync.Mutex
	view   *Graph
}

var _ GraphStore = (*SnapshotGraphStore)(nil)

// NewSnapshotGraphStore returns a read-only GraphStore backed by snapshot.
func NewSnapshotGraphStore(snapshot *Snapshot) *SnapshotGraphStore {
	return &SnapshotGraphStore{snapshot: snapshot}
}

func (s *SnapshotGraphStore) UpsertNode(ctx context.Context, _ *Node) error {
	return snapshotGraphStoreWriteErr(ctx, s)
}

func (s *SnapshotGraphStore) UpsertNodesBatch(ctx context.Context, _ []*Node) error {
	return snapshotGraphStoreWriteErr(ctx, s)
}

func (s *SnapshotGraphStore) UpsertEdge(ctx context.Context, _ *Edge) error {
	return snapshotGraphStoreWriteErr(ctx, s)
}

func (s *SnapshotGraphStore) UpsertEdgesBatch(ctx context.Context, _ []*Edge) error {
	return snapshotGraphStoreWriteErr(ctx, s)
}

func (s *SnapshotGraphStore) DeleteNode(ctx context.Context, _ string) error {
	return snapshotGraphStoreWriteErr(ctx, s)
}

func (s *SnapshotGraphStore) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.snapshot == nil {
		return nil, false, ErrStoreUnavailable
	}
	s.ensureIndexes()
	node, ok := s.nodeByID[id]
	return node, ok, nil
}

func (s *SnapshotGraphStore) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.snapshot == nil {
		return nil, ErrStoreUnavailable
	}
	s.ensureIndexes()
	return append([]*Edge(nil), s.outEdges[nodeID]...), nil
}

func (s *SnapshotGraphStore) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.snapshot == nil {
		return nil, ErrStoreUnavailable
	}
	s.ensureIndexes()
	return append([]*Edge(nil), s.inEdges[nodeID]...), nil
}

func (s *SnapshotGraphStore) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.snapshot == nil {
		return nil, ErrStoreUnavailable
	}
	s.ensureIndexes()
	nodes := make([]*Node, 0)
	for _, kind := range kinds {
		nodes = append(nodes, s.nodesByKind[kind]...)
	}
	return nodes, nil
}

func (s *SnapshotGraphStore) CountNodes(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.snapshot == nil {
		return 0, ErrStoreUnavailable
	}
	s.ensureIndexes()
	return s.nodeCount, nil
}

func (s *SnapshotGraphStore) CountEdges(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.snapshot == nil {
		return 0, ErrStoreUnavailable
	}
	s.ensureIndexes()
	return s.edgeCount, nil
}

func (s *SnapshotGraphStore) EnsureIndexes(ctx context.Context) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.snapshot == nil {
		return ErrStoreUnavailable
	}
	s.ensureIndexes()
	return nil
}

func (s *SnapshotGraphStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.snapshot == nil {
		return nil, ErrStoreUnavailable
	}
	return s.snapshot, nil
}

func (s *SnapshotGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.BlastRadius(ctx, principalID, maxDepth)
}

func (s *SnapshotGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*ReverseAccessResult, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.ReverseAccess(ctx, resourceID, maxDepth)
}

func (s *SnapshotGraphStore) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*EffectiveAccessResult, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.EffectiveAccess(ctx, principalID, resourceID, maxDepth)
}

func (s *SnapshotGraphStore) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*CascadingBlastRadiusResult, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.CascadingBlastRadius(ctx, sourceID, maxDepth)
}

func (s *SnapshotGraphStore) ExtractSubgraph(ctx context.Context, rootID string, opts ExtractSubgraphOptions) (*Graph, error) {
	view, err := s.viewGraph(ctx)
	if err != nil {
		return nil, err
	}
	return view.ExtractSubgraph(ctx, rootID, opts)
}

func (s *SnapshotGraphStore) ensureIndexes() {
	s.indexesOnce.Do(func() {
		s.nodeByID = make(map[string]*Node)
		s.outEdges = make(map[string][]*Edge)
		s.inEdges = make(map[string][]*Edge)
		s.nodesByKind = make(map[NodeKind][]*Node)
		if s.snapshot == nil {
			return
		}

		for _, node := range s.snapshot.Nodes {
			if node == nil || node.ID == "" || node.DeletedAt != nil {
				continue
			}
			s.nodeByID[node.ID] = node
			s.nodesByKind[node.Kind] = append(s.nodesByKind[node.Kind], node)
		}
		s.nodeCount = len(s.nodeByID)

		for _, edge := range s.snapshot.Edges {
			if edge == nil || edge.Source == "" || edge.Target == "" || edge.DeletedAt != nil {
				continue
			}
			if _, ok := s.nodeByID[edge.Source]; !ok {
				continue
			}
			if _, ok := s.nodeByID[edge.Target]; !ok {
				continue
			}
			s.outEdges[edge.Source] = append(s.outEdges[edge.Source], edge)
			s.inEdges[edge.Target] = append(s.inEdges[edge.Target], edge)
			s.edgeCount++
		}
	})
}

func (s *SnapshotGraphStore) viewGraph(ctx context.Context) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.snapshot == nil {
		return nil, ErrStoreUnavailable
	}
	s.viewMu.Lock()
	defer s.viewMu.Unlock()
	if s.view == nil {
		s.view = GraphViewFromSnapshot(s.snapshot)
	}
	if s.view == nil {
		return nil, ErrStoreUnavailable
	}
	return s.view, nil
}

func snapshotGraphStoreWriteErr(ctx context.Context, s *SnapshotGraphStore) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.snapshot == nil {
		return ErrStoreUnavailable
	}
	return ErrStoreReadOnly
}
