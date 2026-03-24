package graph

type ExtractSubgraphDirection int

const (
	ExtractSubgraphDirectionBoth ExtractSubgraphDirection = iota
	ExtractSubgraphDirectionOutgoing
	ExtractSubgraphDirectionIncoming
)

type ExtractSubgraphOptions struct {
	MaxDepth   int
	MaxNodes   int
	Direction  ExtractSubgraphDirection
	EdgeFilter func(*Edge) bool
}

type subgraphQueueItem struct {
	nodeID string
	depth  int
}

const defaultExtractSubgraphMaxDepth = 6

// ExtractSubgraph returns a detached graph containing the bounded neighborhood
// around rootID. Nodes and edges are deep-cloned so later parent-graph
// mutations do not affect the extracted result.
func ExtractSubgraph(g *Graph, rootID string, opts ExtractSubgraphOptions) *Graph {
	subgraph := New()
	if g == nil {
		return subgraph
	}

	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultExtractSubgraphMaxDepth
	}
	maxNodes := opts.MaxNodes
	if maxNodes <= 0 {
		maxNodes = int(^uint(0) >> 1)
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	root, ok := g.nodes[rootID]
	if !ok || root == nil || root.DeletedAt != nil {
		return subgraph
	}

	snapshot := g.csrEdges
	if snapshot == nil {
		snapshot = newCSREdgeSnapshotLocked(g)
	}
	if snapshot == nil {
		return subgraph
	}

	traverser := ParallelTraverser{
		MaxDepth:  maxDepth,
		Direction: parallelTraversalDirectionForExtract(opts.Direction),
		Filter: func(edge *Edge, current *Node, next *Node, currentOrdinal, nextOrdinal NodeOrdinal, depth int) bool {
			if edge == nil || !g.activeEdgeLocked(edge) {
				return false
			}
			if opts.EdgeFilter != nil && !opts.EdgeFilter(edge) {
				return false
			}
			return true
		},
	}
	// Preserve the existing callback contract for EdgeFilter callers by keeping
	// the traversal single-threaded whenever a filter function is present.
	if opts.EdgeFilter != nil {
		traverser.Workers = 1
	}

	result := traverser.traverseSnapshot(g, snapshot, rootID)
	if len(result.Visits) == 0 {
		return subgraph
	}
	if len(result.Visits) > maxNodes {
		result.Visits = result.Visits[:maxNodes]
	}

	nodesToCopy := make(map[string]*Node, len(result.Visits))
	retainedOrdinals := make(map[NodeOrdinal]struct{}, len(result.Visits))
	for _, visit := range result.Visits {
		if visit.Node == nil || visit.Node.DeletedAt != nil {
			continue
		}
		nodesToCopy[visit.NodeID] = visit.Node
		retainedOrdinals[visit.Ordinal] = struct{}{}
	}
	if len(nodesToCopy) == 0 {
		return subgraph
	}

	edgesToCopy := make(map[*Edge]struct{})
	for _, visit := range result.Visits {
		if _, ok := retainedOrdinals[visit.Ordinal]; !ok {
			continue
		}
		if opts.Direction == ExtractSubgraphDirectionBoth || opts.Direction == ExtractSubgraphDirectionOutgoing {
			snapshot.forEachOutEdgeOrdinal(visit.Ordinal, func(edge *Edge, nextOrdinal NodeOrdinal, _ string) bool {
				if _, ok := retainedOrdinals[nextOrdinal]; !ok {
					return true
				}
				if opts.EdgeFilter != nil && !opts.EdgeFilter(edge) {
					return true
				}
				edgesToCopy[edge] = struct{}{}
				return true
			})
		}
		if opts.Direction == ExtractSubgraphDirectionBoth || opts.Direction == ExtractSubgraphDirectionIncoming {
			snapshot.forEachInEdgeOrdinal(visit.Ordinal, func(edge *Edge, nextOrdinal NodeOrdinal, _ string) bool {
				if _, ok := retainedOrdinals[nextOrdinal]; !ok {
					return true
				}
				if opts.EdgeFilter != nil && !opts.EdgeFilter(edge) {
					return true
				}
				edgesToCopy[edge] = struct{}{}
				return true
			})
		}
	}

	for _, node := range nodesToCopy {
		subgraph.AddNode(cloneNode(node))
	}
	for edge := range edgesToCopy {
		subgraph.AddEdge(cloneEdge(edge))
	}
	return subgraph
}

func parallelTraversalDirectionForExtract(direction ExtractSubgraphDirection) ParallelTraversalDirection {
	switch direction {
	case ExtractSubgraphDirectionOutgoing:
		return ParallelTraversalDirectionOutgoing
	case ExtractSubgraphDirectionIncoming:
		return ParallelTraversalDirectionIncoming
	default:
		return ParallelTraversalDirectionBoth
	}
}
