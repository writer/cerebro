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

	nodesToCopy := make(map[string]*Node)
	edgesToCopy := make(map[*Edge]struct{})
	clonedNodes := make([]*Node, 0, 16)
	clonedEdges := make([]*Edge, 0, 16)
	seen := newOrdinalVisitSet(nil)
	queue := make([]subgraphQueueItem, 0, 16)
	queueHead := 0

	g.mu.RLock()
	defer g.mu.RUnlock()
	root, ok := g.nodes[rootID]
	if !ok || root == nil || root.DeletedAt != nil {
		return subgraph
	}

	nodesToCopy[rootID] = root
	seen.markOrdinal(root.ordinal)
	queue = append(queue, subgraphQueueItem{nodeID: rootID, depth: 0})

	visitEdges := func(current string, depth int, edges []*Edge, nextNodeID func(*Edge) string) {
		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}
			if opts.EdgeFilter != nil && !opts.EdgeFilter(edge) {
				continue
			}

			neighborID := nextNodeID(edge)
			neighbor, ok := g.nodes[neighborID]
			if !ok || neighbor == nil || neighbor.DeletedAt != nil {
				continue
			}

			if !seen.hasOrdinal(neighbor.ordinal) {
				if depth >= maxDepth || len(nodesToCopy) >= maxNodes {
					continue
				}
				seen.markOrdinal(neighbor.ordinal)
				nodesToCopy[neighborID] = neighbor
				queue = append(queue, subgraphQueueItem{nodeID: neighborID, depth: depth + 1})
			}

			if _, ok := nodesToCopy[neighborID]; ok {
				edgesToCopy[edge] = struct{}{}
			}
		}
	}

	for queueHead < len(queue) {
		item := queue[queueHead]
		queueHead++

		if opts.Direction == ExtractSubgraphDirectionBoth || opts.Direction == ExtractSubgraphDirectionOutgoing {
			visitEdges(item.nodeID, item.depth, g.outEdges[item.nodeID], func(edge *Edge) string {
				return edge.Target
			})
		}
		if opts.Direction == ExtractSubgraphDirectionBoth || opts.Direction == ExtractSubgraphDirectionIncoming {
			visitEdges(item.nodeID, item.depth, g.inEdges[item.nodeID], func(edge *Edge) string {
				return edge.Source
			})
		}
	}

	for _, node := range nodesToCopy {
		clonedNodes = append(clonedNodes, cloneNode(node))
	}
	for edge := range edgesToCopy {
		clonedEdges = append(clonedEdges, cloneEdge(edge))
	}

	for _, node := range clonedNodes {
		subgraph.AddNode(node)
	}
	for _, edge := range clonedEdges {
		subgraph.AddEdge(edge)
	}
	return subgraph
}
