package graph

func forkGraphForMutation(g *Graph) *Graph {
	if g == nil {
		return nil
	}

	fork := &Graph{
		nodes:                     g.nodes,
		outEdges:                  g.outEdges,
		inEdges:                   g.inEdges,
		edgeByID:                  g.edgeByID,
		metadata:                  cloneMetadata(g.metadata),
		blastRadiusVersion:        g.blastRadiusVersion,
		schemaValidationMode:      g.schemaValidationMode,
		schemaValidationStats:     cloneSchemaValidationStats(g.schemaValidationStats),
		temporalHistoryMaxEntries: g.temporalHistoryMaxEntries,
		temporalHistoryTTL:        g.temporalHistoryTTL,
		sharedNodes:               shareNodeIDs(g.nodes),
		sharedEdges:               shareEdgePointers(g),
		sharedOutEdgeBuckets:      shareEdgeBucketKeys(g.outEdges),
		sharedInEdgeBuckets:       shareEdgeBucketKeys(g.inEdges),
		nodesShared:               true,
		outEdgesShared:            true,
		inEdgesShared:             true,
		edgeByIDShared:            true,
	}
	fork.activeNodeCount.Store(g.activeNodeCount.Load())
	fork.activeEdgeCount.Store(g.activeEdgeCount.Load())
	return fork
}

func shareNodeIDs(values map[string]*Node) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	shared := make(map[string]struct{}, len(values))
	for id := range values {
		shared[id] = struct{}{}
	}
	return shared
}

func shareEdgeBucketKeys(values map[string][]*Edge) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	shared := make(map[string]struct{}, len(values))
	for key := range values {
		shared[key] = struct{}{}
	}
	return shared
}

func shareEdgePointers(g *Graph) map[*Edge]struct{} {
	if g == nil {
		return nil
	}
	shared := make(map[*Edge]struct{}, len(g.edgeByID))
	for _, edge := range g.edgeByID {
		if edge != nil {
			shared[edge] = struct{}{}
		}
	}
	for _, edges := range g.outEdges {
		for _, edge := range edges {
			if edge != nil {
				shared[edge] = struct{}{}
			}
		}
	}
	return shared
}

func (g *Graph) detachNodesMapLocked() {
	if g == nil || !g.nodesShared {
		return
	}
	cloned := make(map[string]*Node, len(g.nodes))
	for id, node := range g.nodes {
		cloned[id] = node
	}
	g.nodes = cloned
	g.nodesShared = false
}

func (g *Graph) detachOutEdgesMapLocked() {
	if g == nil || !g.outEdgesShared {
		return
	}
	cloned := make(map[string][]*Edge, len(g.outEdges))
	for id, edges := range g.outEdges {
		cloned[id] = edges
	}
	g.outEdges = cloned
	g.outEdgesShared = false
}

func (g *Graph) detachInEdgesMapLocked() {
	if g == nil || !g.inEdgesShared {
		return
	}
	cloned := make(map[string][]*Edge, len(g.inEdges))
	for id, edges := range g.inEdges {
		cloned[id] = edges
	}
	g.inEdges = cloned
	g.inEdgesShared = false
}

func (g *Graph) detachEdgeByIDMapLocked() {
	if g == nil || !g.edgeByIDShared {
		return
	}
	cloned := make(map[string]*Edge, len(g.edgeByID))
	for id, edge := range g.edgeByID {
		cloned[id] = edge
	}
	g.edgeByID = cloned
	g.edgeByIDShared = false
}

func (g *Graph) detachOutBucketLocked(nodeID string) {
	if g == nil {
		return
	}
	g.detachOutEdgesMapLocked()
	if _, ok := g.sharedOutEdgeBuckets[nodeID]; !ok {
		return
	}
	edges := g.outEdges[nodeID]
	if edges != nil {
		g.outEdges[nodeID] = append([]*Edge(nil), edges...)
	}
	delete(g.sharedOutEdgeBuckets, nodeID)
}

func (g *Graph) detachInBucketLocked(nodeID string) {
	if g == nil {
		return
	}
	g.detachInEdgesMapLocked()
	if _, ok := g.sharedInEdgeBuckets[nodeID]; !ok {
		return
	}
	edges := g.inEdges[nodeID]
	if edges != nil {
		g.inEdges[nodeID] = append([]*Edge(nil), edges...)
	}
	delete(g.sharedInEdgeBuckets, nodeID)
}

func (g *Graph) ensureWritableNodeLocked(id string) *Node {
	if g == nil {
		return nil
	}
	node := g.nodes[id]
	if node == nil {
		return nil
	}
	if _, ok := g.sharedNodes[id]; !ok {
		return node
	}
	g.detachNodesMapLocked()
	cloned := cloneNodeForGraphClone(node)
	g.nodes[id] = cloned
	delete(g.sharedNodes, id)
	return cloned
}

func (g *Graph) ensureWritableEdgeLocked(edge *Edge) *Edge {
	if g == nil || edge == nil {
		return edge
	}
	if _, ok := g.sharedEdges[edge]; !ok {
		return edge
	}

	cloned := cloneEdge(edge)
	g.detachOutBucketLocked(edge.Source)
	replaceEdgePointerInBucketLocked(g.outEdges[edge.Source], edge, cloned)
	g.detachInBucketLocked(edge.Target)
	replaceEdgePointerInBucketLocked(g.inEdges[edge.Target], edge, cloned)
	if edge.ID != "" && g.edgeByID[edge.ID] == edge {
		g.detachEdgeByIDMapLocked()
		g.edgeByID[edge.ID] = cloned
	}
	delete(g.sharedEdges, edge)
	return cloned
}

func replaceEdgePointerInBucketLocked(edges []*Edge, current *Edge, next *Edge) {
	for i, edge := range edges {
		if edge == current {
			edges[i] = next
		}
	}
}
