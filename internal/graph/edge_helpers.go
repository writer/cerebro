package graph

// AddEdgeIfMissing adds an edge only when both endpoints exist and there is no
// active edge with the same ID or the same source/target/kind tuple already in
// the graph. It returns true only when a new edge is accepted.
func AddEdgeIfMissing(g *Graph, edge *Edge) bool {
	if g == nil || edge == nil || edge.Source == "" || edge.Target == "" {
		return false
	}
	if _, ok := g.GetNode(edge.Source); !ok {
		return false
	}
	if _, ok := g.GetNode(edge.Target); !ok {
		return false
	}
	for _, existing := range g.GetOutEdges(edge.Source) {
		if existing == nil {
			continue
		}
		if existing.ID == edge.ID || (existing.Target == edge.Target && existing.Kind == edge.Kind) {
			return false
		}
	}
	before := len(g.GetOutEdges(edge.Source))
	g.AddEdge(edge)
	return len(g.GetOutEdges(edge.Source)) > before
}
