package graph

import "strings"

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

// MergeEdgeProperties updates one active edge in place by ID, creating the
// properties map if needed. It returns true only when at least one non-empty
// property key was merged onto a matching edge.
func MergeEdgeProperties(g *Graph, edgeID string, properties map[string]any) bool {
	if g == nil {
		return false
	}
	edgeID = strings.TrimSpace(edgeID)
	if edgeID == "" || len(properties) == 0 {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, edges := range g.outEdges {
		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) || edge.ID != edgeID {
				continue
			}
			wasCrossAccount := edge.IsCrossAccount()
			if edge.Properties == nil {
				edge.Properties = make(map[string]any, len(properties))
			}
			changed := false
			for key, value := range properties {
				key = strings.TrimSpace(key)
				if key == "" {
					continue
				}
				edge.Properties[key] = value
				changed = true
			}
			if changed {
				if edge.Version <= 0 {
					edge.Version = 1
				}
				edge.Version++
				if g.crossAccountIndexBuilt {
					isCrossAccount := edge.IsCrossAccount()
					switch {
					case wasCrossAccount && !isCrossAccount:
						g.removeCrossAccountEdgeLocked(edge)
					case !wasCrossAccount && isCrossAccount:
						g.addCrossAccountEdgeLocked(edge)
					}
				}
				g.markGraphEdgeMutationLocked()
			}
			return changed
		}
	}
	return false
}
