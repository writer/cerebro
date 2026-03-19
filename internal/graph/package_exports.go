package graph

import "time"

// GetNodeBitemporal exposes one stable bitemporal node lookup without leaking graph internals.

func (g *Graph) GetNodeBitemporal(nodeID string, validAt, recordedAt time.Time) (*Node, bool) {
	if g == nil {
		return nil, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, ok := g.nodes[nodeID]
	if !ok || node == nil || node.DeletedAt != nil {
		return nil, false
	}
	if !g.nodeVisibleAtLocked(node, validAt, recordedAt) {
		return nil, false
	}
	return node, true
}
