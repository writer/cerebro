package graph

type attackAdjacencySnapshot struct {
	nodeIDs *NodeIDIndex
	offsets []uint32
	targets []NodeOrdinal
	kinds   []EdgeKind
	effects []EdgeEffect
}

func newAttackAdjacencySnapshot(g *Graph, nodeIDs *NodeIDIndex) *attackAdjacencySnapshot {
	if g == nil || nodeIDs == nil {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	counts := make([]uint32, nodeIDs.Len()+2)
	var total uint32

	for sourceID, edges := range g.outEdges {
		var activeCount uint32
		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}
			nodeIDs.Intern(edge.Target)
			activeCount++
		}
		if activeCount == 0 {
			continue
		}
		sourceOrdinal := nodeIDs.Intern(sourceID)
		counts = growAttackAdjacencyCounts(counts, sourceOrdinal)
		counts[sourceOrdinal] += activeCount
		total += activeCount
	}

	offsets := make([]uint32, nodeIDs.Len()+2)
	var running uint32
	for ordinal := 1; ordinal < len(offsets); ordinal++ {
		offsets[ordinal] = running
		if ordinal < len(counts) {
			running += counts[ordinal]
		}
	}

	snapshot := &attackAdjacencySnapshot{
		nodeIDs: nodeIDs,
		offsets: offsets,
		targets: make([]NodeOrdinal, total),
		kinds:   make([]EdgeKind, total),
		effects: make([]EdgeEffect, total),
	}
	cursor := append([]uint32(nil), offsets...)

	for sourceID, edges := range g.outEdges {
		sourceOrdinal, ok := nodeIDs.Lookup(sourceID)
		if !ok || int(sourceOrdinal) >= len(cursor) {
			continue
		}
		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}
			targetOrdinal := nodeIDs.Intern(edge.Target)
			slot := int(cursor[sourceOrdinal])
			if slot < 0 || slot >= len(snapshot.targets) {
				continue
			}
			snapshot.targets[slot] = targetOrdinal
			snapshot.kinds[slot] = edge.Kind
			snapshot.effects[slot] = edge.Effect
			cursor[sourceOrdinal]++
		}
	}

	return snapshot
}

func growAttackAdjacencyCounts(counts []uint32, ordinal NodeOrdinal) []uint32 {
	if ordinal == InvalidNodeOrdinal {
		return counts
	}
	if int(ordinal) < len(counts) {
		return counts
	}
	grown := make([]uint32, int(ordinal)+1)
	copy(grown, counts)
	return grown
}

func (s *attackAdjacencySnapshot) forEachOutEdge(sourceID string, visit func(targetOrdinal NodeOrdinal, targetID string, kind EdgeKind, effect EdgeEffect) bool) {
	if s == nil || s.nodeIDs == nil || visit == nil {
		return
	}
	sourceOrdinal, ok := s.nodeIDs.Lookup(sourceID)
	if !ok {
		return
	}
	start, end, ok := s.edgeRange(sourceOrdinal)
	if !ok {
		return
	}
	for idx := start; idx < end; idx++ {
		targetOrdinal := s.targets[idx]
		targetID, ok := s.nodeIDs.Resolve(targetOrdinal)
		if !ok {
			continue
		}
		if !visit(targetOrdinal, targetID, s.kinds[idx], s.effects[idx]) {
			return
		}
	}
}

func (s *attackAdjacencySnapshot) edgeRange(sourceOrdinal NodeOrdinal) (int, int, bool) {
	if s == nil || sourceOrdinal == InvalidNodeOrdinal {
		return 0, 0, false
	}
	startIndex := int(sourceOrdinal)
	endIndex := startIndex + 1
	if endIndex >= len(s.offsets) {
		return 0, 0, false
	}
	start := int(s.offsets[startIndex])
	end := int(s.offsets[endIndex])
	if start < 0 || end < start || end > len(s.targets) {
		return 0, 0, false
	}
	return start, end, true
}
