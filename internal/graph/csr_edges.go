package graph

type csrEdgeSnapshot struct {
	nodeIDs *NodeIDIndex

	outOffsets  []uint32
	outOrdinals []NodeOrdinal
	outEdges    []*Edge

	inOffsets  []uint32
	inOrdinals []NodeOrdinal
	inEdges    []*Edge

	denyPairs map[uint64]struct{}
}

func (g *Graph) csrEdgeSnapshot() *csrEdgeSnapshot {
	if g == nil {
		return nil
	}

	g.mu.RLock()
	snapshot := g.csrEdges
	g.mu.RUnlock()
	if snapshot != nil {
		return snapshot
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.csrEdges == nil {
		g.csrEdges = newCSREdgeSnapshotLocked(g)
	}
	return g.csrEdges
}

func newCSREdgeSnapshotLocked(g *Graph) *csrEdgeSnapshot {
	if g == nil {
		return nil
	}

	nodeIDs := NewNodeIDIndex()
	for id, node := range g.nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		nodeIDs.Intern(id)
	}

	outCounts := make([]uint32, nodeIDs.Len()+2)
	inCounts := make([]uint32, nodeIDs.Len()+2)
	denyPairs := make(map[uint64]struct{})
	var totalEdges uint32

	for sourceID, edges := range g.outEdges {
		sourceOrdinal := nodeIDs.Intern(sourceID)
		outCounts = growOrdinalCounts(outCounts, sourceOrdinal)

		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}

			targetOrdinal := nodeIDs.Intern(edge.Target)
			inCounts = growOrdinalCounts(inCounts, targetOrdinal)
			outCounts[sourceOrdinal]++
			inCounts[targetOrdinal]++
			totalEdges++

			if edge.IsDeny() {
				denyPairs[csrEdgePairKey(sourceOrdinal, targetOrdinal)] = struct{}{}
			}
		}
	}

	outCounts = ensureCSREdgeCountsLength(outCounts, nodeIDs.Len())
	inCounts = ensureCSREdgeCountsLength(inCounts, nodeIDs.Len())
	outOffsets := buildCSROffsets(outCounts, nodeIDs.Len())
	inOffsets := buildCSROffsets(inCounts, nodeIDs.Len())

	snapshot := &csrEdgeSnapshot{
		nodeIDs:     nodeIDs,
		outOffsets:  outOffsets,
		outOrdinals: make([]NodeOrdinal, totalEdges),
		outEdges:    make([]*Edge, totalEdges),
		inOffsets:   inOffsets,
		inOrdinals:  make([]NodeOrdinal, totalEdges),
		inEdges:     make([]*Edge, totalEdges),
		denyPairs:   denyPairs,
	}

	outCursor := append([]uint32(nil), outOffsets...)
	for sourceID, edges := range g.outEdges {
		sourceOrdinal, ok := nodeIDs.Lookup(sourceID)
		if !ok {
			continue
		}

		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}

			targetOrdinal, ok := nodeIDs.Lookup(edge.Target)
			if !ok {
				continue
			}

			slot := int(outCursor[sourceOrdinal])
			if slot < 0 || slot >= len(snapshot.outEdges) {
				continue
			}
			snapshot.outOrdinals[slot] = targetOrdinal
			snapshot.outEdges[slot] = edge
			outCursor[sourceOrdinal]++
		}
	}

	inCursor := append([]uint32(nil), inOffsets...)
	for targetID, edges := range g.inEdges {
		targetOrdinal, ok := nodeIDs.Lookup(targetID)
		if !ok {
			continue
		}

		for _, edge := range edges {
			if !g.activeEdgeLocked(edge) {
				continue
			}

			sourceOrdinal, ok := nodeIDs.Lookup(edge.Source)
			if !ok {
				continue
			}

			slot := int(inCursor[targetOrdinal])
			if slot < 0 || slot >= len(snapshot.inEdges) {
				continue
			}
			snapshot.inOrdinals[slot] = sourceOrdinal
			snapshot.inEdges[slot] = edge
			inCursor[targetOrdinal]++
		}
	}

	return snapshot
}

func ensureCSREdgeCountsLength(counts []uint32, nodeCount int) []uint32 {
	required := nodeCount + 2
	if len(counts) >= required {
		return counts
	}
	grown := make([]uint32, required)
	copy(grown, counts)
	return grown
}

func growOrdinalCounts(counts []uint32, ordinal NodeOrdinal) []uint32 {
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

func buildCSROffsets(counts []uint32, nodeCount int) []uint32 {
	offsets := make([]uint32, nodeCount+2)
	var running uint32
	for ordinal := 1; ordinal < len(offsets); ordinal++ {
		offsets[ordinal] = running
		if ordinal < len(counts) {
			running += counts[ordinal]
		}
	}
	return offsets
}

func csrEdgePairKey(sourceOrdinal, targetOrdinal NodeOrdinal) uint64 {
	return uint64(sourceOrdinal)<<32 | uint64(targetOrdinal)
}

func (s *csrEdgeSnapshot) lookupOrdinal(nodeID string) (NodeOrdinal, bool) {
	if s == nil || s.nodeIDs == nil {
		return InvalidNodeOrdinal, false
	}
	return s.nodeIDs.Lookup(nodeID)
}

func (s *csrEdgeSnapshot) resolveOrdinal(ordinal NodeOrdinal) (string, bool) {
	if s == nil || s.nodeIDs == nil {
		return "", false
	}
	return s.nodeIDs.Resolve(ordinal)
}

func (s *csrEdgeSnapshot) hasDenyOrdinals(sourceOrdinal, targetOrdinal NodeOrdinal) bool {
	if s == nil || sourceOrdinal == InvalidNodeOrdinal || targetOrdinal == InvalidNodeOrdinal {
		return false
	}
	_, ok := s.denyPairs[csrEdgePairKey(sourceOrdinal, targetOrdinal)]
	return ok
}

func (s *csrEdgeSnapshot) outRange(sourceOrdinal NodeOrdinal) (int, int, bool) {
	return s.edgeRange(s.outOffsets, len(s.outEdges), sourceOrdinal)
}

func (s *csrEdgeSnapshot) inRange(targetOrdinal NodeOrdinal) (int, int, bool) {
	return s.edgeRange(s.inOffsets, len(s.inEdges), targetOrdinal)
}

func (s *csrEdgeSnapshot) edgeRange(offsets []uint32, edgeCount int, ordinal NodeOrdinal) (int, int, bool) {
	if s == nil || ordinal == InvalidNodeOrdinal {
		return 0, 0, false
	}
	startIndex := int(ordinal)
	endIndex := startIndex + 1
	if endIndex >= len(offsets) {
		return 0, 0, false
	}
	start := int(offsets[startIndex])
	end := int(offsets[endIndex])
	if start < 0 || end < start || end > edgeCount {
		return 0, 0, false
	}
	return start, end, true
}

func (s *csrEdgeSnapshot) forEachOutEdgeOrdinal(sourceOrdinal NodeOrdinal, visit func(edge *Edge, targetOrdinal NodeOrdinal, targetID string) bool) {
	if s == nil || visit == nil {
		return
	}
	start, end, ok := s.outRange(sourceOrdinal)
	if !ok {
		return
	}
	for idx := start; idx < end; idx++ {
		targetOrdinal := s.outOrdinals[idx]
		targetID, ok := s.resolveOrdinal(targetOrdinal)
		if !ok {
			continue
		}
		if !visit(s.outEdges[idx], targetOrdinal, targetID) {
			return
		}
	}
}

func (s *csrEdgeSnapshot) forEachInEdgeOrdinal(targetOrdinal NodeOrdinal, visit func(edge *Edge, sourceOrdinal NodeOrdinal, sourceID string) bool) {
	if s == nil || visit == nil {
		return
	}
	start, end, ok := s.inRange(targetOrdinal)
	if !ok {
		return
	}
	for idx := start; idx < end; idx++ {
		sourceOrdinal := s.inOrdinals[idx]
		sourceID, ok := s.resolveOrdinal(sourceOrdinal)
		if !ok {
			continue
		}
		if !visit(s.inEdges[idx], sourceOrdinal, sourceID) {
			return
		}
	}
}
