package graph

func cloneGraphWithSharedPropertyHistory(g *Graph) *Graph {
	if g == nil {
		return nil
	}

	cloned := New()
	cloned.metadata = cloneMetadata(g.metadata)
	cloned.activeNodeCount.Store(g.activeNodeCount.Load())
	cloned.activeEdgeCount.Store(g.activeEdgeCount.Load())
	cloned.blastRadiusVersion = g.blastRadiusVersion
	cloned.nodeIDs = g.nodeIDs.Clone()
	cloned.propertyColumns = g.propertyColumns.Clone()
	cloned.schemaValidationMode = g.schemaValidationMode
	cloned.schemaValidationStats = cloneSchemaValidationStats(g.schemaValidationStats)
	cloned.temporalHistoryMaxEntries = g.temporalHistoryMaxEntries
	cloned.temporalHistoryTTL = g.temporalHistoryTTL

	for id, node := range g.nodes {
		cloned.nodes[id] = cloneNodeForGraphClone(node)
		if cloned.nodes[id] != nil {
			cloned.nodes[id].propertyColumns = cloned.propertyColumns
		}
	}

	edgeClones := make(map[*Edge]*Edge, len(g.edgeByID))
	for source, edges := range g.outEdges {
		clonedEdges := make([]*Edge, len(edges))
		for i, edge := range edges {
			clonedEdges[i] = cloneEdgeReference(edgeClones, edge)
		}
		cloned.outEdges[source] = clonedEdges
	}
	for target, edges := range g.inEdges {
		clonedEdges := make([]*Edge, len(edges))
		for i, edge := range edges {
			clonedEdges[i] = cloneEdgeReference(edgeClones, edge)
		}
		cloned.inEdges[target] = clonedEdges
	}
	for id, edge := range g.edgeByID {
		cloned.edgeByID[id] = cloneEdgeReference(edgeClones, edge)
	}

	// New() bootstraps empty indexes immediately, so the clone must rebuild them
	// after copying graph state or it will retain "built" flags backed by empty maps.
	cloned.buildIndexLocked()
	if g.entitySuggestBuilt {
		cloned.ensureEntitySuggestIndexBuiltLocked()
	}

	return cloned
}

func cloneNodeForGraphClone(node *Node) *Node {
	if node == nil {
		return nil
	}
	cloned := *node
	cloned.Properties = cloneAnyMap(node.Properties)
	cloned.PreviousProperties = cloneAnyMap(node.PreviousProperties)
	cloned.PropertyHistory = sharePropertyHistoryMap(node.PropertyHistory)
	cloned.Tags = cloneStringMap(node.Tags)
	cloned.Findings = append([]string(nil), node.Findings...)
	cloned.propertyColumns = node.propertyColumns
	if node.observationProps != nil {
		cloned.observationProps = ptrObservationProperties(*node.observationProps)
	}
	if node.attackSequenceProps != nil {
		cloned.attackSequenceProps = ptrAttackSequenceProperties(*node.attackSequenceProps)
	}
	return &cloned
}

func cloneEdgeReference(edgeClones map[*Edge]*Edge, edge *Edge) *Edge {
	if edge == nil {
		return nil
	}
	if cloned, ok := edgeClones[edge]; ok {
		return cloned
	}
	cloned := cloneEdge(edge)
	edgeClones[edge] = cloned
	return cloned
}

func sharePropertyHistoryMap(values map[string][]PropertySnapshot) map[string][]PropertySnapshot {
	if values == nil {
		return nil
	}
	cloned := make(map[string][]PropertySnapshot, len(values))
	for property, history := range values {
		cloned[property] = history
	}
	return cloned
}

func clonePropertySnapshotsShared(history []PropertySnapshot) []PropertySnapshot {
	if history == nil {
		return nil
	}
	return append([]PropertySnapshot(nil), history...)
}

func cloneSchemaValidationStats(stats SchemaValidationStats) SchemaValidationStats {
	stats.NodeWarningByCode = cloneCounterMapWritable(stats.NodeWarningByCode)
	stats.EdgeWarningByCode = cloneCounterMapWritable(stats.EdgeWarningByCode)
	stats.NodeRejectByCode = cloneCounterMapWritable(stats.NodeRejectByCode)
	stats.EdgeRejectByCode = cloneCounterMapWritable(stats.EdgeRejectByCode)
	return stats
}

func cloneCounterMapWritable(values map[string]int) map[string]int {
	if len(values) == 0 {
		return make(map[string]int)
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
