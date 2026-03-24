package graph

import (
	"context"
	"math/bits"
	"sort"
)

// SimulateAttackPathsFromStore runs attack-path analysis from bounded
// store-native subgraph extractions instead of full snapshot materialization.
func SimulateAttackPathsFromStore(ctx context.Context, store GraphStore, maxDepth int) (*SimulationResult, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrStoreUnavailable
	}
	if maxDepth <= 0 {
		maxDepth = defaultExtractSubgraphMaxDepth
	}

	roots, err := attackPathStoreRoots(ctx, store)
	if err != nil {
		return nil, err
	}

	result := &SimulationResult{ShortestPath: maxDepth + 1}
	if len(roots) == 0 {
		return result, nil
	}

	allPaths := make([]*ScoredAttackPath, 0, 32)
	seenPaths := make(map[string]struct{}, 64)
	entryIDs := make(map[string]struct{}, 16)
	crownIDs := make(map[string]struct{}, 16)
	nodeByID := make(map[string]*Node, 64)

	for _, root := range roots {
		if err := graphStoreContextErr(ctx); err != nil {
			return nil, err
		}
		subgraph, err := store.ExtractSubgraph(ctx, root.ID, ExtractSubgraphOptions{
			MaxDepth:  maxDepth,
			Direction: ExtractSubgraphDirectionOutgoing,
		})
		if err != nil {
			return nil, err
		}
		if subgraph == nil {
			continue
		}
		rememberAttackPathNodes(nodeByID, subgraph.GetAllNodes())

		sim := NewAttackPathSimulator(subgraph)
		rememberAttackPathNodes(nodeByID, sim.entryPoints)
		rememberAttackPathNodes(nodeByID, sim.crownJewels)
		for _, entry := range sim.entryPoints {
			entryIDs[entry.ID] = struct{}{}
		}
		for _, crown := range sim.crownJewels {
			crownIDs[crown.ID] = struct{}{}
		}

		paths := sim.Simulate(maxDepth).Paths
		for _, path := range paths {
			if path == nil || path.EntryPoint == nil || path.Target == nil {
				continue
			}
			key := pathToKey(path)
			if _, ok := seenPaths[key]; ok {
				continue
			}
			seenPaths[key] = struct{}{}
			allPaths = append(allPaths, path)
			entryIDs[path.EntryPoint.ID] = struct{}{}
			crownIDs[path.Target.ID] = struct{}{}
			if path.Length < result.ShortestPath {
				result.ShortestPath = path.Length
			}
		}
	}

	sort.Slice(allPaths, func(i, j int) bool {
		if allPaths[i].TotalScore != allPaths[j].TotalScore {
			return allPaths[i].TotalScore > allPaths[j].TotalScore
		}
		return pathToKey(allPaths[i]) < pathToKey(allPaths[j])
	})
	for i, path := range allPaths {
		path.Priority = i + 1
		if path.TotalScore >= 70 {
			result.CriticalPaths++
		}
	}
	if len(allPaths) == 0 {
		result.Paths = nil
		result.TotalPaths = 0
		result.EntryPointCount = len(entryIDs)
		result.CrownJewelCount = len(crownIDs)
		return result, nil
	}

	totalLen := 0
	for _, path := range allPaths {
		totalLen += path.Length
	}
	result.Paths = allPaths
	result.TotalPaths = len(allPaths)
	result.EntryPointCount = len(entryIDs)
	result.CrownJewelCount = len(crownIDs)
	result.MeanPathLength = float64(totalLen) / float64(len(allPaths))
	result.Chokepoints = attackPathStoreChokepoints(allPaths, nodeByID)
	return result, nil
}

// SimulateAttackPathFixFromStore runs store-native attack-path analysis and
// evaluates how many paths would be blocked by fixing one node.
func SimulateAttackPathFixFromStore(ctx context.Context, store GraphStore, nodeID string, maxDepth int) (*FixSimulation, error) {
	result, err := SimulateAttackPathsFromStore(ctx, store, maxDepth)
	if err != nil {
		return nil, err
	}
	return (&AttackPathSimulator{}).SimulateFix(result, nodeID), nil
}

func attackPathStoreRoots(ctx context.Context, store GraphStore) ([]*Node, error) {
	nodes, err := store.LookupNodesByKind(ctx, NodeKindInternet, NodeKindUser, NodeKindServiceAccount)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	roots := make([]*Node, 0, len(nodes))
	seen := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if node == nil || node.ID == "" {
			continue
		}
		if _, ok := seen[node.ID]; ok {
			continue
		}
		switch node.Kind {
		case NodeKindInternet, NodeKindUser:
			seen[node.ID] = struct{}{}
			roots = append(roots, node)
		case NodeKindServiceAccount:
			if node.Properties == nil {
				continue
			}
			if _, hasKeys := node.Properties["access_keys"]; !hasKeys {
				continue
			}
			seen[node.ID] = struct{}{}
			roots = append(roots, node)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].Kind != roots[j].Kind {
			return roots[i].Kind < roots[j].Kind
		}
		return roots[i].ID < roots[j].ID
	})
	return roots, nil
}

func rememberAttackPathNodes(nodeByID map[string]*Node, nodes []*Node) {
	for _, node := range nodes {
		if node == nil || node.ID == "" {
			continue
		}
		if _, ok := nodeByID[node.ID]; ok {
			continue
		}
		nodeByID[node.ID] = node
	}
}

func attackPathStoreChokepoints(paths []*ScoredAttackPath, nodeByID map[string]*Node) []*Chokepoint {
	if len(paths) == 0 || len(nodeByID) == 0 {
		return nil
	}

	nodeIDs := NewNodeIDIndex()
	ordered := make([]string, 0, len(nodeByID))
	for id := range nodeByID {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		nodeIDs.Intern(id)
	}
	visitedWords := (nodeIDs.Len() + 63) / 64
	nodePathCount := make([]int, nodeIDs.Len()+1)
	nodeUpstream := make(map[NodeOrdinal][]uint64)
	nodeDownstream := make(map[NodeOrdinal][]uint64)

	sharedEntry := ""
	if len(paths) > 1 {
		sharedEntry = paths[0].EntryPoint.ID
		for _, path := range paths[1:] {
			if path.EntryPoint == nil || path.EntryPoint.ID != sharedEntry {
				sharedEntry = ""
				break
			}
		}
	}

	for _, path := range paths {
		if path == nil || path.EntryPoint == nil || path.Target == nil {
			continue
		}
		entryOrdinal, ok := nodeIDs.Lookup(path.EntryPoint.ID)
		if !ok {
			continue
		}
		targetOrdinal, ok := nodeIDs.Lookup(path.Target.ID)
		if !ok {
			continue
		}
		pathNodes := make([]uint64, visitedWords)
		for _, step := range path.Steps {
			attackPathStoreRecordChokepointNode(nodeIDs, path, sharedEntry, step.FromNode, entryOrdinal, targetOrdinal, pathNodes, nodePathCount, nodeUpstream, nodeDownstream)
			attackPathStoreRecordChokepointNode(nodeIDs, path, sharedEntry, step.ToNode, entryOrdinal, targetOrdinal, pathNodes, nodePathCount, nodeUpstream, nodeDownstream)
		}
	}

	chokepoints := make([]*Chokepoint, 0, len(nodePathCount))
	for ordinal, count := range nodePathCount {
		if count < 2 {
			continue
		}
		nodeID, ok := nodeIDs.Resolve(NodeOrdinal(ordinal))
		if !ok {
			continue
		}
		node := nodeByID[nodeID]
		if node == nil {
			continue
		}
		impact := float64(count) / float64(len(paths))
		chokepoints = append(chokepoints, &Chokepoint{
			Node:                  node,
			PathsThrough:          count,
			BetweennessCentrality: impact,
			BlockedPaths:          count,
			RemediationImpact:     impact,
			UpstreamEntries:       attackPathStoreOrdinalBitsToNodeIDs(nodeIDs, nodeUpstream[NodeOrdinal(ordinal)]),
			DownstreamTargets:     attackPathStoreOrdinalBitsToNodeIDs(nodeIDs, nodeDownstream[NodeOrdinal(ordinal)]),
		})
	}
	sort.Slice(chokepoints, func(i, j int) bool {
		if chokepoints[i].RemediationImpact != chokepoints[j].RemediationImpact {
			return chokepoints[i].RemediationImpact > chokepoints[j].RemediationImpact
		}
		return chokepoints[i].Node.ID < chokepoints[j].Node.ID
	})
	return chokepoints
}

func attackPathStoreRecordChokepointNode(
	nodeIDs *NodeIDIndex,
	path *ScoredAttackPath,
	sharedEntry string,
	nodeID string,
	entryOrdinal NodeOrdinal,
	targetOrdinal NodeOrdinal,
	pathNodes []uint64,
	nodePathCount []int,
	nodeUpstream map[NodeOrdinal][]uint64,
	nodeDownstream map[NodeOrdinal][]uint64,
) {
	if nodeID == sharedEntry {
		return
	}
	if path.Length > 1 && (nodeID == path.EntryPoint.ID || nodeID == path.Target.ID) {
		return
	}
	nodeOrdinal, ok := nodeIDs.Lookup(nodeID)
	if !ok {
		return
	}
	if !markOrdinalBits(pathNodes, nodeOrdinal) || int(nodeOrdinal) >= len(nodePathCount) {
		return
	}
	nodePathCount[nodeOrdinal]++
	if nodeUpstream[nodeOrdinal] == nil {
		nodeUpstream[nodeOrdinal] = make([]uint64, len(pathNodes))
	}
	markOrdinalBits(nodeUpstream[nodeOrdinal], entryOrdinal)
	if nodeDownstream[nodeOrdinal] == nil {
		nodeDownstream[nodeOrdinal] = make([]uint64, len(pathNodes))
	}
	markOrdinalBits(nodeDownstream[nodeOrdinal], targetOrdinal)
}

func attackPathStoreOrdinalBitsToNodeIDs(nodeIDs *NodeIDIndex, visited []uint64) []string {
	if len(visited) == 0 || nodeIDs == nil {
		return nil
	}
	ids := make([]string, 0)
	for wordIndex, word := range visited {
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			ordinal, ok := nodeOrdinalFromWordBit(wordIndex, bit)
			if !ok {
				word &^= uint64(1) << bit
				continue
			}
			if id, ok := nodeIDs.Resolve(ordinal); ok {
				ids = append(ids, id)
			}
			word &^= uint64(1) << bit
		}
	}
	return ids
}
