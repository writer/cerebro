package graph

import (
	"fmt"
	"sort"
	"strings"
)

// NodeMutation represents a node-level graph mutation.
type NodeMutation struct {
	ID         string         `json:"id,omitempty"`
	Action     string         `json:"action"`
	Node       *Node          `json:"node,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// EdgeMutation represents an edge-level graph mutation.
type EdgeMutation struct {
	Source string   `json:"source,omitempty"`
	Target string   `json:"target,omitempty"`
	Kind   EdgeKind `json:"kind,omitempty"`
	Action string   `json:"action"`
	Edge   *Edge    `json:"edge,omitempty"`
}

// GraphDelta is a set of graph mutations.
type GraphDelta struct {
	Nodes []NodeMutation `json:"nodes,omitempty"`
	Edges []EdgeMutation `json:"edges,omitempty"`
}

// GraphSimulationResult captures before/after simulation state and diff.
type GraphSimulationResult struct {
	Before                GraphSimulationSnapshot `json:"before"`
	After                 GraphSimulationSnapshot `json:"after"`
	Delta                 GraphSimulationDiff     `json:"delta"`
	PersonDepartureImpact *PersonDepartureImpact  `json:"person_departure_impact,omitempty"`
}

// GraphSimulationSnapshot contains key metrics for one graph state.
type GraphSimulationSnapshot struct {
	RiskScore         float64             `json:"risk_score"`
	ToxicCombinations []*ToxicCombination `json:"toxic_combinations"`
	AttackPaths       []*ScoredAttackPath `json:"attack_paths"`
	AffectedCustomers []*Node             `json:"affected_customers"`
	AffectedARR       float64             `json:"affected_arr"`
}

// GraphSimulationDiff captures deltas between before and after simulation snapshots.
type GraphSimulationDiff struct {
	ToxicCombosAdded   []*ToxicCombination `json:"toxic_combos_added"`
	ToxicCombosRemoved []*ToxicCombination `json:"toxic_combos_removed"`
	AttackPathsBlocked []*ScoredAttackPath `json:"attack_paths_blocked"`
	AttackPathsCreated []*ScoredAttackPath `json:"attack_paths_created"`
	RiskScoreDelta     float64             `json:"risk_score_delta"`
}

// Simulate applies a delta to a cloned graph and returns before/after metrics.
func (g *Graph) Simulate(delta GraphDelta) (*GraphSimulationResult, error) {
	removedPeople := delta.removedPersonIDs(g)
	changedNodeIDs := delta.changedNodeIDs()

	before := analyzeSimulationSnapshot(g, changedNodeIDs)

	hypothetical := g.Clone()
	if err := hypothetical.ApplyDelta(delta); err != nil {
		return nil, err
	}
	hypothetical.BuildIndex()

	after := analyzeSimulationSnapshot(hypothetical, changedNodeIDs)
	result := &GraphSimulationResult{
		Before: before,
		After:  after,
		Delta:  buildSimulationDiff(before, after),
	}
	if len(removedPeople) == 1 {
		result.PersonDepartureImpact = buildPersonDepartureImpact(g, hypothetical, removedPeople[0])
	}
	return result, nil
}

// ApplyDelta mutates the graph in-place according to the provided delta.
func (g *Graph) ApplyDelta(delta GraphDelta) error {
	for idx, mutation := range delta.Nodes {
		action := normalizeMutationAction(mutation.Action)
		switch action {
		case "add":
			node := mutation.Node
			if node == nil {
				return fmt.Errorf("node mutation %d: add requires node payload", idx)
			}
			if strings.TrimSpace(node.ID) == "" {
				node.ID = strings.TrimSpace(mutation.ID)
			}
			if strings.TrimSpace(node.ID) == "" {
				return fmt.Errorf("node mutation %d: add requires node id", idx)
			}
			g.AddNode(cloneNode(node))
		case "remove":
			nodeID := strings.TrimSpace(mutation.ID)
			if nodeID == "" && mutation.Node != nil {
				nodeID = strings.TrimSpace(mutation.Node.ID)
			}
			if nodeID == "" {
				return fmt.Errorf("node mutation %d: remove requires id", idx)
			}
			g.RemoveNode(nodeID)
		case "modify":
			nodeID := strings.TrimSpace(mutation.ID)
			if nodeID == "" && mutation.Node != nil {
				nodeID = strings.TrimSpace(mutation.Node.ID)
			}
			if nodeID == "" {
				return fmt.Errorf("node mutation %d: modify requires id", idx)
			}
			if len(mutation.Properties) == 0 {
				return fmt.Errorf("node mutation %d: modify requires properties", idx)
			}
			for key, value := range mutation.Properties {
				if strings.TrimSpace(key) == "" {
					continue
				}
				g.SetNodeProperty(nodeID, key, value)
			}
		default:
			return fmt.Errorf("node mutation %d: unsupported action %q", idx, mutation.Action)
		}
	}

	for idx, mutation := range delta.Edges {
		action := normalizeMutationAction(mutation.Action)
		switch action {
		case "add":
			edge := mutation.Edge
			if edge == nil {
				edge = &Edge{
					ID:     fmt.Sprintf("%s->%s:%s", mutation.Source, mutation.Target, mutation.Kind),
					Source: mutation.Source,
					Target: mutation.Target,
					Kind:   mutation.Kind,
					Effect: EdgeEffectAllow,
				}
			}
			if strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" || strings.TrimSpace(string(edge.Kind)) == "" {
				return fmt.Errorf("edge mutation %d: add requires source, target, and kind", idx)
			}
			g.AddEdge(cloneEdge(edge))
		case "remove":
			source := strings.TrimSpace(mutation.Source)
			target := strings.TrimSpace(mutation.Target)
			kind := mutation.Kind
			if mutation.Edge != nil {
				if source == "" {
					source = strings.TrimSpace(mutation.Edge.Source)
				}
				if target == "" {
					target = strings.TrimSpace(mutation.Edge.Target)
				}
				if strings.TrimSpace(string(kind)) == "" {
					kind = mutation.Edge.Kind
				}
			}
			if source == "" || target == "" || strings.TrimSpace(string(kind)) == "" {
				return fmt.Errorf("edge mutation %d: remove requires source, target, and kind", idx)
			}
			g.RemoveEdge(source, target, kind)
		default:
			return fmt.Errorf("edge mutation %d: unsupported action %q", idx, mutation.Action)
		}
	}

	return nil
}

func (d GraphDelta) changedNodeIDs() map[string]struct{} {
	ids := make(map[string]struct{})
	for _, mutation := range d.Nodes {
		if id := strings.TrimSpace(mutation.ID); id != "" {
			ids[id] = struct{}{}
		}
		if mutation.Node != nil {
			if id := strings.TrimSpace(mutation.Node.ID); id != "" {
				ids[id] = struct{}{}
			}
		}
	}
	for _, mutation := range d.Edges {
		if source := strings.TrimSpace(mutation.Source); source != "" {
			ids[source] = struct{}{}
		}
		if target := strings.TrimSpace(mutation.Target); target != "" {
			ids[target] = struct{}{}
		}
		if mutation.Edge != nil {
			if source := strings.TrimSpace(mutation.Edge.Source); source != "" {
				ids[source] = struct{}{}
			}
			if target := strings.TrimSpace(mutation.Edge.Target); target != "" {
				ids[target] = struct{}{}
			}
		}
	}
	return ids
}

func (d GraphDelta) removedPersonIDs(g *Graph) []string {
	if g == nil {
		return nil
	}
	ids := make(map[string]struct{})
	for _, mutation := range d.Nodes {
		if normalizeMutationAction(mutation.Action) != "remove" {
			continue
		}
		nodeID := strings.TrimSpace(mutation.ID)
		if nodeID == "" && mutation.Node != nil {
			nodeID = strings.TrimSpace(mutation.Node.ID)
		}
		if nodeID == "" {
			continue
		}
		node, ok := g.GetNode(nodeID)
		if !ok || node == nil || node.Kind != NodeKindPerson {
			continue
		}
		ids[nodeID] = struct{}{}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func analyzeSimulationSnapshot(g *Graph, changedNodeIDs map[string]struct{}) GraphSimulationSnapshot {
	engine := NewRiskEngine(g)
	report := engine.Analyze()

	affectedCustomers, affectedARR := collectAffectedCustomers(g, changedNodeIDs)

	snapshot := GraphSimulationSnapshot{
		RiskScore:         report.RiskScore,
		ToxicCombinations: report.ToxicCombinations,
		AffectedCustomers: affectedCustomers,
		AffectedARR:       affectedARR,
	}
	if report.AttackPaths != nil {
		snapshot.AttackPaths = report.AttackPaths.Paths
	}
	return snapshot
}

func buildSimulationDiff(before, after GraphSimulationSnapshot) GraphSimulationDiff {
	beforeToxic := make(map[string]*ToxicCombination, len(before.ToxicCombinations))
	for _, combo := range before.ToxicCombinations {
		if combo == nil {
			continue
		}
		beforeToxic[combo.ID] = combo
	}
	afterToxic := make(map[string]*ToxicCombination, len(after.ToxicCombinations))
	for _, combo := range after.ToxicCombinations {
		if combo == nil {
			continue
		}
		afterToxic[combo.ID] = combo
	}

	beforePaths := make(map[string]*ScoredAttackPath, len(before.AttackPaths))
	for _, path := range before.AttackPaths {
		if path == nil {
			continue
		}
		beforePaths[simulationPathKey(path)] = path
	}
	afterPaths := make(map[string]*ScoredAttackPath, len(after.AttackPaths))
	for _, path := range after.AttackPaths {
		if path == nil {
			continue
		}
		afterPaths[simulationPathKey(path)] = path
	}

	diff := GraphSimulationDiff{RiskScoreDelta: after.RiskScore - before.RiskScore}
	for id, combo := range afterToxic {
		if _, exists := beforeToxic[id]; !exists {
			diff.ToxicCombosAdded = append(diff.ToxicCombosAdded, combo)
		}
	}
	for id, combo := range beforeToxic {
		if _, exists := afterToxic[id]; !exists {
			diff.ToxicCombosRemoved = append(diff.ToxicCombosRemoved, combo)
		}
	}

	for key, path := range afterPaths {
		if _, exists := beforePaths[key]; !exists {
			diff.AttackPathsCreated = append(diff.AttackPathsCreated, path)
		}
	}
	for key, path := range beforePaths {
		if _, exists := afterPaths[key]; !exists {
			diff.AttackPathsBlocked = append(diff.AttackPathsBlocked, path)
		}
	}

	sort.Slice(diff.ToxicCombosAdded, func(i, j int) bool { return diff.ToxicCombosAdded[i].ID < diff.ToxicCombosAdded[j].ID })
	sort.Slice(diff.ToxicCombosRemoved, func(i, j int) bool { return diff.ToxicCombosRemoved[i].ID < diff.ToxicCombosRemoved[j].ID })
	sort.Slice(diff.AttackPathsCreated, func(i, j int) bool {
		return simulationPathKey(diff.AttackPathsCreated[i]) < simulationPathKey(diff.AttackPathsCreated[j])
	})
	sort.Slice(diff.AttackPathsBlocked, func(i, j int) bool {
		return simulationPathKey(diff.AttackPathsBlocked[i]) < simulationPathKey(diff.AttackPathsBlocked[j])
	})

	return diff
}

func collectAffectedCustomers(g *Graph, changedNodeIDs map[string]struct{}) ([]*Node, float64) {
	if len(changedNodeIDs) == 0 {
		return nil, 0
	}

	type visit struct {
		nodeID string
		depth  int
	}

	const maxDepth = 4
	queue := make([]visit, 0, len(changedNodeIDs))
	visited := make(map[string]struct{}, len(changedNodeIDs))
	for nodeID := range changedNodeIDs {
		if strings.TrimSpace(nodeID) == "" {
			continue
		}
		if _, ok := g.GetNode(nodeID); !ok {
			continue
		}
		queue = append(queue, visit{nodeID: nodeID, depth: 0})
		visited[nodeID] = struct{}{}
	}

	customers := make(map[string]*Node)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		node, ok := g.GetNode(current.nodeID)
		if !ok || node == nil {
			continue
		}
		if node.Kind == NodeKindCustomer {
			customers[node.ID] = node
		}

		if current.depth >= maxDepth {
			continue
		}

		for _, edge := range g.GetOutEdges(current.nodeID) {
			target := strings.TrimSpace(edge.Target)
			if target == "" {
				continue
			}
			if _, seen := visited[target]; seen {
				continue
			}
			visited[target] = struct{}{}
			queue = append(queue, visit{nodeID: target, depth: current.depth + 1})
		}
		for _, edge := range g.GetInEdges(current.nodeID) {
			source := strings.TrimSpace(edge.Source)
			if source == "" {
				continue
			}
			if _, seen := visited[source]; seen {
				continue
			}
			visited[source] = struct{}{}
			queue = append(queue, visit{nodeID: source, depth: current.depth + 1})
		}
	}

	result := make([]*Node, 0, len(customers))
	arr := 0.0
	for _, customer := range customers {
		result = append(result, customer)
		arr += readFloat(customer.Properties, "arr", "contract_value", "deal_value", "revenue", "amount")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, arr
}

func simulationPathKey(path *ScoredAttackPath) string {
	if path == nil {
		return ""
	}
	if strings.TrimSpace(path.ID) != "" {
		return path.ID
	}
	entry := ""
	target := ""
	if path.EntryPoint != nil {
		entry = path.EntryPoint.ID
	}
	if path.Target != nil {
		target = path.Target.ID
	}
	return fmt.Sprintf("%s->%s:%d", entry, target, path.Length)
}

func normalizeMutationAction(action string) string {
	normalized := strings.ToLower(strings.TrimSpace(action))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	switch normalized {
	case "add", "create", "added", "create_node", "add_node", "add_edge":
		return "add"
	case "remove", "delete", "removed", "delete_node", "remove_node", "remove_edge", "delete_edge":
		return "remove"
	case "modify", "update", "updated", "modify_node", "update_node":
		return "modify"
	default:
		return normalized
	}
}
