package graph

import (
	"container/heap"
	"fmt"
	"sort"
)

// ImpactScenario defines which consequence model to apply during traversal.
type ImpactScenario string

const (
	ImpactScenarioChurnCascade  ImpactScenario = "churn_cascade"
	ImpactScenarioRevenueImpact ImpactScenario = "revenue_impact"
	ImpactScenarioIncidentBlast ImpactScenario = "incident_blast_radius"
)

// ImpactPathAnalyzer generalizes attack-path traversal into business impact chains.
type ImpactPathAnalyzer struct {
	graph *Graph
}

const maxImpactPaths = 50

// ImpactStep is one hop in an impact path.
type ImpactStep struct {
	FromNode string   `json:"from_node"`
	ToNode   string   `json:"to_node"`
	EdgeKind EdgeKind `json:"edge_kind"`
	Depth    int      `json:"depth"`
}

// ImpactPath represents a consequence chain and its aggregate impact.
type ImpactPath struct {
	ID               string             `json:"id"`
	Scenario         ImpactScenario     `json:"scenario"`
	StartNode        string             `json:"start_node"`
	EndNode          string             `json:"end_node"`
	Steps            []ImpactStep       `json:"steps"`
	AffectedEntities []string           `json:"affected_entities"`
	AggregateMetrics map[string]float64 `json:"aggregate_metrics"`
	Score            float64            `json:"score"`
	Severity         Severity           `json:"severity"`
	Recommendation   string             `json:"recommendation"`
}

// ImpactAnalysisResult contains all paths plus roll-up metrics.
type ImpactAnalysisResult struct {
	Scenario              ImpactScenario     `json:"scenario"`
	StartNode             string             `json:"start_node"`
	Paths                 []*ImpactPath      `json:"paths"`
	Chokepoints           []*Chokepoint      `json:"chokepoints"`
	TotalAffectedEntities int                `json:"total_affected_entities"`
	AggregateMetrics      map[string]float64 `json:"aggregate_metrics"`
}

// NewImpactPathAnalyzer creates a business impact analyzer over the unified graph.
func NewImpactPathAnalyzer(g *Graph) *ImpactPathAnalyzer {
	return &ImpactPathAnalyzer{graph: g}
}

// Analyze computes scenario-specific impact chains starting from one node.
func (a *ImpactPathAnalyzer) Analyze(startNodeID string, scenario ImpactScenario, maxDepth int) *ImpactAnalysisResult {
	if maxDepth <= 0 {
		maxDepth = 6
	}

	if _, ok := a.graph.GetNode(startNodeID); !ok {
		return &ImpactAnalysisResult{
			Scenario:         scenario,
			StartNode:        startNodeID,
			AggregateMetrics: map[string]float64{},
		}
	}

	type bfsState struct {
		nodeID  string
		steps   []ImpactStep
		visited map[string]bool
	}

	queue := []bfsState{{nodeID: startNodeID, visited: map[string]bool{startNodeID: true}}}
	topPaths := &impactPathMinHeap{}
	heap.Init(topPaths)

	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]

		if len(state.steps) >= maxDepth {
			continue
		}

		for _, edge := range a.graph.GetOutEdges(state.nodeID) {
			if edge.IsDeny() || !a.allowedEdge(scenario, edge.Kind) {
				continue
			}
			if state.visited[edge.Target] {
				continue
			}
			targetNode, ok := a.graph.GetNode(edge.Target)
			if !ok {
				continue
			}

			nextVisited := cloneVisited(state.visited)
			nextVisited[edge.Target] = true
			nextSteps := append(copySteps(state.steps), ImpactStep{
				FromNode: edge.Source,
				ToNode:   edge.Target,
				EdgeKind: edge.Kind,
				Depth:    len(state.steps) + 1,
			})

			if a.isScenarioTarget(scenario, targetNode, startNodeID) {
				path := a.materializePath(scenario, startNodeID, targetNode.ID, nextSteps)
				pushImpactPathTopK(topPaths, path, maxImpactPaths)
			}

			queue = append(queue, bfsState{nodeID: edge.Target, steps: nextSteps, visited: nextVisited})
		}
	}

	paths := popImpactPathsDescending(topPaths)

	metrics := aggregateImpactMetrics(paths)
	chokepoints := a.impactChokepoints(paths, startNodeID)

	return &ImpactAnalysisResult{
		Scenario:              scenario,
		StartNode:             startNodeID,
		Paths:                 paths,
		Chokepoints:           chokepoints,
		TotalAffectedEntities: len(uniqueAffectedEntities(paths)),
		AggregateMetrics:      metrics,
	}
}

func (a *ImpactPathAnalyzer) allowedEdge(scenario ImpactScenario, edgeKind EdgeKind) bool {
	switch scenario {
	case ImpactScenarioChurnCascade:
		switch edgeKind {
		case EdgeKindRefers, EdgeKindManagedBy, EdgeKindWorksAt, EdgeKindAssignedTo, EdgeKindOwns, EdgeKindOriginatedFrom:
			return true
		}
	case ImpactScenarioRevenueImpact:
		switch edgeKind {
		case EdgeKindBilledBy, EdgeKindSubscribedTo, EdgeKindOwns, EdgeKindRenews, EdgeKindAssignedTo, EdgeKindOriginatedFrom:
			return true
		}
	case ImpactScenarioIncidentBlast:
		switch edgeKind {
		case EdgeKindConnectsTo, EdgeKindOwns, EdgeKindDeployedFrom, EdgeKindSubscribedTo, EdgeKindWorksAt, EdgeKindProvisionedAs:
			return true
		}
	default:
		return true
	}
	return false
}

func (a *ImpactPathAnalyzer) isScenarioTarget(scenario ImpactScenario, node *Node, startNodeID string) bool {
	if node == nil || node.ID == startNodeID {
		return false
	}
	switch scenario {
	case ImpactScenarioChurnCascade:
		return node.Kind == NodeKindCustomer || node.Kind == NodeKindCompany || node.Kind == NodeKindContact
	case ImpactScenarioRevenueImpact:
		return node.Kind == NodeKindCustomer || node.Kind == NodeKindCompany || node.Kind == NodeKindDeal || node.Kind == NodeKindOpportunity
	case ImpactScenarioIncidentBlast:
		return node.Kind == NodeKindCustomer || node.Kind == NodeKindCompany || node.Kind == NodeKindVendor || node.Kind == NodeKindSubscription
	default:
		return node.IsBusinessEntity()
	}
}

func (a *ImpactPathAnalyzer) materializePath(scenario ImpactScenario, startNodeID, endNodeID string, steps []ImpactStep) *ImpactPath {
	affected := make([]string, 0)
	for _, step := range steps {
		node, ok := a.graph.GetNode(step.ToNode)
		if !ok {
			continue
		}
		if node.IsBusinessEntity() {
			affected = append(affected, node.ID)
		}
	}
	affected = dedupeStrings(affected)

	metrics := map[string]float64{
		"affected_entities": float64(len(affected)),
		"combined_arr":      0,
		"renewals_60d":      0,
	}
	for _, entityID := range affected {
		node, ok := a.graph.GetNode(entityID)
		if !ok {
			continue
		}
		metrics["combined_arr"] += readFloat(node.Properties, "arr", "deal_value", "contract_value", "revenue")
		if d := readInt(node.Properties, "days_until_renewal", "days_until_trial_end", "days_until_close"); d > 0 && d <= 60 {
			metrics["renewals_60d"]++
		}
	}

	score := 20.0 + metrics["affected_entities"]*12 + metrics["renewals_60d"]*10
	score += metrics["combined_arr"] / 100000
	if len(steps) > 0 {
		score += 20.0 / float64(len(steps))
	}
	if score > 100 {
		score = 100
	}

	severity := scoreToSeverity(score)
	recommendation := "Review and break high-impact dependency links"
	switch scenario {
	case ImpactScenarioChurnCascade:
		recommendation = "Protect shared champions and isolate referral-driven churn cascades"
	case ImpactScenarioRevenueImpact:
		recommendation = "Escalate revenue protection workflow for impacted opportunities"
	case ImpactScenarioIncidentBlast:
		recommendation = "Isolate the failing service and prioritize enterprise customer recovery"
	}

	return &ImpactPath{
		ID:               fmt.Sprintf("impact:%s:%s:%s", scenario, startNodeID, endNodeID),
		Scenario:         scenario,
		StartNode:        startNodeID,
		EndNode:          endNodeID,
		Steps:            steps,
		AffectedEntities: affected,
		AggregateMetrics: metrics,
		Score:            score,
		Severity:         severity,
		Recommendation:   recommendation,
	}
}

func (a *ImpactPathAnalyzer) impactChokepoints(paths []*ImpactPath, startNodeID string) []*Chokepoint {
	if len(paths) == 0 {
		return nil
	}

	pathsByTarget := make(map[string][]*ImpactPath)
	nodeCounts := make(map[string]int)
	for _, path := range paths {
		pathsByTarget[path.EndNode] = append(pathsByTarget[path.EndNode], path)
		for _, step := range path.Steps {
			if step.ToNode == startNodeID || step.ToNode == path.EndNode {
				continue
			}
			nodeCounts[step.ToNode]++
		}
	}

	result := make([]*Chokepoint, 0)
	for nodeID, count := range nodeCounts {
		if count < 2 {
			continue
		}
		node, ok := a.graph.GetNode(nodeID)
		if !ok {
			continue
		}
		blockedTargets := 0
		blockedPaths := 0
		betweennessAccumulator := 0.0
		totalTargets := len(pathsByTarget)

		for _, targetPaths := range pathsByTarget {
			if len(targetPaths) == 0 {
				continue
			}

			shortestLen := len(targetPaths[0].Steps)
			for _, path := range targetPaths[1:] {
				if len(path.Steps) < shortestLen {
					shortestLen = len(path.Steps)
				}
			}

			totalShortest := 0
			throughShortest := 0
			hasAlternatePath := false

			for _, path := range targetPaths {
				containsNode := pathHasIntermediateNode(path, nodeID, startNodeID)
				if !containsNode {
					hasAlternatePath = true
				}
				if len(path.Steps) != shortestLen {
					continue
				}
				totalShortest++
				if containsNode {
					throughShortest++
				}
			}

			if totalShortest > 0 {
				betweennessAccumulator += float64(throughShortest) / float64(totalShortest)
			}
			if !hasAlternatePath {
				blockedTargets++
				blockedPaths += len(targetPaths)
			}
		}

		betweenness := 0.0
		impact := 0.0
		if totalTargets > 0 {
			betweenness = betweennessAccumulator / float64(totalTargets)
			impact = float64(blockedTargets) / float64(totalTargets)
		}

		result = append(result, &Chokepoint{
			Node:                  node,
			PathsThrough:          count,
			BlockedPaths:          blockedPaths,
			BetweennessCentrality: betweenness,
			RemediationImpact:     impact,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].RemediationImpact == result[j].RemediationImpact {
			return result[i].BetweennessCentrality > result[j].BetweennessCentrality
		}
		return result[i].RemediationImpact > result[j].RemediationImpact
	})
	if len(result) > 20 {
		result = result[:20]
	}
	return result
}

func aggregateImpactMetrics(paths []*ImpactPath) map[string]float64 {
	metrics := map[string]float64{
		"path_count":        float64(len(paths)),
		"combined_arr":      0,
		"renewals_60d":      0,
		"affected_entities": float64(len(uniqueAffectedEntities(paths))),
		"max_path_score":    0,
		"mean_path_score":   0,
	}
	if len(paths) == 0 {
		return metrics
	}

	totalScore := 0.0
	for _, path := range paths {
		totalScore += path.Score
		if path.Score > metrics["max_path_score"] {
			metrics["max_path_score"] = path.Score
		}
		metrics["combined_arr"] += path.AggregateMetrics["combined_arr"]
		metrics["renewals_60d"] += path.AggregateMetrics["renewals_60d"]
	}
	metrics["mean_path_score"] = totalScore / float64(len(paths))
	return metrics
}

func uniqueAffectedEntities(paths []*ImpactPath) []string {
	entities := make([]string, 0)
	for _, path := range paths {
		entities = append(entities, path.AffectedEntities...)
	}
	return dedupeStrings(entities)
}

func copySteps(steps []ImpactStep) []ImpactStep {
	copied := make([]ImpactStep, len(steps))
	copy(copied, steps)
	return copied
}

func cloneVisited(visited map[string]bool) map[string]bool {
	cloned := make(map[string]bool, len(visited))
	for key, value := range visited {
		cloned[key] = value
	}
	return cloned
}

func pathHasIntermediateNode(path *ImpactPath, nodeID, startNodeID string) bool {
	if path == nil {
		return false
	}
	for _, step := range path.Steps {
		if step.ToNode != nodeID {
			continue
		}
		if step.ToNode == startNodeID || step.ToNode == path.EndNode {
			continue
		}
		return true
	}
	return false
}

type impactPathMinHeap []*ImpactPath

func (h impactPathMinHeap) Len() int {
	return len(h)
}

func (h impactPathMinHeap) Less(i, j int) bool {
	return h[i].Score < h[j].Score
}

func (h impactPathMinHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *impactPathMinHeap) Push(x any) {
	*h = append(*h, x.(*ImpactPath))
}

func (h *impactPathMinHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func pushImpactPathTopK(h *impactPathMinHeap, path *ImpactPath, limit int) {
	if limit <= 0 || path == nil {
		return
	}
	heap.Push(h, path)
	if h.Len() > limit {
		_ = heap.Pop(h)
	}
}

func popImpactPathsDescending(h *impactPathMinHeap) []*ImpactPath {
	if h == nil || h.Len() == 0 {
		return nil
	}

	paths := make([]*ImpactPath, h.Len())
	for i := len(paths) - 1; i >= 0; i-- {
		paths[i] = heap.Pop(h).(*ImpactPath)
	}
	return paths
}
