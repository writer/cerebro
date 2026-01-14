package graph

import (
	"container/heap"
	"fmt"
	"sort"
	"sync"
)

// AttackPathSimulator simulates attacker movement through the graph
type AttackPathSimulator struct {
	graph          *Graph
	entryPoints    []*Node
	crownJewels    []*Node
	exploitability map[string]float64 // node ID -> exploitability score
}

// NewAttackPathSimulator creates a new simulator
func NewAttackPathSimulator(g *Graph) *AttackPathSimulator {
	sim := &AttackPathSimulator{
		graph:          g,
		exploitability: make(map[string]float64),
	}
	sim.identifyEntryPoints()
	sim.identifyCrownJewels()
	sim.calculateExploitability()
	return sim
}

// SimulationResult contains all discovered attack paths
type SimulationResult struct {
	Paths           []*ScoredAttackPath `json:"paths"`
	TotalPaths      int                 `json:"total_paths"`
	CriticalPaths   int                 `json:"critical_paths"`
	Chokepoints     []*Chokepoint       `json:"chokepoints"`
	EntryPointCount int                 `json:"entry_point_count"`
	CrownJewelCount int                 `json:"crown_jewel_count"`
	MeanPathLength  float64             `json:"mean_path_length"`
	ShortestPath    int                 `json:"shortest_path"`
}

// ScoredAttackPath is an attack path with risk scoring
type ScoredAttackPath struct {
	ID             string        `json:"id"`
	EntryPoint     *Node         `json:"entry_point"`
	Target         *Node         `json:"target"`
	Steps          []*AttackStep `json:"steps"`
	Length         int           `json:"length"`
	TotalScore     float64       `json:"total_score"`    // Combined risk score
	Exploitability float64       `json:"exploitability"` // How easy to execute
	Impact         float64       `json:"impact"`         // Business impact if successful
	Likelihood     float64       `json:"likelihood"`     // Probability of attempt
	Priority       int           `json:"priority"`       // Remediation priority (1=highest)
	RequiredSkill  string        `json:"required_skill"` // low, medium, high, expert
	EstimatedTime  string        `json:"estimated_time"` // minutes, hours, days
}

// Chokepoint represents a node where multiple attack paths converge
type Chokepoint struct {
	Node                  *Node    `json:"node"`
	PathsThrough          int      `json:"paths_through"`
	BetweennessCentrality float64  `json:"betweenness_centrality"`
	BlockedPaths          int      `json:"blocked_paths"`      // Paths eliminated by fixing this
	RemediationImpact     float64  `json:"remediation_impact"` // 0-1, higher is better ROI
	UpstreamEntries       []string `json:"upstream_entries"`
	DownstreamTargets     []string `json:"downstream_targets"`
}

func (sim *AttackPathSimulator) identifyEntryPoints() {
	for _, node := range sim.graph.GetAllNodes() {
		// Internet-exposed resources
		if isExposedToInternet(sim.graph, node.ID) {
			sim.entryPoints = append(sim.entryPoints, node)
			continue
		}

		// Internet node itself
		if node.Kind == NodeKindInternet {
			sim.entryPoints = append(sim.entryPoints, node)
			continue
		}

		// Users (potential compromise via phishing)
		if node.Kind == NodeKindUser {
			sim.entryPoints = append(sim.entryPoints, node)
		}

		// Service accounts with access keys
		if node.Kind == NodeKindServiceAccount {
			if _, hasKeys := node.Properties["access_keys"]; hasKeys {
				sim.entryPoints = append(sim.entryPoints, node)
			}
		}
	}
}

func (sim *AttackPathSimulator) identifyCrownJewels() {
	for _, node := range sim.graph.GetAllNodes() {
		// Explicitly marked critical
		if node.Risk == RiskCritical {
			sim.crownJewels = append(sim.crownJewels, node)
			continue
		}

		// Databases with sensitive data
		if node.Kind == NodeKindDatabase {
			if node.Risk == RiskHigh || hasTag(node, "contains_pii") || hasTag(node, "production") {
				sim.crownJewels = append(sim.crownJewels, node)
				continue
			}
		}

		// Secrets/credentials stores
		if node.Kind == NodeKindSecret {
			sim.crownJewels = append(sim.crownJewels, node)
			continue
		}

		// High-risk buckets
		if node.Kind == NodeKindBucket && node.Risk == RiskHigh {
			sim.crownJewels = append(sim.crownJewels, node)
		}
	}
}

func (sim *AttackPathSimulator) calculateExploitability() {
	for _, node := range sim.graph.GetAllNodes() {
		score := 0.5 // Base exploitability

		// Increase for vulnerabilities
		if vulns, ok := node.Properties["vulnerabilities"].([]any); ok {
			score += float64(len(vulns)) * 0.05
		}

		// Increase for public exposure
		if isExposedToInternet(sim.graph, node.ID) {
			score += 0.3
		}

		// Increase for weak auth
		if mfa, ok := node.Properties["mfa_enabled"].(bool); ok && !mfa {
			score += 0.2
		}

		// Decrease for hardened systems
		if _, ok := node.Properties["hardened"]; ok {
			score -= 0.2
		}

		// Clamp to 0-1
		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}

		sim.exploitability[node.ID] = score
	}
}

// Simulate runs the attack path simulation
func (sim *AttackPathSimulator) Simulate(maxPathLength int) *SimulationResult {
	result := &SimulationResult{
		EntryPointCount: len(sim.entryPoints),
		CrownJewelCount: len(sim.crownJewels),
		ShortestPath:    maxPathLength + 1,
	}

	var allPaths []*ScoredAttackPath
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 16)

	// Find paths from each entry point to each crown jewel
	for _, entry := range sim.entryPoints {
		for _, target := range sim.crownJewels {
			if entry.ID == target.ID {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(e, t *Node) {
				defer wg.Done()
				defer func() { <-sem }()

				paths := sim.findAttackPaths(e, t, maxPathLength)
				if len(paths) > 0 {
					mu.Lock()
					allPaths = append(allPaths, paths...)
					mu.Unlock()
				}
			}(entry, target)
		}
	}

	wg.Wait()

	// Score and rank paths
	for _, path := range allPaths {
		sim.scorePath(path)
		if path.Length < result.ShortestPath {
			result.ShortestPath = path.Length
		}
	}

	// Sort by total score descending
	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].TotalScore > allPaths[j].TotalScore
	})

	// Assign priorities
	for i, path := range allPaths {
		path.Priority = i + 1
	}

	// Count critical paths (score > 70)
	for _, path := range allPaths {
		if path.TotalScore >= 70 {
			result.CriticalPaths++
		}
	}

	result.Paths = allPaths
	result.TotalPaths = len(allPaths)

	// Calculate mean path length
	if len(allPaths) > 0 {
		totalLen := 0
		for _, p := range allPaths {
			totalLen += p.Length
		}
		result.MeanPathLength = float64(totalLen) / float64(len(allPaths))
	}

	// Find chokepoints
	result.Chokepoints = sim.findChokepoints(allPaths)

	return result
}

func (sim *AttackPathSimulator) findAttackPaths(entry, target *Node, maxLen int) []*ScoredAttackPath {
	var paths []*ScoredAttackPath

	// Use modified Dijkstra to find shortest attack path
	// We want paths that are actually exploitable

	initial := &pathState{
		nodeID:  entry.ID,
		path:    nil,
		visited: map[string]bool{entry.ID: true},
		cost:    0,
	}

	// Priority queue (min-heap by cost, but we want high exploitability so invert)
	pq := &pathQueue{initial}
	heap.Init(pq)

	foundPaths := make(map[string]bool)

	for pq.Len() > 0 && len(paths) < 5 { // Limit to 5 paths per entry/target pair
		current, _ := heap.Pop(pq).(*pathState) //nolint:errcheck

		if len(current.path) > maxLen {
			continue
		}

		if current.nodeID == target.ID {
			pathID := fmt.Sprintf("%s->%s-%d", entry.ID, target.ID, len(paths))
			if !foundPaths[pathID] {
				foundPaths[pathID] = true
				paths = append(paths, &ScoredAttackPath{
					ID:         pathID,
					EntryPoint: entry,
					Target:     target,
					Steps:      current.path,
					Length:     len(current.path),
				})
			}
			continue
		}

		// Explore outbound edges
		for _, edge := range sim.graph.GetOutEdges(current.nodeID) {
			if current.visited[edge.Target] {
				continue
			}
			if edge.IsDeny() {
				continue
			}

			targetNode, ok := sim.graph.GetNode(edge.Target)
			if !ok {
				continue
			}

			// Calculate step cost (inverse of exploitability)
			stepCost := 1.0 - sim.exploitability[edge.Target]
			if stepCost < 0.1 {
				stepCost = 0.1
			}

			newVisited := make(map[string]bool)
			for k, v := range current.visited {
				newVisited[k] = v
			}
			newVisited[edge.Target] = true

			newStep := &AttackStep{
				Order:         len(current.path) + 1,
				FromNode:      current.nodeID,
				ToNode:        edge.Target,
				Technique:     edgeToTechnique(edge.Kind),
				EdgeKind:      edge.Kind,
				Description:   fmt.Sprintf("Move from %s to %s via %s", current.nodeID, targetNode.Name, edge.Kind),
				MITREAttackID: edgeToMITRE(edge.Kind),
			}

			newPath := append([]*AttackStep{}, current.path...)
			newPath = append(newPath, newStep)

			heap.Push(pq, &pathState{
				nodeID:  edge.Target,
				path:    newPath,
				visited: newVisited,
				cost:    current.cost + stepCost,
			})
		}
	}

	return paths
}

func (sim *AttackPathSimulator) scorePath(path *ScoredAttackPath) {
	// Exploitability: average of step exploitabilities
	totalExp := 0.0
	for _, step := range path.Steps {
		totalExp += sim.exploitability[step.ToNode]
	}
	if len(path.Steps) > 0 {
		path.Exploitability = totalExp / float64(len(path.Steps))
	}

	// Impact: based on target criticality
	path.Impact = calculateNodeImpact(path.Target)

	// Likelihood: based on entry point exposure
	path.Likelihood = sim.exploitability[path.EntryPoint.ID]

	// Total score: weighted combination
	// Shorter paths are more dangerous
	lengthFactor := 1.0 - (float64(path.Length) / 10.0)
	if lengthFactor < 0.3 {
		lengthFactor = 0.3
	}

	path.TotalScore = (path.Exploitability*30 + path.Impact*40 + path.Likelihood*20 + lengthFactor*10)

	// Determine required skill
	if path.TotalScore > 80 {
		path.RequiredSkill = "low"
		path.EstimatedTime = "minutes"
	} else if path.TotalScore > 60 {
		path.RequiredSkill = "medium"
		path.EstimatedTime = "hours"
	} else if path.TotalScore > 40 {
		path.RequiredSkill = "high"
		path.EstimatedTime = "days"
	} else {
		path.RequiredSkill = "expert"
		path.EstimatedTime = "weeks"
	}
}

func (sim *AttackPathSimulator) findChokepoints(paths []*ScoredAttackPath) []*Chokepoint {
	// Count how many paths go through each node
	nodePathCount := make(map[string]int)
	nodeUpstream := make(map[string]map[string]bool)
	nodeDownstream := make(map[string]map[string]bool)

	for _, path := range paths {
		pathNodes := make(map[string]bool)
		for _, step := range path.Steps {
			pathNodes[step.ToNode] = true
			pathNodes[step.FromNode] = true
		}

		for nodeID := range pathNodes {
			if nodeID == path.EntryPoint.ID || nodeID == path.Target.ID {
				continue
			}
			nodePathCount[nodeID]++

			if nodeUpstream[nodeID] == nil {
				nodeUpstream[nodeID] = make(map[string]bool)
			}
			nodeUpstream[nodeID][path.EntryPoint.ID] = true

			if nodeDownstream[nodeID] == nil {
				nodeDownstream[nodeID] = make(map[string]bool)
			}
			nodeDownstream[nodeID][path.Target.ID] = true
		}
	}

	// Convert to chokepoints
	chokepoints := make([]*Chokepoint, 0, len(nodePathCount))
	for nodeID, count := range nodePathCount {
		if count < 2 {
			continue // Only nodes with multiple paths through them
		}

		node, ok := sim.graph.GetNode(nodeID)
		if !ok {
			continue
		}

		upstream := make([]string, 0, len(nodeUpstream[nodeID]))
		for id := range nodeUpstream[nodeID] {
			upstream = append(upstream, id)
		}

		downstream := make([]string, 0, len(nodeDownstream[nodeID]))
		for id := range nodeDownstream[nodeID] {
			downstream = append(downstream, id)
		}

		// Calculate betweenness centrality approximation
		centrality := float64(count) / float64(len(paths))

		// Calculate remediation impact
		// Higher if blocking this node blocks more paths
		impact := float64(count) / float64(len(paths))

		chokepoints = append(chokepoints, &Chokepoint{
			Node:                  node,
			PathsThrough:          count,
			BetweennessCentrality: centrality,
			BlockedPaths:          count,
			RemediationImpact:     impact,
			UpstreamEntries:       upstream,
			DownstreamTargets:     downstream,
		})
	}

	// Sort by remediation impact descending
	sort.Slice(chokepoints, func(i, j int) bool {
		return chokepoints[i].RemediationImpact > chokepoints[j].RemediationImpact
	})

	return chokepoints
}

// pathState is used for pathfinding algorithms
type pathState struct {
	nodeID  string
	path    []*AttackStep
	visited map[string]bool
	cost    float64
}

// Priority queue implementation for pathfinding
type pathQueue []*pathState

func (pq pathQueue) Len() int { return len(pq) }

func (pq pathQueue) Less(i, j int) bool {
	return pq[i].cost < pq[j].cost
}

func (pq pathQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *pathQueue) Push(x any) {
	item, _ := x.(*pathState) //nolint:errcheck
	*pq = append(*pq, item)
}

func (pq *pathQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

// Helper
func hasTag(node *Node, tag string) bool {
	if node.Tags == nil {
		return false
	}
	_, exists := node.Tags[tag]
	return exists
}

// GetCriticalPaths returns only the highest-risk attack paths
func (sim *AttackPathSimulator) GetCriticalPaths(result *SimulationResult, threshold float64) []*ScoredAttackPath {
	var critical []*ScoredAttackPath
	for _, path := range result.Paths {
		if path.TotalScore >= threshold {
			critical = append(critical, path)
		}
	}
	return critical
}

// GetRemediationPriorities returns chokepoints sorted by ROI
func (sim *AttackPathSimulator) GetRemediationPriorities(result *SimulationResult) []*Chokepoint {
	// Already sorted by RemediationImpact in findChokepoints
	return result.Chokepoints
}

// SimulateFix returns what paths would be blocked by fixing a node
func (sim *AttackPathSimulator) SimulateFix(result *SimulationResult, nodeID string) *FixSimulation {
	fixSim := &FixSimulation{
		FixedNode:      nodeID,
		BlockedPaths:   make([]*ScoredAttackPath, 0),
		RemainingPaths: make([]*ScoredAttackPath, 0),
	}

	for _, path := range result.Paths {
		blocked := false
		for _, step := range path.Steps {
			if step.FromNode == nodeID || step.ToNode == nodeID {
				blocked = true
				break
			}
		}

		if blocked {
			fixSim.BlockedPaths = append(fixSim.BlockedPaths, path)
		} else {
			fixSim.RemainingPaths = append(fixSim.RemainingPaths, path)
		}
	}

	fixSim.BlockedCount = len(fixSim.BlockedPaths)
	fixSim.RemainingCount = len(fixSim.RemainingPaths)

	// Calculate risk reduction
	var blockedRisk, totalRisk float64
	for _, p := range result.Paths {
		totalRisk += p.TotalScore
	}
	for _, p := range fixSim.BlockedPaths {
		blockedRisk += p.TotalScore
	}
	if totalRisk > 0 {
		fixSim.RiskReduction = blockedRisk / totalRisk
	}

	return fixSim
}

// FixSimulation shows the impact of remediating a specific node
type FixSimulation struct {
	FixedNode      string              `json:"fixed_node"`
	BlockedPaths   []*ScoredAttackPath `json:"blocked_paths"`
	BlockedCount   int                 `json:"blocked_count"`
	RemainingPaths []*ScoredAttackPath `json:"remaining_paths"`
	RemainingCount int                 `json:"remaining_count"`
	RiskReduction  float64             `json:"risk_reduction"` // 0-1
}
