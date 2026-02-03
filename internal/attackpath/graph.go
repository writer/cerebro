package attackpath

import (
	"context"
	"sort"
	"strconv"
	"sync"
)

// Graph represents the attack path graph
type Graph struct {
	nodes map[string]*Node
	edges map[string][]*Edge
	mu    sync.RWMutex
}

// Node represents an entity in the attack graph
type Node struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Name       string                 `json:"name"`
	Provider   string                 `json:"provider"`
	Account    string                 `json:"account"`
	Region     string                 `json:"region,omitempty"`
	Risk       RiskLevel              `json:"risk"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Findings   []string               `json:"findings,omitempty"`
}

type NodeType string

const (
	NodeTypeIdentity NodeType = "identity"
	NodeTypeRole     NodeType = "role"
	NodeTypeResource NodeType = "resource"
	NodeTypeNetwork  NodeType = "network"
	NodeTypeCompute  NodeType = "compute"
	NodeTypeStorage  NodeType = "storage"
	NodeTypeDatabase NodeType = "database"
	NodeTypeSecret   NodeType = "secret"
	NodeTypeExternal NodeType = "external"
)

type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskNone     RiskLevel = "none"
)

// Edge represents a relationship between nodes
type Edge struct {
	ID         string                 `json:"id"`
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Type       EdgeType               `json:"type"`
	Risk       RiskLevel              `json:"risk"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type EdgeType string

const (
	EdgeTypeCanAssume     EdgeType = "can_assume"
	EdgeTypeHasAccess     EdgeType = "has_access"
	EdgeTypeCanModify     EdgeType = "can_modify"
	EdgeTypeCanDelete     EdgeType = "can_delete"
	EdgeTypeCanRead       EdgeType = "can_read"
	EdgeTypeNetworkAccess EdgeType = "network_access"
	EdgeTypeMemberOf      EdgeType = "member_of"
	EdgeTypeAttachedTo    EdgeType = "attached_to"
	EdgeTypeTrusts        EdgeType = "trusts"
	EdgeTypeExposedTo     EdgeType = "exposed_to"
)

// AttackPath represents a discovered attack path
type AttackPath struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    RiskLevel    `json:"severity"`
	Score       int          `json:"score"`
	Nodes       []string     `json:"nodes"`
	Edges       []string     `json:"edges"`
	Steps       []AttackStep `json:"steps"`
	Remediation []string     `json:"remediation"`
}

type AttackStep struct {
	Order       int    `json:"order"`
	Action      string `json:"action"`
	Source      string `json:"source"`
	Target      string `json:"target"`
	Technique   string `json:"technique,omitempty"` // MITRE ATT&CK technique
	Description string `json:"description"`
}

func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string][]*Edge),
	}
}

func (g *Graph) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.ID] = node
}

func (g *Graph) AddEdge(edge *Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[edge.Source] = append(g.edges[edge.Source], edge)
}

func (g *Graph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

func (g *Graph) GetEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.edges[nodeID]
}

func (g *Graph) GetAllNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// PathFinder discovers attack paths in the graph
type PathFinder struct {
	graph     *Graph
	maxDepth  int
	highValue map[string]bool // high-value target node IDs
}

func NewPathFinder(graph *Graph, maxDepth int) *PathFinder {
	return &PathFinder{
		graph:     graph,
		maxDepth:  maxDepth,
		highValue: make(map[string]bool),
	}
}

func (pf *PathFinder) SetHighValueTargets(nodeIDs []string) {
	for _, id := range nodeIDs {
		pf.highValue[id] = true
	}
}

// FindPaths discovers attack paths from external entry points to high-value targets
func (pf *PathFinder) FindPaths(ctx context.Context) []*AttackPath {
	var paths []*AttackPath

	// Find entry points (external-facing or compromised nodes)
	entryPoints := pf.findEntryPoints()

	for _, entry := range entryPoints {
		// BFS to find paths to high-value targets
		discovered := pf.bfs(entry.ID, pf.maxDepth)

		for targetID, path := range discovered {
			if pf.highValue[targetID] {
				attackPath := pf.buildAttackPath(entry, path)
				if attackPath != nil {
					paths = append(paths, attackPath)
				}
			}
		}
	}

	// Sort by severity/score
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Score > paths[j].Score
	})

	return paths
}

func (pf *PathFinder) findEntryPoints() []*Node {
	var entries []*Node

	for _, node := range pf.graph.nodes {
		// External-facing resources
		if node.Type == NodeTypeExternal {
			entries = append(entries, node)
			continue
		}

		// Public resources
		if public, ok := node.Properties["public"].(bool); ok && public {
			entries = append(entries, node)
			continue
		}

		// Resources with critical findings
		if node.Risk == RiskCritical && len(node.Findings) > 0 {
			entries = append(entries, node)
		}
	}

	return entries
}

func (pf *PathFinder) bfs(startID string, maxDepth int) map[string][]string {
	discovered := make(map[string][]string)
	visited := make(map[string]bool)
	queue := []struct {
		nodeID string
		path   []string
		depth  int
	}{{startID, []string{startID}, 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= maxDepth {
			continue
		}

		if visited[current.nodeID] {
			continue
		}
		visited[current.nodeID] = true

		edges := pf.graph.GetEdges(current.nodeID)
		for _, edge := range edges {
			newPath := append([]string{}, current.path...)
			newPath = append(newPath, edge.Target)

			discovered[edge.Target] = newPath

			queue = append(queue, struct {
				nodeID string
				path   []string
				depth  int
			}{edge.Target, newPath, current.depth + 1})
		}
	}

	return discovered
}

func (pf *PathFinder) buildAttackPath(entry *Node, nodePath []string) *AttackPath {
	if len(nodePath) < 2 {
		return nil
	}

	path := &AttackPath{
		ID:    entry.ID + "-" + nodePath[len(nodePath)-1],
		Nodes: nodePath,
		Steps: make([]AttackStep, 0),
	}

	// Build steps from edges
	var edgeIDs []string
	score := 0

	for i := 0; i < len(nodePath)-1; i++ {
		sourceID := nodePath[i]
		targetID := nodePath[i+1]

		edges := pf.graph.GetEdges(sourceID)
		for _, edge := range edges {
			if edge.Target == targetID {
				edgeIDs = append(edgeIDs, edge.ID)

				sourceNode, _ := pf.graph.GetNode(sourceID)
				targetNode, _ := pf.graph.GetNode(targetID)

				step := AttackStep{
					Order:  i + 1,
					Action: string(edge.Type),
					Source: sourceNode.Name,
					Target: targetNode.Name,
				}

				// Add MITRE technique mapping
				step.Technique = mapToMITRE(edge.Type, targetNode.Type)
				step.Description = describeStep(edge, sourceNode, targetNode)

				path.Steps = append(path.Steps, step)

				// Calculate score based on edge risk
				score += riskScore(edge.Risk)
			}
		}
	}

	path.Edges = edgeIDs
	path.Score = score
	path.Severity = scoreSeverity(score)
	path.Title = generateTitle(path)
	path.Description = generateDescription(path)
	path.Remediation = generateRemediation(path)

	return path
}

func mapToMITRE(edgeType EdgeType, _ NodeType) string {
	// Map edge types to MITRE ATT&CK techniques
	mapping := map[EdgeType]string{
		EdgeTypeCanAssume:     "T1078", // Valid Accounts
		EdgeTypeHasAccess:     "T1078", // Valid Accounts
		EdgeTypeCanModify:     "T1098", // Account Manipulation
		EdgeTypeNetworkAccess: "T1021", // Remote Services
		EdgeTypeExposedTo:     "T1190", // Exploit Public-Facing Application
	}

	if technique, ok := mapping[edgeType]; ok {
		return technique
	}
	return ""
}

func describeStep(edge *Edge, source, target *Node) string {
	switch edge.Type {
	case EdgeTypeCanAssume:
		return source.Name + " can assume role " + target.Name
	case EdgeTypeHasAccess:
		return source.Name + " has access to " + target.Name
	case EdgeTypeCanModify:
		return source.Name + " can modify " + target.Name
	case EdgeTypeNetworkAccess:
		return source.Name + " has network access to " + target.Name
	case EdgeTypeExposedTo:
		return target.Name + " is exposed to " + source.Name
	default:
		return source.Name + " -> " + target.Name
	}
}

func riskScore(risk RiskLevel) int {
	switch risk {
	case RiskCritical:
		return 40
	case RiskHigh:
		return 30
	case RiskMedium:
		return 20
	case RiskLow:
		return 10
	default:
		return 5
	}
}

func scoreSeverity(score int) RiskLevel {
	switch {
	case score >= 100:
		return RiskCritical
	case score >= 70:
		return RiskHigh
	case score >= 40:
		return RiskMedium
	default:
		return RiskLow
	}
}

func generateTitle(path *AttackPath) string {
	if len(path.Nodes) < 2 {
		return "Unknown Attack Path"
	}
	return "Attack path from external to high-value target"
}

func generateDescription(path *AttackPath) string {
	return "This attack path shows how an attacker could reach a high-value target through " +
		strconv.Itoa(len(path.Steps)) + " steps"
}

func generateRemediation(path *AttackPath) []string {
	var remediation []string

	for _, step := range path.Steps {
		switch step.Action {
		case string(EdgeTypeCanAssume):
			remediation = append(remediation, "Review and restrict role assumption policies")
		case string(EdgeTypeExposedTo):
			remediation = append(remediation, "Restrict public access to resources")
		case string(EdgeTypeNetworkAccess):
			remediation = append(remediation, "Review network security group rules")
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, r := range remediation {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}

	return unique
}
