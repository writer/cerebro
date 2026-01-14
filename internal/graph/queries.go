package graph

// BlastRadiusResult represents the result of a blast radius analysis
type BlastRadiusResult struct {
	PrincipalID      string           `json:"principal_id"`
	PrincipalName    string           `json:"principal_name"`
	ReachableNodes   []*ReachableNode `json:"reachable_nodes"`
	TotalCount       int              `json:"total_count"`
	MaxDepth         int              `json:"max_depth"`
	CrossAccountRisk bool             `json:"cross_account_risk"`
	AccountsReached  int              `json:"accounts_reached"`
	ForeignAccounts  []string         `json:"foreign_accounts"`
	RiskSummary      RiskSummary      `json:"risk_summary"`
}

// ReachableNode represents a node reachable from a principal
type ReachableNode struct {
	Node     *Node    `json:"node"`
	Depth    int      `json:"depth"`
	Path     []string `json:"path"`
	EdgeKind EdgeKind `json:"edge_kind"`
	Actions  []string `json:"actions,omitempty"`
}

// RiskSummary summarizes the risk levels of reachable nodes
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// BlastRadius performs forward reachability analysis from a principal
func BlastRadius(g *Graph, principalID string, maxDepth int) *BlastRadiusResult {
	principal, ok := g.GetNode(principalID)
	if !ok {
		return &BlastRadiusResult{PrincipalID: principalID}
	}

	result := &BlastRadiusResult{
		PrincipalID:   principalID,
		PrincipalName: principal.Name,
		MaxDepth:      maxDepth,
	}

	startAccount := principal.Account
	visited := make(map[string]bool)
	accountsReached := make(map[string]bool)

	type queueItem struct {
		nodeID string
		depth  int
		path   []string
	}
	queue := []queueItem{{principalID, 0, []string{principalID}}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if item.depth > maxDepth || visited[item.nodeID] {
			continue
		}
		visited[item.nodeID] = true

		for _, edge := range g.GetOutEdges(item.nodeID) {
			// Skip deny edges - they block access
			if edge.IsDeny() {
				continue
			}

			// Check if there's a deny that blocks this allow
			if isDenied(g, item.nodeID, edge.Target) {
				continue
			}

			targetNode, ok := g.GetNode(edge.Target)
			if !ok {
				continue
			}

			newPath := append([]string{}, item.path...)
			newPath = append(newPath, edge.Target)

			// Track cross-account access
			if edge.IsCrossAccount() {
				result.CrossAccountRisk = true
				if targetAccount, ok := edge.Properties["target_account"].(string); ok {
					accountsReached[targetAccount] = true
				}
			}
			if targetNode.Account != "" && targetNode.Account != startAccount {
				accountsReached[targetNode.Account] = true
			}

			// Only collect resource nodes in results
			if targetNode.IsResource() {
				var actions []string
				if a, ok := edge.Properties["actions"].([]string); ok {
					actions = a
				}

				result.ReachableNodes = append(result.ReachableNodes, &ReachableNode{
					Node:     targetNode,
					Depth:    item.depth + 1,
					Path:     newPath,
					EdgeKind: edge.Kind,
					Actions:  actions,
				})

				// Update risk summary
				switch targetNode.Risk {
				case RiskCritical:
					result.RiskSummary.Critical++
				case RiskHigh:
					result.RiskSummary.High++
				case RiskMedium:
					result.RiskSummary.Medium++
				case RiskLow:
					result.RiskSummary.Low++
				}
			}

			// Continue traversal for role chains
			queue = append(queue, queueItem{
				nodeID: edge.Target,
				depth:  item.depth + 1,
				path:   newPath,
			})
		}
	}

	result.TotalCount = len(result.ReachableNodes)
	result.AccountsReached = len(accountsReached)
	if startAccount != "" {
		delete(accountsReached, startAccount)
	}
	for acc := range accountsReached {
		result.ForeignAccounts = append(result.ForeignAccounts, acc)
	}

	return result
}

// ReverseAccessResult represents who can access a resource
type ReverseAccessResult struct {
	ResourceID   string          `json:"resource_id"`
	ResourceName string          `json:"resource_name"`
	AccessibleBy []*AccessorNode `json:"accessible_by"`
	TotalCount   int             `json:"total_count"`
}

// AccessorNode represents a principal that can access a resource
type AccessorNode struct {
	Node     *Node    `json:"node"`
	EdgeKind EdgeKind `json:"edge_kind"`
	Path     []string `json:"path"`
	Actions  []string `json:"actions,omitempty"`
}

// ReverseAccess finds all principals that can access a resource
func ReverseAccess(g *Graph, resourceID string, maxDepth int) *ReverseAccessResult {
	resource, ok := g.GetNode(resourceID)
	if !ok {
		return &ReverseAccessResult{ResourceID: resourceID}
	}

	result := &ReverseAccessResult{
		ResourceID:   resourceID,
		ResourceName: resource.Name,
	}

	visited := make(map[string]bool)
	type queueItem struct {
		nodeID string
		depth  int
		path   []string
	}
	queue := []queueItem{{resourceID, 0, []string{resourceID}}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if item.depth > maxDepth || visited[item.nodeID] {
			continue
		}
		visited[item.nodeID] = true

		// Use inbound edges for reverse traversal
		for _, edge := range g.GetInEdges(item.nodeID) {
			if edge.IsDeny() {
				continue
			}

			sourceNode, ok := g.GetNode(edge.Source)
			if !ok {
				continue
			}

			newPath := append([]string{edge.Source}, item.path...)

			// Collect identity nodes
			if sourceNode.IsIdentity() {
				var actions []string
				if a, ok := edge.Properties["actions"].([]string); ok {
					actions = a
				}

				result.AccessibleBy = append(result.AccessibleBy, &AccessorNode{
					Node:     sourceNode,
					EdgeKind: edge.Kind,
					Path:     newPath,
					Actions:  actions,
				})
			}

			queue = append(queue, queueItem{
				nodeID: edge.Source,
				depth:  item.depth + 1,
				path:   newPath,
			})
		}
	}

	result.TotalCount = len(result.AccessibleBy)
	return result
}

// EffectiveAccessResult shows whether a principal can access a resource
type EffectiveAccessResult struct {
	PrincipalID string  `json:"principal_id"`
	ResourceID  string  `json:"resource_id"`
	Allowed     bool    `json:"allowed"`
	DeniedBy    []*Edge `json:"denied_by,omitempty"`
	AllowedBy   []*Edge `json:"allowed_by,omitempty"`
}

// EffectiveAccess determines if a principal can access a resource
func EffectiveAccess(g *Graph, principalID, resourceID string, maxDepth int) *EffectiveAccessResult {
	result := &EffectiveAccessResult{
		PrincipalID: principalID,
		ResourceID:  resourceID,
	}

	paths := findAllPaths(g, principalID, resourceID, maxDepth)

	for _, path := range paths {
		hasDeny := false
		hasAllow := false

		for _, edge := range path {
			if edge.IsDeny() {
				hasDeny = true
				result.DeniedBy = append(result.DeniedBy, edge)
			} else {
				hasAllow = true
				result.AllowedBy = append(result.AllowedBy, edge)
			}
		}

		if hasAllow && !hasDeny {
			result.Allowed = true
		}
	}

	return result
}

func findAllPaths(g *Graph, from, to string, maxDepth int) [][]*Edge {
	var allPaths [][]*Edge

	type state struct {
		nodeID  string
		depth   int
		path    []*Edge
		visited map[string]bool
	}

	initial := state{
		nodeID:  from,
		depth:   0,
		path:    nil,
		visited: map[string]bool{from: true},
	}
	queue := []state{initial}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth > maxDepth {
			continue
		}

		for _, edge := range g.GetOutEdges(current.nodeID) {
			if current.visited[edge.Target] {
				continue
			}

			newPath := append([]*Edge{}, current.path...)
			newPath = append(newPath, edge)
			newVisited := make(map[string]bool)
			for k, v := range current.visited {
				newVisited[k] = v
			}
			newVisited[edge.Target] = true

			if edge.Target == to {
				allPaths = append(allPaths, newPath)
			} else {
				queue = append(queue, state{
					nodeID:  edge.Target,
					depth:   current.depth + 1,
					path:    newPath,
					visited: newVisited,
				})
			}
		}
	}

	return allPaths
}

func isDenied(g *Graph, source, target string) bool {
	for _, edge := range g.GetOutEdges(source) {
		if edge.Target == target && edge.IsDeny() {
			return true
		}
	}
	return false
}
