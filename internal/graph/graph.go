package graph

import (
	"sync"
	"time"
)

var temporalNowUTC = func() time.Time {
	return time.Now().UTC()
}

// Graph represents the security graph containing all nodes and edges
type Graph struct {
	nodes    map[string]*Node
	outEdges map[string][]*Edge // source -> edges
	inEdges  map[string][]*Edge // target -> edges
	mu       sync.RWMutex
	metadata Metadata

	// Traversal cache for expensive reachability queries.
	blastRadiusCache   sync.Map
	blastRadiusVersion uint64

	// Indexes for O(1) lookups - rebuilt on BuildIndex()
	indexByKind      map[NodeKind][]*Node
	indexByAccount   map[string][]*Node
	indexByRisk      map[RiskLevel][]*Node
	indexByProvider  map[string][]*Node
	indexByARNPrefix map[string][]*Node // "service:resourceType" -> nodes for fast ARN matching
	crossAccountEdge []*Edge
	internetNodes    []*Node // Pre-computed internet-facing nodes
	crownJewels      []*Node // Pre-computed high-value targets
	indexBuilt       bool
}

// Metadata contains information about the graph
type Metadata struct {
	BuiltAt       time.Time     `json:"built_at"`
	NodeCount     int           `json:"node_count"`
	EdgeCount     int           `json:"edge_count"`
	Providers     []string      `json:"providers"`
	Accounts      []string      `json:"accounts"`
	BuildDuration time.Duration `json:"build_duration_ms"`
}

// New creates a new empty graph
func New() *Graph {
	return &Graph{
		nodes:              make(map[string]*Node),
		outEdges:           make(map[string][]*Edge),
		inEdges:            make(map[string][]*Edge),
		blastRadiusVersion: 1,
	}
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node *Node) {
	if node == nil || node.ID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.addNodeLocked(node)
	g.markGraphChangedLocked()
}

// AddNodesBatch adds multiple nodes in a single lock acquisition
func (g *Graph) AddNodesBatch(nodes []*Node) {
	if len(nodes) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, node := range nodes {
		if node == nil || node.ID == "" {
			continue
		}
		g.addNodeLocked(node)
	}
	g.markGraphChangedLocked()
}

// AddEdge adds an edge to the graph
func (g *Graph) AddEdge(edge *Edge) {
	if edge == nil || edge.Source == "" || edge.Target == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.addEdgeLocked(edge)
	g.markGraphChangedLocked()
}

// AddEdgesBatch adds multiple edges in a single lock acquisition
func (g *Graph) AddEdgesBatch(edges []*Edge) {
	if len(edges) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, edge := range edges {
		if edge == nil || edge.Source == "" || edge.Target == "" {
			continue
		}
		g.addEdgeLocked(edge)
	}
	g.markGraphChangedLocked()
}

// RemoveNode removes a node and all edges touching it.
func (g *Graph) RemoveNode(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	node, ok := g.nodes[id]
	if !ok || node.DeletedAt != nil {
		return false
	}

	now := temporalNowUTC()
	node.DeletedAt = &now
	node.UpdatedAt = now
	if node.Version <= 0 {
		node.Version = 1
	}
	node.Version++
	g.removeEdgesByNodeLocked(id)
	g.markGraphChangedLocked()
	return true
}

// RemoveEdge removes all edges matching source, target, and kind.
func (g *Graph) RemoveEdge(source, target string, kind EdgeKind) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	removed := false
	if edges, ok := g.outEdges[source]; ok {
		for _, edge := range edges {
			if edge == nil || edge.DeletedAt != nil {
				continue
			}
			if edge.Source == source && edge.Target == target && edge.Kind == kind {
				now := temporalNowUTC()
				edge.DeletedAt = &now
				if edge.Version <= 0 {
					edge.Version = 1
				}
				edge.Version++
				removed = true
			}
		}
	}

	if removed {
		g.markGraphChangedLocked()
	}
	return removed
}

// RemoveEdgesByNode removes all edges connected to nodeID.
func (g *Graph) RemoveEdgesByNode(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.removeEdgesByNodeLocked(nodeID) {
		g.markGraphChangedLocked()
	}
}

// SetNodeProperty sets or updates a single property on a node.
func (g *Graph) SetNodeProperty(id string, key string, value any) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	node, ok := g.nodes[id]
	if !ok || node.DeletedAt != nil {
		return false
	}

	node.PreviousProperties = cloneAnyMap(node.Properties)
	if node.Properties == nil {
		node.Properties = make(map[string]any)
	}
	node.Properties[key] = value
	now := temporalNowUTC()
	if node.CreatedAt.IsZero() {
		node.CreatedAt = now
	}
	node.UpdatedAt = now
	if node.Version <= 0 {
		node.Version = 1
	}
	node.Version++
	g.appendNodePropertyHistoryLocked(node, key, value, now)
	g.markGraphChangedLocked()
	return true
}

// Clone returns a deep copy of the graph via snapshot/restore.
func (g *Graph) Clone() *Graph {
	return RestoreFromSnapshot(CreateSnapshot(g))
}

// GetNode retrieves a node by ID
func (g *Graph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	if !ok || n == nil || n.DeletedAt != nil {
		return nil, false
	}
	return n, true
}

// GetNodeIncludingDeleted retrieves a node by ID, including soft-deleted nodes.
func (g *Graph) GetNodeIncludingDeleted(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// GetOutEdges returns edges originating from a node
func (g *Graph) GetOutEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeEdgesForNodeLocked(g.outEdges[nodeID])
}

// GetInEdges returns edges pointing to a node
func (g *Graph) GetInEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.activeEdgesForNodeLocked(g.inEdges[nodeID])
}

// GetAllNodes returns all nodes in the graph
func (g *Graph) GetAllNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		if n == nil || n.DeletedAt != nil {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// GetAllNodesIncludingDeleted returns all nodes, including soft-deleted nodes.
func (g *Graph) GetAllNodesIncludingDeleted() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		if n == nil {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// Nodes returns active (non-deleted) nodes.
func (g *Graph) Nodes() []*Node {
	return g.GetAllNodes()
}

// NodesIncludingDeleted returns all nodes, including soft-deleted nodes.
func (g *Graph) NodesIncludingDeleted() []*Node {
	return g.GetAllNodesIncludingDeleted()
}

// GetNodesByKind returns nodes of specific kinds
func (g *Graph) GetNodesByKind(kinds ...NodeKind) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	kindSet := make(map[NodeKind]bool)
	for _, k := range kinds {
		kindSet[k] = true
	}
	var nodes []*Node
	for _, n := range g.nodes {
		if n == nil || n.DeletedAt != nil {
			continue
		}
		if kindSet[n.Kind] {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// GetNodesByAccount returns nodes belonging to a specific account
func (g *Graph) GetNodesByAccount(accountID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var nodes []*Node
	for _, n := range g.nodes {
		if n == nil || n.DeletedAt != nil {
			continue
		}
		if n.Account == accountID {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// GetCrossAccountEdges returns all edges that cross account boundaries
func (g *Graph) GetCrossAccountEdges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var edges []*Edge
	for _, edgeList := range g.outEdges {
		for _, e := range edgeList {
			if !g.activeEdgeLocked(e) {
				continue
			}
			if e.IsCrossAccount() {
				edges = append(edges, e)
			}
		}
	}
	return edges
}

// GetAllEdges returns all edges grouped by source node
func (g *Graph) GetAllEdges() map[string][]*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make(map[string][]*Edge)
	for source, edges := range g.outEdges {
		active := g.activeEdgesForNodeLocked(edges)
		if len(active) == 0 {
			continue
		}
		result[source] = active
	}
	return result
}

// NodeCount returns the number of nodes
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, node := range g.nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		count++
	}
	return count
}

// EdgeCount returns the total number of edges
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, edges := range g.outEdges {
		for _, edge := range edges {
			if g.activeEdgeLocked(edge) {
				count++
			}
		}
	}
	return count
}

// Clear removes all nodes and edges
func (g *Graph) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes = make(map[string]*Node)
	g.outEdges = make(map[string][]*Edge)
	g.inEdges = make(map[string][]*Edge)
	g.markGraphChangedLocked()
}

// ClearEdges removes all edges while preserving nodes.
func (g *Graph) ClearEdges() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.outEdges = make(map[string][]*Edge)
	g.inEdges = make(map[string][]*Edge)
	g.markGraphChangedLocked()
}

// SetMetadata sets the graph metadata
func (g *Graph) SetMetadata(m Metadata) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.metadata = m
}

// Metadata returns the graph metadata
func (g *Graph) Metadata() Metadata {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.metadata
}

// BuildIndex builds all secondary indexes for O(1) lookups.
// Should be called after bulk graph construction for optimal performance.
func (g *Graph) BuildIndex() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Initialize index maps
	g.indexByKind = make(map[NodeKind][]*Node)
	g.indexByAccount = make(map[string][]*Node)
	g.indexByRisk = make(map[RiskLevel][]*Node)
	g.indexByProvider = make(map[string][]*Node)
	g.indexByARNPrefix = make(map[string][]*Node)
	g.crossAccountEdge = nil
	g.internetNodes = nil
	g.crownJewels = nil

	// Index all nodes
	for _, node := range g.nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		g.indexByKind[node.Kind] = append(g.indexByKind[node.Kind], node)

		if node.Account != "" {
			g.indexByAccount[node.Account] = append(g.indexByAccount[node.Account], node)
		}

		g.indexByRisk[node.Risk] = append(g.indexByRisk[node.Risk], node)

		if node.Provider != "" {
			g.indexByProvider[node.Provider] = append(g.indexByProvider[node.Provider], node)
		}

		// Index resource nodes by ARN service:resourceType prefix
		if node.IsResource() {
			if parsed, err := ParseARN(node.ID); err == nil {
				prefix := parsed.ResourcePrefix()
				g.indexByARNPrefix[prefix] = append(g.indexByARNPrefix[prefix], node)
			}
		}

		// Pre-compute internet-facing nodes
		if g.isInternetFacing(node) {
			g.internetNodes = append(g.internetNodes, node)
		}

		// Pre-compute crown jewels (high-value targets)
		if g.isCrownJewel(node) {
			g.crownJewels = append(g.crownJewels, node)
		}
	}

	// Index cross-account edges
	for _, edgeList := range g.outEdges {
		for _, edge := range edgeList {
			if !g.activeEdgeLocked(edge) {
				continue
			}
			if edge.IsCrossAccount() {
				g.crossAccountEdge = append(g.crossAccountEdge, edge)
			}
		}
	}

	g.indexBuilt = true
}

// isInternetFacing checks if a node is exposed to the internet
func (g *Graph) isInternetFacing(node *Node) bool {
	if node.Properties == nil {
		return false
	}

	// Check for common internet exposure indicators
	if exposed, ok := node.Properties["internet_exposed"].(bool); ok && exposed {
		return true
	}
	if public, ok := node.Properties["public"].(bool); ok && public {
		return true
	}
	if publicIP, ok := node.Properties["public_ip"].(string); ok && publicIP != "" {
		return true
	}

	// Check specific node types
	switch node.Kind {
	case NodeKindNetwork:
		// Load balancers, API gateways, etc are usually network type
		if nodeType, ok := node.Properties["type"].(string); ok {
			if nodeType == "load_balancer" || nodeType == "api_gateway" || nodeType == "cdn" {
				return true
			}
		}
	case NodeKindInstance:
		if publicIP, ok := node.Properties["public_ip_address"].(string); ok && publicIP != "" {
			return true
		}
	case NodeKindFunction:
		// Lambda/Functions with public URL
		if funcURL, ok := node.Properties["function_url"].(string); ok && funcURL != "" {
			return true
		}
	case NodeKindBucket:
		if public, ok := node.Properties["public_access_block_enabled"].(bool); ok && !public {
			return true
		}
	}

	return false
}

// isCrownJewel checks if a node is a high-value target
func (g *Graph) isCrownJewel(node *Node) bool {
	// High criticality
	if node.Risk == RiskCritical || node.Risk == RiskHigh {
		return true
	}

	if node.Properties == nil {
		return false
	}

	// Contains sensitive data
	if dataClass, ok := node.Properties["data_classification"].(string); ok {
		if dataClass == "confidential" || dataClass == "restricted" || dataClass == "sensitive" {
			return true
		}
	}

	// High-value node kinds
	switch node.Kind {
	case NodeKindDatabase, NodeKindSecret, NodeKindBucket:
		// Check if contains PII/sensitive data
		if containsPII, ok := node.Properties["contains_pii"].(bool); ok && containsPII {
			return true
		}
		// Production databases/buckets
		if env, ok := node.Properties["environment"].(string); ok && env == "production" {
			return true
		}
	case NodeKindRole, NodeKindServiceAccount:
		// Admin roles
		if admin, ok := node.Properties["is_admin"].(bool); ok && admin {
			return true
		}
	}

	return false
}

// GetNodesByKindIndexed returns nodes of specific kinds using the index (O(1) per kind)
func (g *Graph) GetNodesByKindIndexed(kinds ...NodeKind) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.indexBuilt {
		// Fall back to scan if index not built
		return g.getNodesByKindScan(kinds...)
	}

	var result []*Node
	for _, kind := range kinds {
		result = append(result, g.indexByKind[kind]...)
	}
	return result
}

// getNodesByKindScan is the non-indexed fallback
func (g *Graph) getNodesByKindScan(kinds ...NodeKind) []*Node {
	kindSet := make(map[NodeKind]bool)
	for _, k := range kinds {
		kindSet[k] = true
	}
	var nodes []*Node
	for _, n := range g.nodes {
		if n == nil || n.DeletedAt != nil {
			continue
		}
		if kindSet[n.Kind] {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// GetNodesByAccountIndexed returns nodes for an account using the index (O(1))
func (g *Graph) GetNodesByAccountIndexed(accountID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.indexBuilt {
		// Fall back to scan
		var nodes []*Node
		for _, n := range g.nodes {
			if n == nil || n.DeletedAt != nil {
				continue
			}
			if n.Account == accountID {
				nodes = append(nodes, n)
			}
		}
		return nodes
	}

	return g.indexByAccount[accountID]
}

// GetNodesByRisk returns nodes with a specific risk level using the index
func (g *Graph) GetNodesByRisk(risk RiskLevel) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.indexBuilt {
		var nodes []*Node
		for _, n := range g.nodes {
			if n == nil || n.DeletedAt != nil {
				continue
			}
			if n.Risk == risk {
				nodes = append(nodes, n)
			}
		}
		return nodes
	}

	return g.indexByRisk[risk]
}

// GetInternetFacingNodes returns pre-computed internet-facing nodes (O(1))
func (g *Graph) GetInternetFacingNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.indexBuilt {
		var nodes []*Node
		for _, n := range g.nodes {
			if n == nil || n.DeletedAt != nil {
				continue
			}
			if g.isInternetFacing(n) {
				nodes = append(nodes, n)
			}
		}
		return nodes
	}

	return g.internetNodes
}

// GetCrownJewels returns pre-computed high-value target nodes (O(1))
func (g *Graph) GetCrownJewels() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.indexBuilt {
		var nodes []*Node
		for _, n := range g.nodes {
			if n == nil || n.DeletedAt != nil {
				continue
			}
			if g.isCrownJewel(n) {
				nodes = append(nodes, n)
			}
		}
		return nodes
	}

	return g.crownJewels
}

// GetCrossAccountEdgesIndexed returns pre-computed cross-account edges (O(1))
func (g *Graph) GetCrossAccountEdgesIndexed() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.indexBuilt {
		return g.GetCrossAccountEdges()
	}

	return g.crossAccountEdge
}

// InvalidateIndex marks the index as stale (call after modifications)
func (g *Graph) InvalidateIndex() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.markGraphChangedLocked()
}

// IsIndexBuilt returns whether the index is current
func (g *Graph) IsIndexBuilt() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.indexBuilt
}

// GetResourceNodesByARNPrefix returns resource nodes matching a service:resourceType prefix.
// Returns nil if index is not built.
func (g *Graph) GetResourceNodesByARNPrefix(prefix string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.indexBuilt {
		return nil
	}
	return g.indexByARNPrefix[prefix]
}

func (g *Graph) addNodeLocked(node *Node) {
	now := temporalNowUTC()
	if existing, ok := g.nodes[node.ID]; ok && existing != nil {
		if existing.CreatedAt.IsZero() {
			existing.CreatedAt = now
		}
		if node.CreatedAt.IsZero() {
			node.CreatedAt = existing.CreatedAt
		}
		node.PreviousProperties = cloneAnyMap(existing.Properties)
		if len(existing.PropertyHistory) > 0 {
			if node.PropertyHistory == nil {
				node.PropertyHistory = clonePropertyHistoryMap(existing.PropertyHistory)
			} else {
				for property, history := range existing.PropertyHistory {
					if len(node.PropertyHistory[property]) == 0 {
						node.PropertyHistory[property] = clonePropertySnapshots(history)
					}
				}
			}
		}
		if node.Version <= existing.Version {
			node.Version = existing.Version + 1
		}
	}

	if node.CreatedAt.IsZero() {
		node.CreatedAt = now
	}
	if node.UpdatedAt.IsZero() {
		node.UpdatedAt = now
	}
	if node.Version <= 0 {
		node.Version = 1
	}
	node.DeletedAt = nil
	g.appendNodePropertiesHistoryLocked(node, node.UpdatedAt)
	g.nodes[node.ID] = node
}

func (g *Graph) addEdgeLocked(edge *Edge) {
	now := temporalNowUTC()
	if edge.CreatedAt.IsZero() {
		edge.CreatedAt = now
	}
	if edge.Version <= 0 {
		edge.Version = 1
	}
	edge.DeletedAt = nil
	g.outEdges[edge.Source] = append(g.outEdges[edge.Source], edge)
	g.inEdges[edge.Target] = append(g.inEdges[edge.Target], edge)
}

func (g *Graph) activeEdgesForNodeLocked(edges []*Edge) []*Edge {
	if len(edges) == 0 {
		return nil
	}
	active := make([]*Edge, 0, len(edges))
	for _, edge := range edges {
		if g.activeEdgeLocked(edge) {
			active = append(active, edge)
		}
	}
	return active
}

func (g *Graph) activeEdgeLocked(edge *Edge) bool {
	if edge == nil || edge.DeletedAt != nil {
		return false
	}
	if source, ok := g.nodes[edge.Source]; ok && source != nil && source.DeletedAt != nil {
		return false
	}
	if target, ok := g.nodes[edge.Target]; ok && target != nil && target.DeletedAt != nil {
		return false
	}
	return true
}

func (g *Graph) removeEdgesByNodeLocked(nodeID string) bool {
	removed := false

	if edges, ok := g.outEdges[nodeID]; ok {
		for _, edge := range edges {
			if g.markEdgeDeletedLocked(edge) {
				removed = true
			}
		}
	}
	if edges, ok := g.inEdges[nodeID]; ok {
		for _, edge := range edges {
			if g.markEdgeDeletedLocked(edge) {
				removed = true
			}
		}
	}

	return removed
}

func (g *Graph) markEdgeDeletedLocked(edge *Edge) bool {
	if edge == nil || edge.DeletedAt != nil {
		return false
	}
	now := temporalNowUTC()
	edge.DeletedAt = &now
	if edge.Version <= 0 {
		edge.Version = 1
	}
	edge.Version++
	return true
}

func (g *Graph) markGraphChangedLocked() {
	g.indexBuilt = false
	g.blastRadiusVersion++
	g.blastRadiusCache.Range(func(key, _ any) bool {
		g.blastRadiusCache.Delete(key)
		return true
	})
}
