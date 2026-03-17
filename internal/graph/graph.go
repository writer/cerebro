package graph

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
)

var temporalNowUTC = func() time.Time {
	return time.Now().UTC()
}

// Graph represents the graph platform containing all nodes and edges.
type Graph struct {
	nodes    map[string]*Node
	outEdges map[string][]*Edge // source -> edges
	inEdges  map[string][]*Edge // target -> edges
	edgeByID map[string]*Edge
	mu       sync.RWMutex
	metadata Metadata

	activeNodeCount atomic.Int64
	activeEdgeCount atomic.Int64

	// Traversal cache for expensive reachability queries.
	blastRadiusCache            sync.Map
	blastRadiusCacheWriteMu     sync.Mutex
	blastRadiusTopNCache        sync.Map
	blastRadiusTopNCacheWriteMu sync.Mutex
	blastRadiusVersion          uint64
	blastRadiusNeedsCompaction  bool

	// Basic node lookup indexes are maintained incrementally once built.
	indexByKind            map[NodeKind][]*Node
	indexByAccount         map[string][]*Node
	indexByRisk            map[RiskLevel][]*Node
	indexByProvider        map[string][]*Node
	nodeLookupIndexBuilt   bool
	arnPrefixIndexBuilt    bool
	crossAccountIndexBuilt bool

	// Heavier derived/search indexes are still rebuilt on BuildIndex().
	indexByARNPrefix         map[string][]*Node // "service:resourceType" -> nodes for fast ARN matching
	crossAccountEdge         []*Edge
	internetNodes            []*Node // Pre-computed internet-facing nodes
	crownJewels              []*Node // Pre-computed high-value targets
	entitySearchDocs         map[string]entitySearchDocument
	entitySearchTokenIndex   map[string][]string
	entitySearchTrigramIndex map[string][]string
	entitySuggestIndex       map[string][]EntitySuggestion
	entitySuggestBuilt       bool
	indexBuilt               bool

	// Runtime ontology validation behavior and counters.
	schemaValidationMode  SchemaValidationMode
	schemaValidationStats SchemaValidationStats

	// Property history retention controls.
	temporalHistoryMaxEntries int
	temporalHistoryTTL        time.Duration

	// Copy-on-write fork tracking for mutation-heavy internal workflows.
	sharedNodes          map[string]struct{}
	sharedEdges          map[*Edge]struct{}
	sharedOutEdgeBuckets map[string]struct{}
	sharedInEdgeBuckets  map[string]struct{}
	nodesShared          bool
	outEdgesShared       bool
	inEdgesShared        bool
	edgeByIDShared       bool
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
	mode := SchemaValidationWarn
	return &Graph{
		nodes:                      make(map[string]*Node),
		outEdges:                   make(map[string][]*Edge),
		inEdges:                    make(map[string][]*Edge),
		edgeByID:                   make(map[string]*Edge),
		blastRadiusVersion:         1,
		blastRadiusNeedsCompaction: false,
		schemaValidationMode:       mode,
		schemaValidationStats:      newSchemaValidationStats(mode),
		temporalHistoryMaxEntries:  DefaultTemporalHistoryMaxEntries,
		temporalHistoryTTL:         DefaultTemporalHistoryTTL,
	}
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node *Node) {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphMutation("add_node", time.Since(start))
	}()

	if node == nil || node.ID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.addNodeLocked(node) {
		g.markGraphChangedPreservingNodeIndexesLocked()
	}
}

// AddNodesBatch adds multiple nodes in a single lock acquisition
func (g *Graph) AddNodesBatch(nodes []*Node) {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphMutation("add_nodes_batch", time.Since(start))
	}()

	if len(nodes) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	changed := false
	for _, node := range nodes {
		if node == nil || node.ID == "" {
			continue
		}
		if g.addNodeLocked(node) {
			changed = true
		}
	}
	if changed {
		g.markGraphChangedPreservingNodeIndexesLocked()
	}
}

// AddEdge adds an edge to the graph
func (g *Graph) AddEdge(edge *Edge) {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphMutation("add_edge", time.Since(start))
	}()

	if edge == nil || edge.Source == "" || edge.Target == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.addEdgeLocked(edge) {
		g.markGraphEdgeMutationLocked()
	}
}

// AddEdgesBatch adds multiple edges in a single lock acquisition
func (g *Graph) AddEdgesBatch(edges []*Edge) {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphMutation("add_edges_batch", time.Since(start))
	}()

	if len(edges) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	changed := false
	for _, edge := range edges {
		if edge == nil || edge.Source == "" || edge.Target == "" {
			continue
		}
		if g.addEdgeLocked(edge) {
			changed = true
		}
	}
	if changed {
		g.markGraphEdgeMutationLocked()
	}
}

// RemoveNode removes a node and all edges touching it.
func (g *Graph) RemoveNode(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	node, ok := g.nodes[id]
	if !ok || node.DeletedAt != nil {
		return false
	}
	node = g.ensureWritableNodeLocked(id)

	g.removeEdgesByNodeLocked(id)
	now := temporalNowUTC()
	node.DeletedAt = &now
	node.UpdatedAt = now
	if node.Version <= 0 {
		node.Version = 1
	}
	node.Version++
	g.activeNodeCount.Add(-1)
	g.removeNodeFromLookupIndexesLocked(node)
	g.removeNodeFromDerivedIndexesLocked(node)
	g.markGraphChangedPreservingNodeIndexesLocked()
	return true
}

// RemoveEdge removes all edges matching source, target, and kind.
func (g *Graph) RemoveEdge(source, target string, kind EdgeKind) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	removed := false
	if edges, ok := g.outEdges[source]; ok {
		for _, edge := range edges {
			if edge != nil && edge.Source == source && edge.Target == target && edge.Kind == kind {
				if g.markEdgeDeletedLocked(edge) {
					removed = true
				}
			}
		}
	}

	if removed {
		g.markGraphEdgeMutationLocked()
	}
	return removed
}

// RemoveEdgesByNode removes all edges connected to nodeID.
func (g *Graph) RemoveEdgesByNode(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.removeEdgesByNodeLocked(nodeID) {
		g.markGraphEdgeMutationLocked()
	}
}

// CompactDeletedEdges removes soft-deleted edges from adjacency slices to keep
// long-lived graphs from accumulating tombstoned edge pointers.
func (g *Graph) CompactDeletedEdges() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.compactDeletedEdgesLocked()
}

// CompactDeletedNodes removes soft-deleted node tombstones from the backing
// node map to keep long-lived graphs from accumulating dead entries.
func (g *Graph) CompactDeletedNodes() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.compactDeletedNodesLocked() {
		g.markGraphChangedPreservingNodeIndexesLocked()
	}
}

// SetNodeProperty sets or updates a single property on a node.
func (g *Graph) SetNodeProperty(id string, key string, value any) bool {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphMutation("set_property", time.Since(start))
	}()

	g.mu.Lock()
	defer g.mu.Unlock()

	node, ok := g.nodes[id]
	if !ok || node.DeletedAt != nil {
		return false
	}
	node = g.ensureWritableNodeLocked(id)
	wasInternetFacing := g.isInternetFacing(node)
	wasCrownJewel := g.isCrownJewel(node)

	previousValue, hadPreviousValue := node.Properties[key]
	if hadPreviousValue {
		if node.PreviousProperties == nil {
			node.PreviousProperties = make(map[string]any, 1)
		} else {
			for previousKey := range node.PreviousProperties {
				delete(node.PreviousProperties, previousKey)
			}
		}
		node.PreviousProperties[key] = cloneAny(previousValue)
	} else {
		node.PreviousProperties = nil
	}
	if node.Properties == nil {
		node.Properties = make(map[string]any)
	}
	node.Properties[key] = value
	hydrateNodeTypedProperties(node)
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
	g.refreshNodeClassifiedIndexesLocked(node, wasInternetFacing, wasCrownJewel)
	g.markGraphChangedPreservingNodeIndexesLocked()
	return true
}

// Clone returns a copy of the graph while structurally sharing immutable
// property history slices until later writes detach them.
func (g *Graph) Clone() *Graph {
	start := time.Now()
	defer func() {
		metrics.ObserveGraphCloneDuration(time.Since(start))
	}()

	g.mu.RLock()
	defer g.mu.RUnlock()

	return cloneGraphWithSharedPropertyHistory(g)
}

// Fork returns a copy-on-write graph optimized for graph-method mutations.
// Callers must treat nodes and edges returned from getters as read-only.
func (g *Graph) Fork() *Graph {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return forkGraphForMutation(g)
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
	return int(g.activeNodeCount.Load())
}

// EdgeCount returns the total number of edges
func (g *Graph) EdgeCount() int {
	return int(g.activeEdgeCount.Load())
}

// Clear removes all nodes and edges
func (g *Graph) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes = make(map[string]*Node)
	g.outEdges = make(map[string][]*Edge)
	g.inEdges = make(map[string][]*Edge)
	g.activeNodeCount.Store(0)
	g.activeEdgeCount.Store(0)
	g.edgeByID = make(map[string]*Edge)
	g.sharedNodes = nil
	g.sharedEdges = nil
	g.sharedOutEdgeBuckets = nil
	g.sharedInEdgeBuckets = nil
	g.nodesShared = false
	g.outEdgesShared = false
	g.inEdgesShared = false
	g.edgeByIDShared = false
	g.nodeLookupIndexBuilt = false
	g.markGraphChangedLocked()
}

// ClearEdges removes all edges while preserving nodes.
func (g *Graph) ClearEdges() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.outEdges = make(map[string][]*Edge)
	g.inEdges = make(map[string][]*Edge)
	g.activeEdgeCount.Store(0)
	g.edgeByID = make(map[string]*Edge)
	g.sharedEdges = nil
	g.sharedOutEdgeBuckets = nil
	g.sharedInEdgeBuckets = nil
	g.outEdgesShared = false
	g.inEdgesShared = false
	g.edgeByIDShared = false
	g.crossAccountEdge = nil
	g.crossAccountIndexBuilt = false
	g.markGraphEdgeMutationLocked()
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
	g.buildIndexWithTrigger("manual")
}

func (g *Graph) buildIndexWithTrigger(trigger string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.indexBuilt {
		return
	}
	start := time.Now()
	g.buildIndexLocked()
	metrics.ObserveGraphIndexBuild(trigger, time.Since(start))
}

func (g *Graph) buildIndexLocked() {
	// Initialize index maps
	g.indexByKind = make(map[NodeKind][]*Node)
	g.indexByAccount = make(map[string][]*Node)
	g.indexByRisk = make(map[RiskLevel][]*Node)
	g.indexByProvider = make(map[string][]*Node)
	g.indexByARNPrefix = make(map[string][]*Node)
	g.crossAccountEdge = nil
	g.internetNodes = nil
	g.crownJewels = nil
	g.entitySearchDocs = make(map[string]entitySearchDocument)
	g.entitySearchTokenIndex = make(map[string][]string)
	g.entitySearchTrigramIndex = make(map[string][]string)
	g.entitySuggestIndex = make(map[string][]EntitySuggestion)
	g.entitySuggestBuilt = false
	g.nodeLookupIndexBuilt = true
	g.arnPrefixIndexBuilt = true

	entityTokenSets := make(map[string]map[string]struct{})
	entityTrigramSets := make(map[string]map[string]struct{})

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

		if prefix, ok := resourceNodeARNPrefix(node); ok {
			g.indexByARNPrefix[prefix] = append(g.indexByARNPrefix[prefix], node)
		}

		// Pre-compute internet-facing nodes
		if g.isInternetFacing(node) {
			g.internetNodes = append(g.internetNodes, node)
		}

		// Pre-compute crown jewels (high-value targets)
		if g.isCrownJewel(node) {
			g.crownJewels = append(g.crownJewels, node)
		}

		if doc, ok := buildEntitySearchDocument(node); ok {
			g.entitySearchDocs[node.ID] = doc
			for _, token := range doc.Tokens {
				appendEntitySearchSet(entityTokenSets, token, node.ID)
			}
			for _, trigram := range entitySearchTrigrams(doc.SearchText) {
				appendEntitySearchSet(entityTrigramSets, trigram, node.ID)
			}
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

	for token, ids := range entityTokenSets {
		g.entitySearchTokenIndex[token] = flattenEntitySearchSet(ids)
	}
	for trigram, ids := range entityTrigramSets {
		g.entitySearchTrigramIndex[trigram] = flattenEntitySearchSet(ids)
	}

	g.crossAccountIndexBuilt = true
	g.indexBuilt = true
}

// isInternetFacing checks if a node is exposed to the internet
func (g *Graph) isInternetFacing(node *Node) bool {
	if node == nil || node.Properties == nil {
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

	// Extra heuristics only apply to kinds marked as internet-exposable in the ontology.
	if !NodeKindHasCapability(node.Kind, NodeCapabilityInternetExposable) {
		return false
	}
	if nodeType, ok := node.Properties["type"].(string); ok {
		if nodeType == "load_balancer" || nodeType == "api_gateway" || nodeType == "cdn" {
			return true
		}
	}
	if publicIP, ok := node.Properties["public_ip_address"].(string); ok && publicIP != "" {
		return true
	}
	if funcURL, ok := node.Properties["function_url"].(string); ok && funcURL != "" {
		return true
	}
	if public, ok := node.Properties["public_access_block_enabled"].(bool); ok && !public {
		return true
	}

	return false
}

// isCrownJewel checks if a node is a high-value target
func (g *Graph) isCrownJewel(node *Node) bool {
	if node == nil {
		return false
	}

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

	// Use schema capabilities instead of hardcoded kind checks.
	if NodeKindHasCapability(node.Kind, NodeCapabilitySensitiveData) {
		if containsPII, ok := node.Properties["contains_pii"].(bool); ok && containsPII {
			return true
		}
		if env, ok := node.Properties["environment"].(string); ok && env == "production" {
			return true
		}
	}
	if NodeKindHasCapability(node.Kind, NodeCapabilityPrivilegedIdentity) {
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

	if !g.nodeLookupIndexBuilt {
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

	if !g.nodeLookupIndexBuilt {
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

	return append([]*Node(nil), g.indexByAccount[accountID]...)
}

// GetNodesByRisk returns nodes with a specific risk level using the index
func (g *Graph) GetNodesByRisk(risk RiskLevel) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.nodeLookupIndexBuilt {
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

	return append([]*Node(nil), g.indexByRisk[risk]...)
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

	if !g.crossAccountIndexBuilt {
		edges := make([]*Edge, 0, len(g.crossAccountEdge))
		for _, edgeList := range g.outEdges {
			for _, edge := range edgeList {
				if !g.activeEdgeLocked(edge) {
					continue
				}
				if edge.IsCrossAccount() {
					edges = append(edges, edge)
				}
			}
		}
		return edges
	}

	return append([]*Edge(nil), g.crossAccountEdge...)
}

// HasResourceARNPrefixIndex reports whether the ARN prefix index is current.
func (g *Graph) HasResourceARNPrefixIndex() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.arnPrefixIndexBuilt
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
	if !g.arnPrefixIndexBuilt {
		return nil
	}
	return append([]*Node(nil), g.indexByARNPrefix[prefix]...)
}

func (g *Graph) addNodeLocked(node *Node) bool {
	normalizeNodeTenantID(node)
	if !g.applyNodeSchemaValidationLocked(node) {
		return false
	}

	now := temporalNowUTC()
	wasActive := false
	var existing *Node
	if current, ok := g.nodes[node.ID]; ok && current != nil {
		existing = current
		wasActive = existing.DeletedAt == nil
		existingCreatedAt := existing.CreatedAt
		if existingCreatedAt.IsZero() {
			existingCreatedAt = now
		}
		if node.CreatedAt.IsZero() {
			node.CreatedAt = existingCreatedAt
		}
		node.PreviousProperties = cloneAnyMap(existing.Properties)
		if len(existing.PropertyHistory) > 0 {
			if node.PropertyHistory == nil {
				node.PropertyHistory = sharePropertyHistoryMap(existing.PropertyHistory)
			} else {
				for property, history := range existing.PropertyHistory {
					if len(node.PropertyHistory[property]) == 0 {
						node.PropertyHistory[property] = history
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
	hydrateNodeTypedProperties(node)
	g.appendNodePropertiesHistoryLocked(node, node.UpdatedAt)
	g.removeNodeFromLookupIndexesLocked(existing)
	g.removeNodeFromDerivedIndexesLocked(existing)
	g.detachNodesMapLocked()
	g.nodes[node.ID] = node
	delete(g.sharedNodes, node.ID)
	g.addNodeToLookupIndexesLocked(node)
	g.addNodeToDerivedIndexesLocked(node)
	if !wasActive {
		g.activeNodeCount.Add(1)
	}
	return true
}

func (g *Graph) addNodeToLookupIndexesLocked(node *Node) {
	if !g.nodeLookupIndexBuilt || node == nil || node.DeletedAt != nil {
		return
	}
	g.indexByKind[node.Kind] = append(g.indexByKind[node.Kind], node)
	if node.Account != "" {
		g.indexByAccount[node.Account] = append(g.indexByAccount[node.Account], node)
	}
	g.indexByRisk[node.Risk] = append(g.indexByRisk[node.Risk], node)
	if node.Provider != "" {
		g.indexByProvider[node.Provider] = append(g.indexByProvider[node.Provider], node)
	}
	if g.arnPrefixIndexBuilt {
		if prefix, ok := resourceNodeARNPrefix(node); ok {
			g.indexByARNPrefix[prefix] = append(g.indexByARNPrefix[prefix], node)
		}
	}
}

func (g *Graph) removeNodeFromLookupIndexesLocked(node *Node) {
	if !g.nodeLookupIndexBuilt || node == nil {
		return
	}
	g.indexByKind[node.Kind] = removeIndexedNodeLocked(g.indexByKind[node.Kind], node.ID)
	if len(g.indexByKind[node.Kind]) == 0 {
		delete(g.indexByKind, node.Kind)
	}
	if node.Account != "" {
		g.indexByAccount[node.Account] = removeIndexedNodeLocked(g.indexByAccount[node.Account], node.ID)
		if len(g.indexByAccount[node.Account]) == 0 {
			delete(g.indexByAccount, node.Account)
		}
	}
	g.indexByRisk[node.Risk] = removeIndexedNodeLocked(g.indexByRisk[node.Risk], node.ID)
	if len(g.indexByRisk[node.Risk]) == 0 {
		delete(g.indexByRisk, node.Risk)
	}
	if node.Provider != "" {
		g.indexByProvider[node.Provider] = removeIndexedNodeLocked(g.indexByProvider[node.Provider], node.ID)
		if len(g.indexByProvider[node.Provider]) == 0 {
			delete(g.indexByProvider, node.Provider)
		}
	}
	if g.arnPrefixIndexBuilt {
		if prefix, ok := resourceNodeARNPrefix(node); ok {
			g.indexByARNPrefix[prefix] = removeIndexedNodeLocked(g.indexByARNPrefix[prefix], node.ID)
			if len(g.indexByARNPrefix[prefix]) == 0 {
				delete(g.indexByARNPrefix, prefix)
			}
		}
	}
}

func resourceNodeARNPrefix(node *Node) (string, bool) {
	if node == nil || !node.IsResource() {
		return "", false
	}
	parsed, err := ParseARN(node.ID)
	if err != nil {
		return "", false
	}
	return parsed.ResourcePrefix(), true
}

func removeIndexedNodeLocked(nodes []*Node, nodeID string) []*Node {
	if len(nodes) == 0 || nodeID == "" {
		return nodes
	}
	originalLen := len(nodes)
	compacted := nodes[:0]
	for _, node := range nodes {
		if node != nil && node.ID == nodeID {
			continue
		}
		compacted = append(compacted, node)
	}
	for i := len(compacted); i < originalLen; i++ {
		nodes[i] = nil
	}
	return compacted
}

func (g *Graph) addEdgeLocked(edge *Edge) bool {
	if !g.applyEdgeSchemaValidationLocked(edge) {
		return false
	}

	now := temporalNowUTC()
	if edge.ID != "" {
		if existing := g.edgeByID[edge.ID]; existing != nil {
			return g.replaceEdgeLocked(existing, edge, now)
		}
	}
	if edge.CreatedAt.IsZero() {
		edge.CreatedAt = now
	}
	if edge.Version <= 0 {
		edge.Version = 1
	}
	edge.DeletedAt = nil
	g.detachOutBucketLocked(edge.Source)
	g.outEdges[edge.Source] = append(g.outEdges[edge.Source], edge)
	g.detachInBucketLocked(edge.Target)
	g.inEdges[edge.Target] = append(g.inEdges[edge.Target], edge)
	g.activeEdgeCount.Add(1)
	g.addCrossAccountEdgeLocked(edge)
	if edge.ID != "" {
		g.detachEdgeByIDMapLocked()
		g.edgeByID[edge.ID] = edge
	}
	return true
}

func (g *Graph) replaceEdgeLocked(existing *Edge, next *Edge, now time.Time) bool {
	if existing == nil || next == nil {
		return false
	}
	existing = g.ensureWritableEdgeLocked(existing)

	oldSource := existing.Source
	oldTarget := existing.Target

	if next.CreatedAt.IsZero() {
		if existing.CreatedAt.IsZero() {
			next.CreatedAt = now
		} else {
			next.CreatedAt = existing.CreatedAt
		}
	}
	if next.Version <= 0 {
		if existing.Version > 0 {
			next.Version = existing.Version + 1
		} else {
			next.Version = 1
		}
	}
	next.DeletedAt = nil
	if existing.DeletedAt != nil {
		g.activeEdgeCount.Add(1)
	}
	g.removeCrossAccountEdgeLocked(existing)

	if oldSource != next.Source {
		g.detachOutBucketLocked(oldSource)
		g.outEdges[oldSource] = removeEdgePointerLocked(g.outEdges[oldSource], existing)
		if len(g.outEdges[oldSource]) == 0 {
			delete(g.outEdges, oldSource)
		}
	}
	if oldTarget != next.Target {
		g.detachInBucketLocked(oldTarget)
		g.inEdges[oldTarget] = removeEdgePointerLocked(g.inEdges[oldTarget], existing)
		if len(g.inEdges[oldTarget]) == 0 {
			delete(g.inEdges, oldTarget)
		}
	}

	*existing = *next
	if !edgePointerPresentLocked(g.outEdges[next.Source], existing) {
		g.detachOutBucketLocked(next.Source)
		g.outEdges[next.Source] = append(g.outEdges[next.Source], existing)
	}
	if !edgePointerPresentLocked(g.inEdges[next.Target], existing) {
		g.detachInBucketLocked(next.Target)
		g.inEdges[next.Target] = append(g.inEdges[next.Target], existing)
	}
	g.addCrossAccountEdgeLocked(existing)
	g.detachEdgeByIDMapLocked()
	g.edgeByID[next.ID] = existing
	return true
}

func (g *Graph) addCrossAccountEdgeLocked(edge *Edge) {
	if !g.crossAccountIndexBuilt || !g.activeEdgeLocked(edge) || !edge.IsCrossAccount() {
		return
	}
	g.crossAccountEdge = append(g.crossAccountEdge, edge)
}

func (g *Graph) removeCrossAccountEdgeLocked(target *Edge) {
	if !g.crossAccountIndexBuilt || len(g.crossAccountEdge) == 0 || target == nil {
		return
	}
	originalLen := len(g.crossAccountEdge)
	compacted := g.crossAccountEdge[:0]
	for _, edge := range g.crossAccountEdge {
		if edge == target {
			continue
		}
		compacted = append(compacted, edge)
	}
	for i := len(compacted); i < originalLen; i++ {
		g.crossAccountEdge[i] = nil
	}
	g.crossAccountEdge = compacted
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

func (g *Graph) compactDeletedEdgesLocked() {
	for source := range g.outEdges {
		g.detachOutBucketLocked(source)
		edges := g.outEdges[source]
		compacted := edges[:0]
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			if edge.DeletedAt != nil {
				g.evictEdgeIDLocked(edge)
				continue
			}
			compacted = append(compacted, edge)
		}
		if len(compacted) == 0 {
			delete(g.outEdges, source)
			continue
		}
		g.outEdges[source] = compacted
	}
	for target := range g.inEdges {
		g.detachInBucketLocked(target)
		edges := g.inEdges[target]
		compacted := edges[:0]
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			if edge.DeletedAt != nil {
				g.evictEdgeIDLocked(edge)
				continue
			}
			compacted = append(compacted, edge)
		}
		if len(compacted) == 0 {
			delete(g.inEdges, target)
			continue
		}
		g.inEdges[target] = compacted
	}
}

func (g *Graph) evictEdgeIDLocked(edge *Edge) {
	if edge == nil || edge.ID == "" {
		return
	}
	if g.edgeByID[edge.ID] == edge {
		g.detachEdgeByIDMapLocked()
		delete(g.edgeByID, edge.ID)
	}
}

func removeEdgePointerLocked(edges []*Edge, target *Edge) []*Edge {
	if len(edges) == 0 || target == nil {
		return edges
	}
	compacted := edges[:0]
	for _, edge := range edges {
		if edge == target {
			continue
		}
		compacted = append(compacted, edge)
	}
	return compacted
}

func edgePointerPresentLocked(edges []*Edge, target *Edge) bool {
	for _, edge := range edges {
		if edge == target {
			return true
		}
	}
	return false
}

func (g *Graph) compactDeletedNodesLocked() bool {
	removed := false
	for id, node := range g.nodes {
		if node != nil && node.DeletedAt == nil {
			continue
		}
		g.detachNodesMapLocked()
		g.detachOutEdgesMapLocked()
		g.detachInEdgesMapLocked()
		for _, edge := range g.outEdges[id] {
			g.evictEdgeIDLocked(edge)
		}
		for _, edge := range g.inEdges[id] {
			g.evictEdgeIDLocked(edge)
		}
		delete(g.nodes, id)
		delete(g.outEdges, id)
		delete(g.inEdges, id)
		removed = true
	}
	return removed
}

func (g *Graph) removeEdgesByNodeLocked(nodeID string) bool {
	removed := false
	seen := make(map[*Edge]struct{})

	markDeleted := func(edges []*Edge) {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			if _, ok := seen[edge]; ok {
				continue
			}
			seen[edge] = struct{}{}
			if g.markEdgeDeletedLocked(edge) {
				removed = true
			}
		}
	}

	if edges, ok := g.outEdges[nodeID]; ok {
		markDeleted(edges)
	}
	if edges, ok := g.inEdges[nodeID]; ok {
		markDeleted(edges)
	}

	return removed
}

func (g *Graph) markEdgeDeletedLocked(edge *Edge) bool {
	if edge == nil {
		return false
	}
	edge = g.ensureWritableEdgeLocked(edge)
	if edge.DeletedAt != nil {
		return false
	}
	g.removeCrossAccountEdgeLocked(edge)
	now := temporalNowUTC()
	edge.DeletedAt = &now
	if edge.Version <= 0 {
		edge.Version = 1
	}
	edge.Version++
	g.activeEdgeCount.Add(-1)
	return true
}

func (g *Graph) markGraphChangedLocked() {
	g.nodeLookupIndexBuilt = false
	g.arnPrefixIndexBuilt = false
	g.crossAccountIndexBuilt = false
	g.indexBuilt = false
	g.entitySuggestBuilt = false
	g.blastRadiusVersion++
	g.blastRadiusNeedsCompaction = true
}

func (g *Graph) markGraphChangedPreservingNodeIndexesLocked() {
	g.entitySuggestBuilt = false
	g.blastRadiusVersion++
	g.blastRadiusNeedsCompaction = true
}

func (g *Graph) markGraphEdgeMutationLocked() {
	g.blastRadiusVersion++
	g.blastRadiusNeedsCompaction = true
}
