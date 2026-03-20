package graph

import (
	"container/heap"
	"strconv"
	"strings"
)

type blastRadiusCacheKey struct {
	principalID string
	maxDepth    int
}

type cachedBlastRadius struct {
	version uint64
	result  *BlastRadiusResult
}

const blastRadiusCacheCompactionDeleteLimit = 128

// blastRadiusComputeHook is used by tests to verify cache hit/miss behavior.
var blastRadiusComputeHook func(principalID string, maxDepth int)

// blastRadiusCacheBeforeWriteHook is used by tests to force interleavings right
// before cache compaction/store is serialized.
var blastRadiusCacheBeforeWriteHook func(g *Graph, version uint64)

// blastRadiusCacheStoreHook is used by tests to force interleavings around cache writes.
var blastRadiusCacheStoreHook func(g *Graph, version uint64)

// blastRadiusCacheAfterLoadHook is used by tests to force interleavings after a
// cache load but before stale-state handling.
var blastRadiusCacheAfterLoadHook func(g *Graph, key blastRadiusCacheKey)

// blastRadiusCacheAfterCompactionScanHook is used by tests to force
// interleavings after a stale-cache scan but before compaction state is cleared.
var blastRadiusCacheAfterCompactionScanHook func(g *Graph, version uint64, removed int)

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

type blastRadiusFrontierItem struct {
	ordinal NodeOrdinal
	nodeID  string
	path    []string
}

type blastRadiusExpansion struct {
	next             blastRadiusFrontierItem
	reachable        *ReachableNode
	crossAccountRisk bool
	accounts         [2]string
	accountCount     int
}

// BlastRadius performs forward reachability analysis from a principal
func BlastRadius(g *Graph, principalID string, maxDepth int) *BlastRadiusResult {
	if cached, ok := g.getBlastRadiusFromCache(principalID, maxDepth); ok {
		return cached
	}
	cacheVersion := g.currentBlastRadiusCacheVersion()

	principal, ok := g.GetNode(principalID)
	if !ok {
		return &BlastRadiusResult{PrincipalID: principalID}
	}

	if blastRadiusComputeHook != nil {
		blastRadiusComputeHook(principalID, maxDepth)
	}

	result := computeBlastRadius(g, principal, maxDepth)

	g.putBlastRadiusInCache(principalID, maxDepth, cacheVersion, result)
	return cloneBlastRadiusResult(result)
}

func computeBlastRadius(g *Graph, principal *Node, maxDepth int) *BlastRadiusResult {
	if principal == nil {
		return &BlastRadiusResult{}
	}

	result := &BlastRadiusResult{
		PrincipalID:   principal.ID,
		PrincipalName: principal.Name,
		MaxDepth:      maxDepth,
	}

	startAccount := principal.Account
	visited := newOrdinalVisitSet(nil)
	accountsReached := make(map[string]bool)
	frontier := []blastRadiusFrontierItem{{
		ordinal: principal.ordinal,
		nodeID:  principal.ID,
		path:    []string{principal.ID},
	}}

	for depth := 0; depth <= maxDepth && len(frontier) > 0; depth++ {
		activeFrontier := make([]blastRadiusFrontierItem, 0, len(frontier))
		for _, item := range frontier {
			if visited.hasNode(item.nodeID, item.ordinal) {
				continue
			}
			visited.markNode(item.nodeID, item.ordinal)
			activeFrontier = append(activeFrontier, item)
		}
		if len(activeFrontier) == 0 {
			break
		}

		expansions := parallelProcessOrdered(activeFrontier, func(item blastRadiusFrontierItem) []blastRadiusExpansion {
			return expandBlastRadiusFrontierItem(g, item, depth, startAccount)
		})

		nextFrontier := make([]blastRadiusFrontierItem, 0, len(expansions))
		for _, expansion := range expansions {
			if expansion.crossAccountRisk {
				result.CrossAccountRisk = true
			}
			for i := 0; i < expansion.accountCount; i++ {
				if expansion.accounts[i] != "" {
					accountsReached[expansion.accounts[i]] = true
				}
			}
			if expansion.reachable != nil {
				result.ReachableNodes = append(result.ReachableNodes, expansion.reachable)
				switch expansion.reachable.Node.Risk {
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
			nextFrontier = append(nextFrontier, expansion.next)
		}
		frontier = nextFrontier
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

func expandBlastRadiusFrontierItem(g *Graph, item blastRadiusFrontierItem, depth int, startAccount string) []blastRadiusExpansion {
	expansions := make([]blastRadiusExpansion, 0, len(g.GetOutEdges(item.nodeID)))
	for _, edge := range g.GetOutEdges(item.nodeID) {
		if edge.IsDeny() || isDeniedByOrdinal(g, item.nodeID, item.ordinal, edge.Target, edge.targetOrd) {
			continue
		}

		targetNode, ok := g.GetNode(edge.Target)
		if !ok {
			continue
		}

		newPath := append(append([]string{}, item.path...), edge.Target)
		expansion := blastRadiusExpansion{
			next: blastRadiusFrontierItem{
				ordinal: edge.targetOrd,
				nodeID:  edge.Target,
				path:    newPath,
			},
		}

		if edge.IsCrossAccount() {
			expansion.crossAccountRisk = true
			if targetAccount, ok := edge.Properties["target_account"].(string); ok && targetAccount != "" {
				expansion.accounts[expansion.accountCount] = targetAccount
				expansion.accountCount++
			}
		}
		if targetNode.Account != "" && targetNode.Account != startAccount {
			if expansion.accountCount == 0 || expansion.accounts[0] != targetNode.Account {
				expansion.accounts[expansion.accountCount] = targetNode.Account
				expansion.accountCount++
			}
		}

		if targetNode.IsResource() {
			var actions []string
			if a, ok := edge.Properties["actions"].([]string); ok {
				actions = a
			}
			expansion.reachable = &ReachableNode{
				Node:     targetNode,
				Depth:    depth + 1,
				Path:     newPath,
				EdgeKind: edge.Kind,
				Actions:  actions,
			}
		}

		expansions = append(expansions, expansion)
	}
	return expansions
}

func (g *Graph) getBlastRadiusFromCache(principalID string, maxDepth int) (*BlastRadiusResult, bool) {
	version := g.currentBlastRadiusCacheVersion()

	key := blastRadiusCacheKey{principalID: principalID, maxDepth: maxDepth}
	raw, ok := g.blastRadiusCache.Load(key)
	if !ok {
		return nil, false
	}
	if blastRadiusCacheAfterLoadHook != nil {
		blastRadiusCacheAfterLoadHook(g, key)
	}

	cached, ok := raw.(*cachedBlastRadius)
	if !ok || cached == nil || cached.version != version || cached.result == nil {
		return nil, false
	}

	return cloneBlastRadiusResult(cached.result), true
}

func (g *Graph) putBlastRadiusInCache(principalID string, maxDepth int, version uint64, result *BlastRadiusResult) {
	if result == nil {
		return
	}

	if version != g.currentBlastRadiusCacheVersion() {
		return
	}

	if blastRadiusCacheBeforeWriteHook != nil {
		blastRadiusCacheBeforeWriteHook(g, version)
	}

	g.blastRadiusCacheWriteMu.Lock()
	defer g.blastRadiusCacheWriteMu.Unlock()

	currentVersion := g.currentBlastRadiusCacheVersion()
	if version != currentVersion {
		return
	}

	g.maybeCompactStaleBlastRadiusCache(currentVersion)
	if blastRadiusCacheStoreHook != nil {
		blastRadiusCacheStoreHook(g, currentVersion)
	}
	currentVersion = g.currentBlastRadiusCacheVersion()
	if version != currentVersion {
		return
	}

	key := blastRadiusCacheKey{principalID: principalID, maxDepth: maxDepth}
	g.blastRadiusCache.Store(key, &cachedBlastRadius{
		version: currentVersion,
		result:  cloneBlastRadiusResult(result),
	})
}

func (g *Graph) maybeCompactStaleBlastRadiusCache(version uint64) {
	g.mu.RLock()
	needsCompaction := g.blastRadiusNeedsCompaction
	g.mu.RUnlock()
	if !needsCompaction {
		return
	}

	removed := 0
	g.blastRadiusCache.Range(func(key, value any) bool {
		cached, ok := value.(*cachedBlastRadius)
		if !ok || cached == nil || cached.version != version || cached.result == nil {
			g.blastRadiusCache.Delete(key)
			removed++
			if removed >= blastRadiusCacheCompactionDeleteLimit {
				return false
			}
		}
		return true
	})

	if blastRadiusCacheAfterCompactionScanHook != nil {
		blastRadiusCacheAfterCompactionScanHook(g, version, removed)
	}

	g.mu.Lock()
	if removed < blastRadiusCacheCompactionDeleteLimit && g.blastRadiusNeedsCompaction && g.blastRadiusVersion == version {
		g.blastRadiusNeedsCompaction = false
	}
	g.mu.Unlock()
}

func (g *Graph) currentBlastRadiusCacheVersion() uint64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.blastRadiusVersion
}

// CurrentVersion returns the current in-memory mutation version for cache invalidation.
func (g *Graph) CurrentVersion() uint64 {
	return g.currentBlastRadiusCacheVersion()
}

func cloneBlastRadiusResult(result *BlastRadiusResult) *BlastRadiusResult {
	if result == nil {
		return nil
	}

	cloned := *result
	if len(result.ForeignAccounts) > 0 {
		cloned.ForeignAccounts = append([]string(nil), result.ForeignAccounts...)
	}

	if len(result.ReachableNodes) > 0 {
		cloned.ReachableNodes = make([]*ReachableNode, 0, len(result.ReachableNodes))
		for _, reachable := range result.ReachableNodes {
			if reachable == nil {
				continue
			}

			reachableClone := *reachable
			if len(reachable.Path) > 0 {
				reachableClone.Path = append([]string(nil), reachable.Path...)
			}
			if len(reachable.Actions) > 0 {
				reachableClone.Actions = append([]string(nil), reachable.Actions...)
			}
			cloned.ReachableNodes = append(cloned.ReachableNodes, &reachableClone)
		}
	}

	return &cloned
}

// ReverseAccessResult represents who can access a resource
type ReverseAccessResult struct {
	ResourceID   string          `json:"resource_id"`
	ResourceName string          `json:"resource_name"`
	AccessibleBy []*AccessorNode `json:"accessible_by"`
	TotalCount   int             `json:"total_count"`
}

type reverseAccessFrontierItem struct {
	ordinal NodeOrdinal
	nodeID  string
	path    []string
}

type reverseAccessExpansion struct {
	next     reverseAccessFrontierItem
	accessor *AccessorNode
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

	return computeReverseAccess(g, resource, maxDepth)
}

func computeReverseAccess(g *Graph, resource *Node, maxDepth int) *ReverseAccessResult {
	result := &ReverseAccessResult{
		ResourceID:   resource.ID,
		ResourceName: resource.Name,
	}

	visited := newOrdinalVisitSet(nil)
	frontier := []reverseAccessFrontierItem{{
		ordinal: resource.ordinal,
		nodeID:  resource.ID,
		path:    []string{resource.ID},
	}}

	for depth := 0; depth <= maxDepth && len(frontier) > 0; depth++ {
		activeFrontier := make([]reverseAccessFrontierItem, 0, len(frontier))
		for _, item := range frontier {
			if visited.hasNode(item.nodeID, item.ordinal) {
				continue
			}
			visited.markNode(item.nodeID, item.ordinal)
			activeFrontier = append(activeFrontier, item)
		}
		if len(activeFrontier) == 0 {
			break
		}

		expansions := parallelProcessOrdered(activeFrontier, func(item reverseAccessFrontierItem) []reverseAccessExpansion {
			return expandReverseAccessFrontierItem(g, item)
		})

		nextFrontier := make([]reverseAccessFrontierItem, 0, len(expansions))
		for _, expansion := range expansions {
			if expansion.accessor != nil {
				result.AccessibleBy = append(result.AccessibleBy, expansion.accessor)
			}
			nextFrontier = append(nextFrontier, expansion.next)
		}
		frontier = nextFrontier
	}

	result.TotalCount = len(result.AccessibleBy)
	return result
}

func expandReverseAccessFrontierItem(g *Graph, item reverseAccessFrontierItem) []reverseAccessExpansion {
	expansions := make([]reverseAccessExpansion, 0, len(g.GetInEdges(item.nodeID)))
	for _, edge := range g.GetInEdges(item.nodeID) {
		if edge.IsDeny() {
			continue
		}

		sourceNode, ok := g.GetNode(edge.Source)
		if !ok {
			continue
		}

		newPath := append([]string{edge.Source}, item.path...)
		expansion := reverseAccessExpansion{
			next: reverseAccessFrontierItem{
				ordinal: edge.sourceOrd,
				nodeID:  edge.Source,
				path:    newPath,
			},
		}

		if sourceNode.IsIdentity() {
			var actions []string
			if a, ok := edge.Properties["actions"].([]string); ok {
				actions = a
			}
			expansion.accessor = &AccessorNode{
				Node:     sourceNode,
				EdgeKind: edge.Kind,
				Path:     newPath,
				Actions:  actions,
			}
		}

		expansions = append(expansions, expansion)
	}
	return expansions
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
		visited ordinalVisitSet
	}

	sourceNode, ok := g.GetNode(from)
	if !ok {
		return nil
	}
	targetNode, ok := g.GetNode(to)
	if !ok {
		return nil
	}
	nodeIDs := NewNodeIDIndex()
	initialVisited := newOrdinalVisitSet(nodeIDs)
	initialVisited.mark(sourceNode.ID)
	initial := state{
		nodeID:  sourceNode.ID,
		depth:   0,
		path:    nil,
		visited: initialVisited,
	}
	queue := []state{initial}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth > maxDepth {
			continue
		}

		for _, edge := range g.GetOutEdges(current.nodeID) {
			if current.visited.has(edge.Target) {
				continue
			}

			newPath := append([]*Edge{}, current.path...)
			newPath = append(newPath, edge)
			newVisited := current.visited.clone()
			newVisited.mark(edge.Target)

			if edge.Target == targetNode.ID {
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

func isDeniedByOrdinal(g *Graph, sourceID string, sourceOrdinal NodeOrdinal, targetID string, targetOrdinal NodeOrdinal) bool {
	if sourceOrdinal != InvalidNodeOrdinal {
		if resolvedSourceID, ok := g.ResolveNodeOrdinal(sourceOrdinal); ok {
			sourceID = resolvedSourceID
		}
	}
	if sourceID == "" {
		return false
	}
	for _, edge := range g.GetOutEdges(sourceID) {
		if !edge.IsDeny() {
			continue
		}
		if targetOrdinal != InvalidNodeOrdinal && edge.targetOrd == targetOrdinal {
			return true
		}
		if edge.Target == targetID {
			return true
		}
	}
	return false
}

// CascadingBlastRadiusResult represents time-aware blast radius with sensitive data mapping
type CascadingBlastRadiusResult struct {
	SourceID          string                     `json:"source_id"`
	SourceName        string                     `json:"source_name"`
	TotalImpact       int                        `json:"total_impact"`
	MaxCascadeDepth   int                        `json:"max_cascade_depth"`
	TimeToCompromise  map[int][]*CompromisedNode `json:"time_to_compromise"` // depth -> nodes
	SensitiveDataHits []*SensitiveDataNode       `json:"sensitive_data_hits"`
	CriticalPathCount int                        `json:"critical_path_count"`
	AccountBoundaries []*AccountBoundaryCross    `json:"account_boundaries"`
	ImpactScore       float64                    `json:"impact_score"` // 0-100
	RemediationPaths  []string                   `json:"remediation_paths"`
}

// CompromisedNode represents a node that could be compromised at a specific cascade depth
type CompromisedNode struct {
	Node            *Node    `json:"node"`
	Depth           int      `json:"depth"`
	Path            []string `json:"path"`
	EstimatedTimeMs int64    `json:"estimated_time_ms"` // Estimated time to reach this node
	Technique       string   `json:"technique"`
	Impact          string   `json:"impact"` // low, medium, high, critical
}

// SensitiveDataNode represents a node containing sensitive data that could be exposed
type SensitiveDataNode struct {
	Node               *Node    `json:"node"`
	DataClassification string   `json:"data_classification"`
	DataTypes          []string `json:"data_types"` // PII, PHI, PCI, credentials, etc.
	PathToData         []string `json:"path_to_data"`
	Depth              int      `json:"depth"`
	ComplianceImpact   []string `json:"compliance_impact"` // GDPR, HIPAA, PCI-DSS, SOC2
}

// AccountBoundaryCross represents crossing an account boundary during cascade
type AccountBoundaryCross struct {
	FromAccount string   `json:"from_account"`
	ToAccount   string   `json:"to_account"`
	CrossingAt  string   `json:"crossing_at"` // Node ID where crossing occurs
	EdgeKind    EdgeKind `json:"edge_kind"`
	Depth       int      `json:"depth"`
}

type cascadeItem struct {
	ordinal   NodeOrdinal
	nodeID    string
	depth     int
	path      []string
	timeMs    int64
	technique string
	index     int
}

type cascadePriorityQueue []*cascadeItem

func (pq cascadePriorityQueue) Len() int { return len(pq) }

func (pq cascadePriorityQueue) Less(i, j int) bool {
	if pq[i].timeMs == pq[j].timeMs {
		return pq[i].depth < pq[j].depth
	}
	return pq[i].timeMs < pq[j].timeMs
}

func (pq cascadePriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *cascadePriorityQueue) Push(x interface{}) {
	item := x.(*cascadeItem)
	item.index = len(*pq)
	*pq = append(*pq, item)
}

func (pq *cascadePriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1
	*pq = old[:n-1]
	return item
}

// CascadingBlastRadius performs advanced blast radius analysis with time-awareness
// and sensitive data mapping. This simulates how a compromise would cascade through
// the infrastructure over time.
func CascadingBlastRadius(g *Graph, sourceID string, maxDepth int) *CascadingBlastRadiusResult {
	source, ok := g.GetNode(sourceID)
	if !ok {
		return &CascadingBlastRadiusResult{SourceID: sourceID}
	}

	if maxDepth <= 0 {
		maxDepth = 6
	}

	result := &CascadingBlastRadiusResult{
		SourceID:          sourceID,
		SourceName:        source.Name,
		MaxCascadeDepth:   0,
		TimeToCompromise:  make(map[int][]*CompromisedNode),
		SensitiveDataHits: make([]*SensitiveDataNode, 0),
		AccountBoundaries: make([]*AccountBoundaryCross, 0),
	}

	sourceOrdinal := source.ordinal
	visited := newOrdinalVisitSet(nil)
	visitedCount := 0
	bestTimeByOrdinal := make(map[NodeOrdinal]int64)
	bestTimeByNodeID := make(map[string]int64)
	getBestTime := func(nodeID string, ordinal NodeOrdinal) (int64, bool) {
		if ordinal != InvalidNodeOrdinal {
			best, ok := bestTimeByOrdinal[ordinal]
			return best, ok
		}
		best, ok := bestTimeByNodeID[nodeID]
		return best, ok
	}
	setBestTime := func(nodeID string, ordinal NodeOrdinal, timeMs int64) {
		if ordinal != InvalidNodeOrdinal {
			bestTimeByOrdinal[ordinal] = timeMs
			return
		}
		bestTimeByNodeID[nodeID] = timeMs
	}
	setBestTime(sourceID, sourceOrdinal, 0)

	queue := &cascadePriorityQueue{}
	heap.Init(queue)
	heap.Push(queue, &cascadeItem{
		ordinal:   sourceOrdinal,
		nodeID:    sourceID,
		depth:     0,
		path:      []string{sourceID},
		timeMs:    0,
		technique: "initial_access",
	})

	for queue.Len() > 0 {
		item := heap.Pop(queue).(*cascadeItem)
		if item.depth > maxDepth {
			continue
		}
		if best, ok := getBestTime(item.nodeID, item.ordinal); ok && item.timeMs > best {
			continue
		}
		if visited.markNode(item.nodeID, item.ordinal) {
			visitedCount++
		}

		currentNode, ok := g.GetNode(item.nodeID)
		if !ok {
			continue
		}

		// Track max cascade depth
		if item.depth > result.MaxCascadeDepth {
			result.MaxCascadeDepth = item.depth
		}

		// Record compromised node at this depth
		if item.depth > 0 {
			compromised := &CompromisedNode{
				Node:            currentNode,
				Depth:           item.depth,
				Path:            item.path,
				EstimatedTimeMs: item.timeMs,
				Technique:       item.technique,
				Impact:          riskToImpact(currentNode.Risk),
			}
			result.TimeToCompromise[item.depth] = append(result.TimeToCompromise[item.depth], compromised)

			// Check for sensitive data
			if sensitiveData := detectSensitiveData(currentNode); sensitiveData != nil {
				sensitiveData.PathToData = item.path
				sensitiveData.Depth = item.depth
				result.SensitiveDataHits = append(result.SensitiveDataHits, sensitiveData)
			}

			// Check for critical paths
			if currentNode.Risk == RiskCritical {
				result.CriticalPathCount++
			}
		}

		// Explore outbound edges
		for _, edge := range g.GetOutEdges(item.nodeID) {
			if edge.IsDeny() {
				continue
			}
			if isDeniedByOrdinal(g, item.nodeID, item.ordinal, edge.Target, edge.targetOrd) {
				continue
			}

			targetNode, ok := g.GetNode(edge.Target)
			if !ok {
				continue
			}

			nextDepth := item.depth + 1
			if nextDepth > maxDepth {
				continue
			}

			newPath := append([]string{}, item.path...)
			newPath = append(newPath, edge.Target)

			// Estimate time based on edge type and target
			timeIncrement := estimateCompromiseTime(edge, targetNode)

			// Track account boundary crossings
			fromAccount := currentNode.Account
			toAccount := targetNode.Account
			if edge.Properties != nil {
				if fromAccount == "" {
					if sourceAccount, ok := edge.Properties["source_account"].(string); ok {
						fromAccount = sourceAccount
					}
				}
				if toAccount == "" {
					if targetAccount, ok := edge.Properties["target_account"].(string); ok {
						toAccount = targetAccount
					}
				}
			}

			crossAccount := edge.IsCrossAccount()
			if !crossAccount && fromAccount != "" && toAccount != "" && fromAccount != toAccount {
				crossAccount = true
			}
			if crossAccount {
				if fromAccount == "" {
					fromAccount = "unknown"
				}
				if toAccount == "" {
					toAccount = "unknown"
				}
				result.AccountBoundaries = append(result.AccountBoundaries, &AccountBoundaryCross{
					FromAccount: fromAccount,
					ToAccount:   toAccount,
					CrossingAt:  edge.Target,
					EdgeKind:    edge.Kind,
					Depth:       nextDepth,
				})
			}

			nextTime := item.timeMs + timeIncrement
			targetOrdinal := edge.targetOrd
			if best, ok := getBestTime(edge.Target, targetOrdinal); ok && nextTime >= best {
				continue
			}
			setBestTime(edge.Target, targetOrdinal, nextTime)

			heap.Push(queue, &cascadeItem{
				ordinal:   targetOrdinal,
				nodeID:    edge.Target,
				depth:     nextDepth,
				path:      newPath,
				timeMs:    nextTime,
				technique: edgeToAttackTechnique(edge.Kind),
			})
		}
	}

	// Calculate total impact and score
	result.TotalImpact = visitedCount - 1 // Exclude source
	result.ImpactScore = calculateImpactScore(result)
	result.RemediationPaths = suggestRemediationPaths(result)

	return result
}

// riskToImpact converts RiskLevel to impact string
func riskToImpact(risk RiskLevel) string {
	switch risk {
	case RiskCritical:
		return "critical"
	case RiskHigh:
		return "high"
	case RiskMedium:
		return "medium"
	default:
		return "low"
	}
}

// detectSensitiveData checks if a node contains sensitive data
func detectSensitiveData(node *Node) *SensitiveDataNode {
	return detectSensitiveDataWithOptions(node, true)
}

func detectSensitiveDataExplicit(node *Node) *SensitiveDataNode {
	return detectSensitiveDataWithOptions(node, false)
}

func detectSensitiveDataWithOptions(node *Node, includeNameHeuristics bool) *SensitiveDataNode {
	if node.Properties == nil {
		return nil
	}

	result := &SensitiveDataNode{
		Node:             node,
		DataTypes:        make([]string, 0),
		ComplianceImpact: make([]string, 0),
	}

	// Check data classification
	if class, ok := node.Properties["data_classification"].(string); ok {
		result.DataClassification = class
		if class == "confidential" || class == "restricted" || class == "sensitive" {
			result.ComplianceImpact = append(result.ComplianceImpact, "SOC2")
		}
	}

	// Check for PII
	if pii, ok := node.Properties["contains_pii"].(bool); ok && pii {
		result.DataTypes = append(result.DataTypes, "PII")
		result.ComplianceImpact = append(result.ComplianceImpact, "GDPR", "CCPA")
	}

	// Check for PHI (healthcare data)
	if phi, ok := node.Properties["contains_phi"].(bool); ok && phi {
		result.DataTypes = append(result.DataTypes, "PHI")
		result.ComplianceImpact = append(result.ComplianceImpact, "HIPAA")
	}

	// Check for PCI data
	if pci, ok := node.Properties["contains_pci"].(bool); ok && pci {
		result.DataTypes = append(result.DataTypes, "PCI")
		result.ComplianceImpact = append(result.ComplianceImpact, "PCI-DSS")
	}

	// Buckets and databases can also contain secrets surfaced by DSPM scans.
	if containsSecrets, ok := node.Properties["contains_secrets"].(bool); ok && containsSecrets {
		result.DataTypes = append(result.DataTypes, "secrets")
		if !sliceContains(result.ComplianceImpact, "SOC2") {
			result.ComplianceImpact = append(result.ComplianceImpact, "SOC2")
		}
	}

	// Check for credentials/secrets via ontology capability.
	if NodeKindHasCapability(node.Kind, NodeCapabilityCredentialStore) {
		result.DataTypes = append(result.DataTypes, "credentials")
	}

	if includeNameHeuristics {
		// Check node name for sensitive patterns
		sensitivePatterns := []string{"secret", "credential", "password", "key", "token", "backup", "pii", "phi"}
		nodeName := node.Name
		for _, pattern := range sensitivePatterns {
			if containsIgnoreCase(nodeName, pattern) {
				if !sliceContains(result.DataTypes, "sensitive_by_name") {
					result.DataTypes = append(result.DataTypes, "sensitive_by_name")
				}
				break
			}
		}
	}

	if len(result.DataTypes) == 0 && result.DataClassification == "" {
		return nil
	}

	return result
}

// estimateCompromiseTime estimates time to compromise based on edge and target
func estimateCompromiseTime(edge *Edge, target *Node) int64 {
	// Base time in milliseconds
	baseTime := int64(60000) // 1 minute default

	switch edge.Kind {
	case EdgeKindCanAssume:
		baseTime = 5000 // 5 seconds - role assumption is fast
	case EdgeKindCanRead:
		baseTime = 30000 // 30 seconds - need to exercise permission
	case EdgeKindCanWrite, EdgeKindCanDelete, EdgeKindCanAdmin:
		baseTime = 45000 // 45 seconds - write operations
	case EdgeKindConnectsTo:
		baseTime = 60000 // 1 minute - network traversal
	case EdgeKindExposedTo:
		baseTime = 10000 // 10 seconds - direct exposure
	case EdgeKindMemberOf:
		baseTime = 5000 // 5 seconds - group membership
	}

	// Increase time for cross-account
	if edge.IsCrossAccount() {
		baseTime *= 2
	}

	// Increase time for critical targets (more careful exploitation)
	if target.Risk == RiskCritical {
		baseTime = int64(float64(baseTime) * 1.5)
	}

	return baseTime
}

// edgeToAttackTechnique maps edge kind to attack technique
func edgeToAttackTechnique(kind EdgeKind) string {
	switch kind {
	case EdgeKindCanAssume:
		return "role_assumption"
	case EdgeKindCanRead:
		return "data_exfiltration"
	case EdgeKindCanWrite:
		return "data_modification"
	case EdgeKindCanDelete:
		return "data_destruction"
	case EdgeKindCanAdmin:
		return "privilege_escalation"
	case EdgeKindConnectsTo:
		return "network_traversal"
	case EdgeKindExposedTo:
		return "external_access"
	case EdgeKindMemberOf:
		return "group_membership_abuse"
	case EdgeKindDeployedFrom:
		return "supply_chain"
	default:
		return "lateral_movement"
	}
}

// calculateImpactScore calculates an overall impact score (0-100)
func calculateImpactScore(result *CascadingBlastRadiusResult) float64 {
	score := 0.0

	// Base score from total impact
	score += float64(result.TotalImpact) * 2.0
	if score > 30 {
		score = 30
	}

	// Add for sensitive data hits
	score += float64(len(result.SensitiveDataHits)) * 10.0
	if score > 60 {
		score = 60
	}

	// Add for critical paths
	score += float64(result.CriticalPathCount) * 5.0

	// Add for account boundary crossings
	score += float64(len(result.AccountBoundaries)) * 8.0

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// suggestRemediationPaths suggests top remediation actions
func suggestRemediationPaths(result *CascadingBlastRadiusResult) []string {
	suggestions := make([]string, 0)

	// Suggest fixing sensitive data access first
	if len(result.SensitiveDataHits) > 0 {
		for _, hit := range result.SensitiveDataHits {
			if len(hit.ComplianceImpact) > 0 {
				label := "sensitive data"
				if len(hit.DataTypes) > 0 {
					label = hit.DataTypes[0]
				} else if hit.DataClassification != "" {
					label = hit.DataClassification
				}
				suggestions = append(suggestions,
					"Review access to "+hit.Node.Name+" (contains "+label+")")
				if len(suggestions) >= 3 {
					break
				}
			}
		}
	}

	// Suggest fixing account boundary crossings
	if len(result.AccountBoundaries) > 0 {
		suggestions = append(suggestions,
			"Review cross-account access from "+result.AccountBoundaries[0].FromAccount+
				" to "+result.AccountBoundaries[0].ToAccount)
	}

	// Suggest reducing blast radius at high-depth nodes
	if result.MaxCascadeDepth > 3 {
		suggestions = append(suggestions,
			"Consider least-privilege review to reduce cascade depth (currently "+
				strconv.Itoa(result.MaxCascadeDepth)+" hops)")
	}

	return suggestions
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// sliceContains checks if slice contains item
func sliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
