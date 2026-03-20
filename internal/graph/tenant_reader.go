package graph

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"
)

var (
	ErrTenantScopeRequired      = errors.New("graph read requires tenant scope")
	ErrCrossTenantScopeRequired = errors.New("cross-tenant graph read requires explicit cross-tenant scope")
)

type tenantReadScopeContextKey struct{}

// TenantReadScope describes the tenant visibility requested for graph reads.
type TenantReadScope struct {
	TenantIDs   []string `json:"tenant_ids,omitempty"`
	CrossTenant bool     `json:"cross_tenant,omitempty"`
	AuditActor  string   `json:"audit_actor,omitempty"`
	AuditReason string   `json:"audit_reason,omitempty"`
}

// TenantReadStats summarizes tenant visibility over the current graph snapshot.
type TenantReadStats struct {
	TotalTenants   int            `json:"total_tenants"`
	VisibleTenants []string       `json:"visible_tenants,omitempty"`
	NodeCounts     map[string]int `json:"node_counts,omitempty"`
}

// TenantReader provides tenant-filtered graph reads without cloning the graph.
type TenantReader struct {
	graph        *Graph
	scope        TenantReadScope
	stats        TenantReadStats
	allowed      map[string]struct{}
	unrestricted bool
}

var tenantReadAuditHook = func(scope TenantReadScope, visibleTenants []string) {
	if !scope.CrossTenant {
		return
	}
	slog.Default().Info("graph cross-tenant read scope granted",
		"audit_actor", strings.TrimSpace(scope.AuditActor),
		"audit_reason", strings.TrimSpace(scope.AuditReason),
		"tenant_ids", append([]string(nil), visibleTenants...),
	)
}

func WithTenantReadScope(ctx context.Context, scope TenantReadScope) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	scope = normalizeTenantReadScope(scope)
	return context.WithValue(ctx, tenantReadScopeContextKey{}, scope)
}

func WithTenantScope(ctx context.Context, tenantID string) context.Context {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return WithTenantReadScope(ctx, TenantReadScope{})
	}
	return WithTenantReadScope(ctx, TenantReadScope{TenantIDs: []string{tenantID}})
}

func WithCrossTenantScope(ctx context.Context, actor, reason string, tenantIDs ...string) context.Context {
	return WithTenantReadScope(ctx, TenantReadScope{
		TenantIDs:   append([]string(nil), tenantIDs...),
		CrossTenant: true,
		AuditActor:  strings.TrimSpace(actor),
		AuditReason: strings.TrimSpace(reason),
	})
}

func TenantReadScopeFromContext(ctx context.Context) (TenantReadScope, bool) {
	if ctx == nil {
		return TenantReadScope{}, false
	}
	scope, ok := ctx.Value(tenantReadScopeContextKey{}).(TenantReadScope)
	if !ok {
		return TenantReadScope{}, false
	}
	return normalizeTenantReadScope(scope), true
}

func normalizeTenantReadScope(scope TenantReadScope) TenantReadScope {
	scope.AuditActor = strings.TrimSpace(scope.AuditActor)
	scope.AuditReason = strings.TrimSpace(scope.AuditReason)
	if len(scope.TenantIDs) == 0 {
		scope.TenantIDs = nil
		return scope
	}
	seen := make(map[string]struct{}, len(scope.TenantIDs))
	normalized := make([]string, 0, len(scope.TenantIDs))
	for _, tenantID := range scope.TenantIDs {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			continue
		}
		if _, ok := seen[tenantID]; ok {
			continue
		}
		seen[tenantID] = struct{}{}
		normalized = append(normalized, tenantID)
	}
	sort.Strings(normalized)
	scope.TenantIDs = normalized
	return scope
}

func (g *Graph) NewTenantReader(ctx context.Context) (*TenantReader, error) {
	if g == nil {
		return &TenantReader{}, nil
	}
	scope, _ := TenantReadScopeFromContext(ctx)
	scope = normalizeTenantReadScope(scope)

	g.mu.RLock()
	defer g.mu.RUnlock()

	counts := tenantNodeCountsLocked(g.nodes)
	totalTenants := len(counts)
	visibleTenants := make([]string, 0, len(scope.TenantIDs))
	unrestricted := false
	switch {
	case scope.CrossTenant && len(scope.TenantIDs) == 0:
		unrestricted = true
		visibleTenants = sortedTenantIDs(counts)
	case scope.CrossTenant:
		visibleTenants = append(visibleTenants, scope.TenantIDs...)
	case len(scope.TenantIDs) == 0 && totalTenants <= 1:
		unrestricted = true
		visibleTenants = sortedTenantIDs(counts)
	case len(scope.TenantIDs) == 0:
		return nil, ErrTenantScopeRequired
	case len(scope.TenantIDs) > 1:
		return nil, ErrCrossTenantScopeRequired
	default:
		visibleTenants = append(visibleTenants, scope.TenantIDs...)
	}

	allowed := make(map[string]struct{}, len(visibleTenants))
	for _, tenantID := range visibleTenants {
		allowed[tenantID] = struct{}{}
	}
	stats := TenantReadStats{
		VisibleTenants: append([]string(nil), visibleTenants...),
	}
	if scope.CrossTenant {
		stats.TotalTenants = totalTenants
		stats.NodeCounts = counts
	}
	reader := &TenantReader{
		graph:        g,
		scope:        scope,
		stats:        stats,
		allowed:      allowed,
		unrestricted: unrestricted,
	}
	if scope.CrossTenant {
		tenantReadAuditHook(scope, stats.VisibleTenants)
	}
	return reader, nil
}

func tenantNodeCountsLocked(nodes map[string]*Node) map[string]int {
	counts := make(map[string]int)
	for _, node := range nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		tenantID := nodeTenantID(node)
		if tenantID == "" {
			continue
		}
		counts[tenantID]++
	}
	return counts
}

func sortedTenantIDs(counts map[string]int) []string {
	if len(counts) == 0 {
		return nil
	}
	tenantIDs := make([]string, 0, len(counts))
	for tenantID := range counts {
		tenantIDs = append(tenantIDs, tenantID)
	}
	sort.Strings(tenantIDs)
	return tenantIDs
}

func (r *TenantReader) Scope() TenantReadScope {
	if r == nil {
		return TenantReadScope{}
	}
	return r.scope
}

func (r *TenantReader) Stats() TenantReadStats {
	if r == nil {
		return TenantReadStats{}
	}
	stats := TenantReadStats{
		TotalTenants:   r.stats.TotalTenants,
		VisibleTenants: append([]string(nil), r.stats.VisibleTenants...),
	}
	if len(r.stats.NodeCounts) > 0 {
		stats.NodeCounts = make(map[string]int, len(r.stats.NodeCounts))
		for tenantID, count := range r.stats.NodeCounts {
			stats.NodeCounts[tenantID] = count
		}
	}
	return stats
}

func (r *TenantReader) nodeVisible(node *Node) bool {
	if node == nil || node.DeletedAt != nil {
		return false
	}
	if r == nil || r.unrestricted {
		return true
	}
	tenantID := nodeTenantID(node)
	if tenantID == "" {
		return true
	}
	_, ok := r.allowed[tenantID]
	return ok
}

func (r *TenantReader) GetNode(id string) (*Node, bool) {
	if r == nil || r.graph == nil {
		return nil, false
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	node, ok := r.graph.nodes[id]
	if !ok || !r.nodeVisible(node) {
		return nil, false
	}
	return node, true
}

func (r *TenantReader) GetNodeBitemporal(nodeID string, validAt, recordedAt time.Time) (*Node, bool) {
	if r == nil || r.graph == nil {
		return nil, false
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	node, ok := r.graph.nodes[nodeID]
	if !ok || node == nil || node.DeletedAt != nil || !r.nodeVisible(node) {
		return nil, false
	}
	if !r.graph.nodeVisibleAtLocked(node, validAt, recordedAt) {
		return nil, false
	}
	return node, true
}

func (r *TenantReader) GetAllNodes() []*Node {
	if r == nil || r.graph == nil {
		return nil
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterNodesLocked(r.graph.nodes, func(node *Node) bool {
		return node != nil && node.DeletedAt == nil
	})
}

func (r *TenantReader) GetAllNodesAt(at time.Time) []*Node {
	if r == nil || r.graph == nil {
		return nil
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterNodesLocked(r.graph.nodes, func(node *Node) bool {
		return r.graph.nodeActiveAtLocked(node, at)
	})
}

func (r *TenantReader) GetAllNodesBitemporal(validAt, recordedAt time.Time) []*Node {
	if r == nil || r.graph == nil {
		return nil
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterNodesLocked(r.graph.nodes, func(node *Node) bool {
		return r.graph.nodeVisibleAtLocked(node, validAt, recordedAt)
	})
}

func (r *TenantReader) GetNodesByKind(kinds ...NodeKind) []*Node {
	if r == nil || r.graph == nil {
		return nil
	}
	kindSet := make(map[NodeKind]struct{}, len(kinds))
	for _, kind := range kinds {
		kindSet[kind] = struct{}{}
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterNodesLocked(r.graph.nodes, func(node *Node) bool {
		if node == nil || node.DeletedAt != nil {
			return false
		}
		_, ok := kindSet[node.Kind]
		return ok
	})
}

func (r *TenantReader) GetOutEdges(nodeID string) []*Edge {
	if r == nil || r.graph == nil {
		return nil
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterEdgesLocked(nodeID, r.graph.activeEdgesForNodeLocked(r.graph.outEdges[nodeID]))
}

func (r *TenantReader) GetInEdges(nodeID string) []*Edge {
	if r == nil || r.graph == nil {
		return nil
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterEdgesLocked(nodeID, r.graph.activeEdgesForNodeLocked(r.graph.inEdges[nodeID]))
}

func (r *TenantReader) GetOutEdgesAt(nodeID string, at time.Time) []*Edge {
	if r == nil || r.graph == nil {
		return nil
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterEdgesLocked(nodeID, r.graph.activeEdgesAtForNodeLocked(r.graph.outEdges[nodeID], at))
}

func (r *TenantReader) GetInEdgesAt(nodeID string, at time.Time) []*Edge {
	if r == nil || r.graph == nil {
		return nil
	}
	if at.IsZero() {
		at = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterEdgesLocked(nodeID, r.graph.activeEdgesAtForNodeLocked(r.graph.inEdges[nodeID], at))
}

func (r *TenantReader) GetOutEdgesBitemporal(nodeID string, validAt, recordedAt time.Time) []*Edge {
	if r == nil || r.graph == nil {
		return nil
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterEdgesLocked(nodeID, r.graph.activeEdgesBitemporalForNodeLocked(r.graph.outEdges[nodeID], validAt, recordedAt))
}

func (r *TenantReader) GetInEdgesBitemporal(nodeID string, validAt, recordedAt time.Time) []*Edge {
	if r == nil || r.graph == nil {
		return nil
	}
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	r.graph.mu.RLock()
	defer r.graph.mu.RUnlock()
	return r.filterEdgesLocked(nodeID, r.graph.activeEdgesBitemporalForNodeLocked(r.graph.inEdges[nodeID], validAt, recordedAt))
}

func (r *TenantReader) filterNodesLocked(nodes map[string]*Node, include func(*Node) bool) []*Node {
	filtered := make([]*Node, 0, len(nodes))
	for _, node := range nodes {
		if !include(node) || !r.nodeVisible(node) {
			continue
		}
		filtered = append(filtered, node)
	}
	return filtered
}

func (r *TenantReader) filterEdgesLocked(nodeID string, edges []*Edge) []*Edge {
	if len(edges) == 0 {
		return nil
	}
	sourceNode, ok := r.graph.nodes[nodeID]
	if !ok || !r.nodeVisible(sourceNode) {
		return nil
	}
	filtered := make([]*Edge, 0, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		source := r.graph.nodes[edge.Source]
		target := r.graph.nodes[edge.Target]
		if !r.nodeVisible(source) || !r.nodeVisible(target) {
			continue
		}
		filtered = append(filtered, edge)
	}
	return filtered
}
