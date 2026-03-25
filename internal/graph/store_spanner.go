package graph

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/spanner"
	databaseadmin "cloud.google.com/go/spanner/admin/database/apiv1"
	databasepb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"google.golang.org/api/iterator"
)

const (
	spannerGraphNodesTable = "graph_nodes"
	spannerGraphEdgesTable = "graph_edges"
)

//go:embed schema/spanner_graph_store.sql
var spannerGraphStoreSchemaFS embed.FS

var (
	spannerGraphStoreSchemaOnce       sync.Once
	spannerGraphStoreSchemaStatements []string
	spannerGraphStoreSchemaErr        error
)

// SpannerDDLApplier applies DDL statements to a Cloud Spanner database.
type SpannerDDLApplier interface {
	ApplyDDL(ctx context.Context, database string, statements []string) error
}

type cloudSpannerDDLApplier struct {
	client *databaseadmin.DatabaseAdminClient
}

// NewCloudSpannerDDLApplier adapts the database admin client for optional graph
// store schema bootstrapping.
func NewCloudSpannerDDLApplier(client *databaseadmin.DatabaseAdminClient) SpannerDDLApplier {
	return &cloudSpannerDDLApplier{client: client}
}

func (a *cloudSpannerDDLApplier) ApplyDDL(ctx context.Context, database string, statements []string) error {
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	op, err := a.client.UpdateDatabaseDdl(ctx, &databasepb.UpdateDatabaseDdlRequest{
		Database:   strings.TrimSpace(database),
		Statements: append([]string(nil), statements...),
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// SpannerGraphStoreSchemaStatements exposes the DDL required for the Spanner
// graph backend so operators can review or apply it out of band.
func SpannerGraphStoreSchemaStatements() ([]string, error) {
	spannerGraphStoreSchemaOnce.Do(func() {
		raw, err := spannerGraphStoreSchemaFS.ReadFile("schema/spanner_graph_store.sql")
		if err != nil {
			spannerGraphStoreSchemaErr = err
			return
		}
		for _, statement := range strings.Split(string(raw), ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			spannerGraphStoreSchemaStatements = append(spannerGraphStoreSchemaStatements, statement)
		}
	})
	if spannerGraphStoreSchemaErr != nil {
		return nil, spannerGraphStoreSchemaErr
	}
	return append([]string(nil), spannerGraphStoreSchemaStatements...), nil
}

type spannerGraphStoreAdapter interface {
	UpsertNode(ctx context.Context, node *Node) error
	UpsertNodesBatch(ctx context.Context, nodes []*Node) error
	UpsertEdge(ctx context.Context, edge *Edge) error
	UpsertEdgesBatch(ctx context.Context, edges []*Edge) error
	DeleteNode(ctx context.Context, id string) error
	DeleteEdge(ctx context.Context, id string) error
	LookupNode(ctx context.Context, id string) (*Node, bool, error)
	LookupEdge(ctx context.Context, id string) (*Edge, bool, error)
	LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error)
	LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error)
	LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error)
	CountNodes(ctx context.Context) (int, error)
	CountEdges(ctx context.Context) (int, error)
	EnsureIndexes(ctx context.Context) error
	Snapshot(ctx context.Context) (*Snapshot, error)
}

type cloudSpannerGraphStoreAdapter struct {
	client     *spanner.Client
	database   string
	ddlApplier SpannerDDLApplier

	ensureOnce sync.Once
	ensureErr  error
}

// NewCloudSpannerGraphStoreAdapter creates the production Cloud Spanner adapter
// used by SpannerGraphStore.
func NewCloudSpannerGraphStoreAdapter(client *spanner.Client, database string, ddlApplier SpannerDDLApplier) spannerGraphStoreAdapter {
	return &cloudSpannerGraphStoreAdapter{
		client:     client,
		database:   strings.TrimSpace(database),
		ddlApplier: ddlApplier,
	}
}

// SpannerGraphStore persists graph records in Cloud Spanner and can optionally
// execute bounded traversals through Spanner Graph query patterns.
type SpannerGraphStore struct {
	adapter                spannerGraphStoreAdapter
	nativeTraversalQueries bool
}

var _ GraphStore = (*SpannerGraphStore)(nil)
var _ TenantScopeAwareGraphStore = (*SpannerGraphStore)(nil)

type SpannerGraphStoreOption func(*SpannerGraphStore)

type spannerTraversalDirection int

const (
	spannerTraversalDirectionBoth spannerTraversalDirection = iota
	spannerTraversalDirectionOutgoing
	spannerTraversalDirectionIncoming
)

type spannerGraphTraversalQuerier interface {
	QueryTraversalEdges(ctx context.Context, rootID string, direction spannerTraversalDirection, maxDepth int) ([]*Edge, error)
}

func WithSpannerNativeTraversalQueries(enabled bool) SpannerGraphStoreOption {
	return func(store *SpannerGraphStore) {
		if store != nil {
			store.nativeTraversalQueries = enabled
		}
	}
}

func NewSpannerGraphStore(adapter spannerGraphStoreAdapter, opts ...SpannerGraphStoreOption) *SpannerGraphStore {
	store := &SpannerGraphStore{adapter: adapter}
	for _, opt := range opts {
		if opt != nil {
			opt(store)
		}
	}
	return store
}

func (s *SpannerGraphStore) SupportsTenantReadScope() bool {
	return s != nil
}

func (s *SpannerGraphStore) UpsertNode(ctx context.Context, node *Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.UpsertNode(ctx, node)
}

func (s *SpannerGraphStore) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.UpsertNodesBatch(ctx, nodes)
}

func (s *SpannerGraphStore) UpsertEdge(ctx context.Context, edge *Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.UpsertEdge(ctx, edge)
}

func (s *SpannerGraphStore) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.UpsertEdgesBatch(ctx, edges)
}

func (s *SpannerGraphStore) DeleteNode(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.DeleteNode(ctx, id)
}

func (s *SpannerGraphStore) DeleteEdge(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.DeleteEdge(ctx, id)
}

func (s *SpannerGraphStore) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.adapter == nil {
		return nil, false, ErrStoreUnavailable
	}
	node, ok, err := s.adapter.LookupNode(ctx, id)
	if err != nil || !ok || node == nil {
		return nil, ok, err
	}
	if !spannerNodeVisibleForTenantScope(ctx, node) {
		return nil, false, nil
	}
	return node, true, nil
}

func (s *SpannerGraphStore) LookupEdge(ctx context.Context, id string) (*Edge, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.adapter == nil {
		return nil, false, ErrStoreUnavailable
	}
	edge, ok, err := s.adapter.LookupEdge(ctx, id)
	if err != nil || !ok || edge == nil {
		return nil, ok, err
	}
	if visible, err := s.spannerEdgeVisibleForTenantScope(ctx, edge); err != nil {
		return nil, false, err
	} else if !visible {
		return nil, false, nil
	}
	return edge, true, nil
}

func (s *SpannerGraphStore) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.adapter == nil {
		return nil, ErrStoreUnavailable
	}
	if _, ok, err := s.LookupNode(ctx, nodeID); err != nil {
		return nil, err
	} else if !ok {
		return nil, nil
	}
	edges, err := s.adapter.LookupOutEdges(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return s.filterEdgesForTenantScope(ctx, edges)
}

func (s *SpannerGraphStore) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.adapter == nil {
		return nil, ErrStoreUnavailable
	}
	if _, ok, err := s.LookupNode(ctx, nodeID); err != nil {
		return nil, err
	} else if !ok {
		return nil, nil
	}
	edges, err := s.adapter.LookupInEdges(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	return s.filterEdgesForTenantScope(ctx, edges)
}

func (s *SpannerGraphStore) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.adapter == nil {
		return nil, ErrStoreUnavailable
	}
	nodes, err := s.adapter.LookupNodesByKind(ctx, kinds...)
	if err != nil {
		return nil, err
	}
	return filterNodesForTenantScope(ctx, nodes), nil
}

func (s *SpannerGraphStore) CountNodes(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.adapter == nil {
		return 0, ErrStoreUnavailable
	}
	if !spannerTenantScopeEnabled(ctx) {
		return s.adapter.CountNodes(ctx)
	}
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	if snapshot == nil {
		return 0, nil
	}
	return snapshot.Metadata.NodeCount, nil
}

func (s *SpannerGraphStore) CountEdges(ctx context.Context) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.adapter == nil {
		return 0, ErrStoreUnavailable
	}
	if !spannerTenantScopeEnabled(ctx) {
		return s.adapter.CountEdges(ctx)
	}
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	if snapshot == nil {
		return 0, nil
	}
	return snapshot.Metadata.EdgeCount, nil
}

func (s *SpannerGraphStore) EnsureIndexes(ctx context.Context) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.adapter == nil {
		return ErrStoreUnavailable
	}
	return s.adapter.EnsureIndexes(ctx)
}

func (s *SpannerGraphStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.adapter == nil {
		return nil, ErrStoreUnavailable
	}
	snapshot, err := s.adapter.Snapshot(ctx)
	if err != nil || snapshot == nil {
		return snapshot, err
	}
	return filterSnapshotForTenantScope(ctx, snapshot), nil
}

func spannerTenantScopeEnabled(ctx context.Context) bool {
	scope, ok := TenantReadScopeFromContext(ctx)
	if !ok {
		return false
	}
	if scope.CrossTenant && len(scope.TenantIDs) == 0 {
		return false
	}
	return len(scope.TenantIDs) > 0
}

func spannerNodeVisibleForTenantScope(ctx context.Context, node *Node) bool {
	if node == nil {
		return false
	}
	if !spannerTenantScopeEnabled(ctx) {
		return true
	}
	if node.DeletedAt != nil {
		return false
	}
	tenantID := nodeTenantID(node)
	if tenantID == "" {
		return true
	}
	scope, _ := TenantReadScopeFromContext(ctx)
	for _, allowedTenantID := range scope.TenantIDs {
		if tenantID == allowedTenantID {
			return true
		}
	}
	return false
}

func filterNodesForTenantScope(ctx context.Context, nodes []*Node) []*Node {
	if len(nodes) == 0 {
		return nil
	}
	filtered := make([]*Node, 0, len(nodes))
	for _, node := range nodes {
		if spannerNodeVisibleForTenantScope(ctx, node) {
			filtered = append(filtered, node)
		}
	}
	return filtered
}

func filterSnapshotForTenantScope(ctx context.Context, snapshot *Snapshot) *Snapshot {
	if snapshot == nil || !spannerTenantScopeEnabled(ctx) {
		return snapshot
	}
	filteredNodes := filterNodesForTenantScope(ctx, snapshot.Nodes)
	visibleNodeIDs := make(map[string]struct{}, len(filteredNodes))
	activeNodeCount := 0
	for _, node := range filteredNodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		visibleNodeIDs[node.ID] = struct{}{}
		activeNodeCount++
	}
	filteredEdges := make([]*Edge, 0, len(snapshot.Edges))
	activeEdgeCount := 0
	for _, edge := range snapshot.Edges {
		if edge == nil {
			continue
		}
		if _, ok := visibleNodeIDs[edge.Source]; !ok {
			continue
		}
		if _, ok := visibleNodeIDs[edge.Target]; !ok {
			continue
		}
		filteredEdges = append(filteredEdges, edge)
		if edge.DeletedAt == nil {
			activeEdgeCount++
		}
	}
	filtered := *snapshot
	filtered.Metadata.NodeCount = activeNodeCount
	filtered.Metadata.EdgeCount = activeEdgeCount
	filtered.Nodes = filteredNodes
	filtered.Edges = filteredEdges
	return &filtered
}

func (s *SpannerGraphStore) filterEdgesForTenantScope(ctx context.Context, edges []*Edge) ([]*Edge, error) {
	if len(edges) == 0 {
		return nil, nil
	}
	filtered := make([]*Edge, 0, len(edges))
	for _, edge := range edges {
		visible, err := s.spannerEdgeVisibleForTenantScope(ctx, edge)
		if err != nil {
			return nil, err
		}
		if visible {
			filtered = append(filtered, edge)
		}
	}
	return filtered, nil
}

func (s *SpannerGraphStore) spannerEdgeVisibleForTenantScope(ctx context.Context, edge *Edge) (bool, error) {
	if edge == nil || edge.DeletedAt != nil {
		return false, nil
	}
	if !spannerTenantScopeEnabled(ctx) {
		return true, nil
	}
	if _, ok, err := s.LookupNode(ctx, edge.Source); err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}
	if _, ok, err := s.LookupNode(ctx, edge.Target); err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}
	return true, nil
}

func (s *SpannerGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error) {
	view, err := s.traversalGraph(ctx, principalID, spannerTraversalDirectionOutgoing, normalizeTraversalDepth(maxDepth))
	if err != nil {
		return nil, err
	}
	return view.BlastRadius(ctx, principalID, maxDepth)
}

func (s *SpannerGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*ReverseAccessResult, error) {
	view, err := s.traversalGraph(ctx, resourceID, spannerTraversalDirectionIncoming, normalizeTraversalDepth(maxDepth))
	if err != nil {
		return nil, err
	}
	return view.ReverseAccess(ctx, resourceID, maxDepth)
}

func (s *SpannerGraphStore) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*EffectiveAccessResult, error) {
	view, err := s.traversalGraph(ctx, principalID, spannerTraversalDirectionOutgoing, normalizeTraversalDepth(maxDepth))
	if err != nil {
		return nil, err
	}
	return view.EffectiveAccess(ctx, principalID, resourceID, maxDepth)
}

func (s *SpannerGraphStore) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*CascadingBlastRadiusResult, error) {
	view, err := s.materializedSnapshotStore(ctx)
	if err != nil {
		return nil, err
	}
	return view.CascadingBlastRadius(ctx, sourceID, maxDepth)
}

func (s *SpannerGraphStore) ExtractSubgraph(ctx context.Context, rootID string, opts ExtractSubgraphOptions) (*Graph, error) {
	view, err := s.traversalGraph(ctx, rootID, spannerTraversalDirectionFromExtractSubgraph(opts.Direction), normalizeTraversalDepthWithDefault(opts.MaxDepth, defaultExtractSubgraphMaxDepth))
	if err != nil {
		return nil, err
	}
	return view.ExtractSubgraph(ctx, rootID, opts)
}

func (s *SpannerGraphStore) materializedSnapshotStore(ctx context.Context) (*SnapshotGraphStore, error) {
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return NewSnapshotGraphStore(snapshot), nil
}

func (s *SpannerGraphStore) traversalGraph(ctx context.Context, rootID string, direction spannerTraversalDirection, maxDepth int) (*Graph, error) {
	if view, ok, err := s.nativeTraversalGraph(ctx, rootID, direction, maxDepth); err != nil {
		return nil, err
	} else if ok {
		return view, nil
	}
	return s.lookupTraversalGraph(ctx, rootID, direction, maxDepth)
}

func (s *SpannerGraphStore) lookupTraversalGraph(ctx context.Context, rootID string, direction spannerTraversalDirection, maxDepth int) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.adapter == nil {
		return nil, ErrStoreUnavailable
	}

	rootID = strings.TrimSpace(rootID)
	if rootID == "" {
		return New(), nil
	}
	root, ok, err := s.LookupNode(ctx, rootID)
	if err != nil {
		return nil, err
	}
	if !ok || root == nil {
		return New(), nil
	}

	view := New()
	view.AddNode(root)
	if maxDepth < 0 {
		return view, nil
	}

	frontier := []string{root.ID}
	visited := map[string]struct{}{root.ID: {}}
	for depth := 0; depth <= maxDepth && len(frontier) > 0; depth++ {
		nextFrontier := make([]string, 0, len(frontier))
		for _, nodeID := range frontier {
			if err := graphStoreContextErr(ctx); err != nil {
				return nil, err
			}
			var directions []spannerTraversalDirection
			switch direction {
			case spannerTraversalDirectionOutgoing:
				directions = []spannerTraversalDirection{spannerTraversalDirectionOutgoing}
			case spannerTraversalDirectionIncoming:
				directions = []spannerTraversalDirection{spannerTraversalDirectionIncoming}
			default:
				directions = []spannerTraversalDirection{spannerTraversalDirectionOutgoing, spannerTraversalDirectionIncoming}
			}
			for _, traversalDirection := range directions {
				neighborIDs, err := s.expandTraversalNode(ctx, view, nodeID, traversalDirection)
				if err != nil {
					return nil, err
				}
				for _, neighborID := range neighborIDs {
					if _, seen := visited[neighborID]; seen {
						continue
					}
					visited[neighborID] = struct{}{}
					nextFrontier = append(nextFrontier, neighborID)
				}
			}
		}
		frontier = nextFrontier
	}
	return view, nil
}

func (s *SpannerGraphStore) nativeTraversalGraph(ctx context.Context, rootID string, direction spannerTraversalDirection, maxDepth int) (*Graph, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, true, err
	}
	if s == nil || s.adapter == nil {
		return nil, true, ErrStoreUnavailable
	}
	if !s.nativeTraversalQueries {
		return nil, false, nil
	}
	// Native graph queries only support single-direction trails from the root.
	// Mixed-direction bidirectional traversal must use the lookup-based BFS.
	if direction == spannerTraversalDirectionBoth {
		return nil, false, nil
	}
	querier, ok := s.adapter.(spannerGraphTraversalQuerier)
	if !ok {
		return nil, false, nil
	}

	rootID = strings.TrimSpace(rootID)
	if rootID == "" {
		return New(), true, nil
	}
	root, ok, err := s.LookupNode(ctx, rootID)
	if err != nil {
		return nil, true, err
	}
	if !ok || root == nil {
		return New(), true, nil
	}

	view := New()
	view.AddNode(root)

	edgeByID := make(map[string]*Edge)
	nodeIDs := map[string]struct{}{root.ID: {}}
	edges, err := querier.QueryTraversalEdges(ctx, rootID, direction, maxDepth)
	if err != nil {
		return nil, true, err
	}
	for _, edge := range edges {
		if edge == nil || strings.TrimSpace(edge.ID) == "" {
			continue
		}
		visible, err := s.spannerEdgeVisibleForTenantScope(ctx, edge)
		if err != nil {
			return nil, true, err
		}
		if !visible {
			continue
		}
		edgeByID[edge.ID] = edge
		nodeIDs[edge.Source] = struct{}{}
		nodeIDs[edge.Target] = struct{}{}
	}

	for nodeID := range nodeIDs {
		if nodeID == root.ID {
			continue
		}
		node, ok, err := s.LookupNode(ctx, nodeID)
		if err != nil {
			return nil, true, err
		}
		if !ok || node == nil {
			continue
		}
		view.AddNode(node)
	}
	for _, edge := range edgeByID {
		if edge == nil {
			continue
		}
		if _, ok := view.GetNode(edge.Source); !ok {
			continue
		}
		if _, ok := view.GetNode(edge.Target); !ok {
			continue
		}
		view.AddEdge(edge)
	}
	return view, true, nil
}

func (s *SpannerGraphStore) expandTraversalNode(ctx context.Context, view *Graph, nodeID string, direction spannerTraversalDirection) ([]string, error) {
	var (
		edges []*Edge
		err   error
	)
	switch direction {
	case spannerTraversalDirectionIncoming:
		edges, err = s.LookupInEdges(ctx, nodeID)
	default:
		edges, err = s.LookupOutEdges(ctx, nodeID)
	}
	if err != nil {
		return nil, err
	}

	neighbors := make([]string, 0, len(edges))
	seen := make(map[string]struct{}, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		neighborID := edge.Target
		if direction == spannerTraversalDirectionIncoming {
			neighborID = edge.Source
		}
		neighbor, ok, err := s.LookupNode(ctx, neighborID)
		if err != nil {
			return nil, err
		}
		if !ok || neighbor == nil {
			continue
		}
		view.AddNode(neighbor)
		view.AddEdge(edge)
		if _, exists := seen[neighborID]; exists {
			continue
		}
		seen[neighborID] = struct{}{}
		neighbors = append(neighbors, neighborID)
	}
	return neighbors, nil
}

func spannerTraversalDirectionFromExtractSubgraph(direction ExtractSubgraphDirection) spannerTraversalDirection {
	switch direction {
	case ExtractSubgraphDirectionOutgoing:
		return spannerTraversalDirectionOutgoing
	case ExtractSubgraphDirectionIncoming:
		return spannerTraversalDirectionIncoming
	default:
		return spannerTraversalDirectionBoth
	}
}

func (a *cloudSpannerGraphStoreAdapter) UpsertNode(ctx context.Context, node *Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return nil
	}
	return a.apply(ctx, []*spanner.Mutation{spanner.InsertOrUpdateMap(spannerGraphNodesTable, spannerNodeMutationMap(node))})
}

func (a *cloudSpannerGraphStoreAdapter) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	mutations := make([]*spanner.Mutation, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || strings.TrimSpace(node.ID) == "" {
			continue
		}
		mutations = append(mutations, spanner.InsertOrUpdateMap(spannerGraphNodesTable, spannerNodeMutationMap(node)))
	}
	return a.apply(ctx, mutations)
}

func (a *cloudSpannerGraphStoreAdapter) UpsertEdge(ctx context.Context, edge *Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	if edge == nil || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
		return nil
	}
	return a.apply(ctx, []*spanner.Mutation{spanner.InsertOrUpdateMap(spannerGraphEdgesTable, spannerEdgeMutationMap(edge))})
}

func (a *cloudSpannerGraphStoreAdapter) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	mutations := make([]*spanner.Mutation, 0, len(edges))
	for _, edge := range edges {
		if edge == nil || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
			continue
		}
		mutations = append(mutations, spanner.InsertOrUpdateMap(spannerGraphEdgesTable, spannerEdgeMutationMap(edge)))
	}
	return a.apply(ctx, mutations)
}

func (a *cloudSpannerGraphStoreAdapter) DeleteNode(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	node, ok, err := a.lookupNodeAny(ctx, strings.TrimSpace(id))
	if err != nil || !ok || node == nil || node.DeletedAt != nil {
		return err
	}
	now := time.Now().UTC()
	updatedNode := cloneNode(node)
	updatedNode.UpdatedAt = now
	updatedNode.DeletedAt = &now
	if updatedNode.Version <= 0 {
		updatedNode.Version = 1
	}
	updatedNode.Version++

	edges, err := a.lookupEdgesTouchingNode(ctx, updatedNode.ID)
	if err != nil {
		return err
	}
	mutations := []*spanner.Mutation{spanner.InsertOrUpdateMap(spannerGraphNodesTable, spannerNodeMutationMap(updatedNode))}
	for _, edge := range edges {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		updatedEdge := cloneEdge(edge)
		updatedEdge.DeletedAt = &now
		if updatedEdge.Version <= 0 {
			updatedEdge.Version = 1
		}
		updatedEdge.Version++
		mutations = append(mutations, spanner.InsertOrUpdateMap(spannerGraphEdgesTable, spannerEdgeMutationMap(updatedEdge)))
	}
	return a.apply(ctx, mutations)
}

func (a *cloudSpannerGraphStoreAdapter) DeleteEdge(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	edge, ok, err := a.lookupEdgeAny(ctx, strings.TrimSpace(id))
	if err != nil || !ok || edge == nil || edge.DeletedAt != nil {
		return err
	}
	now := time.Now().UTC()
	updatedEdge := cloneEdge(edge)
	updatedEdge.DeletedAt = &now
	if updatedEdge.Version <= 0 {
		updatedEdge.Version = 1
	}
	updatedEdge.Version++
	return a.apply(ctx, []*spanner.Mutation{spanner.InsertOrUpdateMap(spannerGraphEdgesTable, spannerEdgeMutationMap(updatedEdge))})
}

func (a *cloudSpannerGraphStoreAdapter) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	return a.lookupNode(ctx, strings.TrimSpace(id), false)
}

func (a *cloudSpannerGraphStoreAdapter) LookupEdge(ctx context.Context, id string) (*Edge, bool, error) {
	return a.lookupEdge(ctx, strings.TrimSpace(id), false)
}

func (a *cloudSpannerGraphStoreAdapter) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	return a.queryEdges(ctx, spanner.Statement{
		SQL: `SELECT
  e.edge_id, e.source_node_id, e.target_node_id, e.kind, e.effect, e.priority,
  e.properties_json, e.risk, e.created_at, e.deleted_at, e.version
FROM graph_edges e
JOIN graph_nodes src ON src.node_id = e.source_node_id
JOIN graph_nodes dst ON dst.node_id = e.target_node_id
WHERE e.source_node_id = @node_id
  AND e.deleted_at IS NULL
  AND src.deleted_at IS NULL
  AND dst.deleted_at IS NULL`,
		Params: map[string]any{"node_id": strings.TrimSpace(nodeID)},
	})
}

func (a *cloudSpannerGraphStoreAdapter) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	return a.queryEdges(ctx, spanner.Statement{
		SQL: `SELECT
  e.edge_id, e.source_node_id, e.target_node_id, e.kind, e.effect, e.priority,
  e.properties_json, e.risk, e.created_at, e.deleted_at, e.version
FROM graph_edges e
JOIN graph_nodes src ON src.node_id = e.source_node_id
JOIN graph_nodes dst ON dst.node_id = e.target_node_id
WHERE e.target_node_id = @node_id
  AND e.deleted_at IS NULL
  AND src.deleted_at IS NULL
  AND dst.deleted_at IS NULL`,
		Params: map[string]any{"node_id": strings.TrimSpace(nodeID)},
	})
}

func (a *cloudSpannerGraphStoreAdapter) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	rawKinds := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		trimmed := strings.TrimSpace(string(kind))
		if trimmed != "" {
			rawKinds = append(rawKinds, trimmed)
		}
	}
	if len(rawKinds) == 0 {
		return nil, nil
	}
	return a.queryNodes(ctx, spanner.Statement{
		SQL: `SELECT
  node_id, kind, name, tenant_id, provider, account, region, properties_json,
  tags_json, risk, findings_json, created_at, updated_at, deleted_at, version,
  previous_properties_json, property_history_json
FROM graph_nodes
WHERE deleted_at IS NULL
  AND kind IN UNNEST(@kinds)`,
		Params: map[string]any{"kinds": rawKinds},
	})
}

func (a *cloudSpannerGraphStoreAdapter) CountNodes(ctx context.Context) (int, error) {
	return a.queryCount(ctx, `SELECT COUNT(1) AS total FROM graph_nodes WHERE deleted_at IS NULL`, nil)
}

func (a *cloudSpannerGraphStoreAdapter) CountEdges(ctx context.Context) (int, error) {
	return a.queryCount(ctx, `SELECT COUNT(1) AS total
FROM graph_edges e
JOIN graph_nodes src ON src.node_id = e.source_node_id
JOIN graph_nodes dst ON dst.node_id = e.target_node_id
WHERE e.deleted_at IS NULL
  AND src.deleted_at IS NULL
  AND dst.deleted_at IS NULL`, nil)
}

func (a *cloudSpannerGraphStoreAdapter) EnsureIndexes(ctx context.Context) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if a == nil || a.client == nil {
		return ErrStoreUnavailable
	}
	if a.ddlApplier == nil || a.database == "" {
		return nil
	}
	a.ensureOnce.Do(func() {
		statements, err := SpannerGraphStoreSchemaStatements()
		if err != nil {
			a.ensureErr = err
			return
		}
		a.ensureErr = a.ddlApplier.ApplyDDL(ctx, a.database, statements)
	})
	return a.ensureErr
}

func (a *cloudSpannerGraphStoreAdapter) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.client == nil {
		return nil, ErrStoreUnavailable
	}
	nodes, err := a.queryNodes(ctx, spanner.Statement{
		SQL: `SELECT
  node_id, kind, name, tenant_id, provider, account, region, properties_json,
  tags_json, risk, findings_json, created_at, updated_at, deleted_at, version,
  previous_properties_json, property_history_json
FROM graph_nodes`,
	})
	if err != nil {
		return nil, err
	}
	edges, err := a.queryEdges(ctx, spanner.Statement{
		SQL: `SELECT
  edge_id, source_node_id, target_node_id, kind, effect, priority,
  properties_json, risk, created_at, deleted_at, version
FROM graph_edges`,
	})
	if err != nil {
		return nil, err
	}
	activeNodes := 0
	for _, node := range nodes {
		if node != nil && node.DeletedAt == nil {
			activeNodes++
		}
	}
	activeEdges := 0
	for _, edge := range edges {
		if edge != nil && edge.DeletedAt == nil {
			activeEdges++
		}
	}
	return &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: time.Now().UTC(),
		Metadata: Metadata{
			BuiltAt:   time.Now().UTC(),
			NodeCount: activeNodes,
			EdgeCount: activeEdges,
		},
		Nodes: nodes,
		Edges: edges,
	}, nil
}

func (a *cloudSpannerGraphStoreAdapter) lookupNode(ctx context.Context, id string, includeDeleted bool) (*Node, bool, error) {
	if strings.TrimSpace(id) == "" {
		return nil, false, nil
	}
	sql := `SELECT
  node_id, kind, name, tenant_id, provider, account, region, properties_json,
  tags_json, risk, findings_json, created_at, updated_at, deleted_at, version,
  previous_properties_json, property_history_json
FROM graph_nodes
WHERE node_id = @node_id`
	if !includeDeleted {
		sql += ` AND deleted_at IS NULL`
	}
	nodes, err := a.queryNodes(ctx, spanner.Statement{SQL: sql, Params: map[string]any{"node_id": id}})
	if err != nil || len(nodes) == 0 {
		return nil, false, err
	}
	return nodes[0], true, nil
}

func (a *cloudSpannerGraphStoreAdapter) lookupNodeAny(ctx context.Context, id string) (*Node, bool, error) {
	return a.lookupNode(ctx, id, true)
}

func (a *cloudSpannerGraphStoreAdapter) lookupEdge(ctx context.Context, id string, includeDeleted bool) (*Edge, bool, error) {
	if strings.TrimSpace(id) == "" {
		return nil, false, nil
	}
	sql := `SELECT
  edge_id, source_node_id, target_node_id, kind, effect, priority,
  properties_json, risk, created_at, deleted_at, version
FROM graph_edges
WHERE edge_id = @edge_id`
	if !includeDeleted {
		sql += ` AND deleted_at IS NULL`
	}
	edges, err := a.queryEdges(ctx, spanner.Statement{SQL: sql, Params: map[string]any{"edge_id": id}})
	if err != nil || len(edges) == 0 {
		return nil, false, err
	}
	return edges[0], true, nil
}

func (a *cloudSpannerGraphStoreAdapter) lookupEdgeAny(ctx context.Context, id string) (*Edge, bool, error) {
	return a.lookupEdge(ctx, id, true)
}

func (a *cloudSpannerGraphStoreAdapter) lookupEdgesTouchingNode(ctx context.Context, nodeID string) ([]*Edge, error) {
	return a.queryEdges(ctx, spanner.Statement{
		SQL: `SELECT
  edge_id, source_node_id, target_node_id, kind, effect, priority,
  properties_json, risk, created_at, deleted_at, version
FROM graph_edges
WHERE source_node_id = @node_id OR target_node_id = @node_id`,
		Params: map[string]any{"node_id": nodeID},
	})
}

func (a *cloudSpannerGraphStoreAdapter) queryNodes(ctx context.Context, statement spanner.Statement) ([]*Node, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	txn := a.client.Single()
	defer txn.Close()
	iter := txn.Query(ctx, statement)
	defer iter.Stop()

	nodes := make([]*Node, 0)
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return nodes, nil
		}
		if err != nil {
			return nil, err
		}
		node, err := spannerRowToNode(row)
		if err != nil {
			return nil, err
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}
}

func (a *cloudSpannerGraphStoreAdapter) queryEdges(ctx context.Context, statement spanner.Statement) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	txn := a.client.Single()
	defer txn.Close()
	iter := txn.Query(ctx, statement)
	defer iter.Stop()

	edges := make([]*Edge, 0)
	for {
		row, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return edges, nil
		}
		if err != nil {
			return nil, err
		}
		edge, err := spannerRowToEdge(row)
		if err != nil {
			return nil, err
		}
		if edge != nil {
			edges = append(edges, edge)
		}
	}
}

func (a *cloudSpannerGraphStoreAdapter) queryCount(ctx context.Context, sql string, params map[string]any) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	txn := a.client.Single()
	defer txn.Close()
	iter := txn.Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer iter.Stop()
	row, err := iter.Next()
	if errors.Is(err, iterator.Done) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	if err := row.ColumnByName("total", &total); err != nil {
		return 0, err
	}
	return int(total), nil
}

func (a *cloudSpannerGraphStoreAdapter) QueryTraversalEdges(ctx context.Context, rootID string, direction spannerTraversalDirection, maxDepth int) ([]*Edge, error) {
	statement, err := spannerGraphTraversalEdgesStatement(rootID, direction, maxDepth)
	if err != nil {
		return nil, err
	}
	return a.queryEdges(ctx, statement)
}

func (a *cloudSpannerGraphStoreAdapter) apply(ctx context.Context, mutations []*spanner.Mutation) error {
	if len(mutations) == 0 {
		return nil
	}
	_, err := a.client.Apply(ctx, mutations)
	return err
}

func spannerNodeMutationMap(node *Node) map[string]any {
	if node == nil {
		return nil
	}
	normalizeNodeTenantID(node)
	return map[string]any{
		"node_id":                  strings.TrimSpace(node.ID),
		"kind":                     strings.TrimSpace(string(node.Kind)),
		"name":                     spannerNullableString(node.Name),
		"tenant_id":                spannerNullableString(node.TenantID),
		"provider":                 spannerNullableString(node.Provider),
		"account":                  spannerNullableString(node.Account),
		"region":                   spannerNullableString(node.Region),
		"properties_json":          spannerNullableString(mustJSON(node.PropertyMap())),
		"tags_json":                spannerNullableString(mustJSON(node.Tags)),
		"risk":                     spannerNullableString(string(node.Risk)),
		"findings_json":            spannerNullableString(mustJSON(node.Findings)),
		"created_at":               node.CreatedAt.UTC(),
		"updated_at":               node.UpdatedAt.UTC(),
		"deleted_at":               spannerNullableTime(node.DeletedAt),
		"version":                  int64(node.Version),
		"previous_properties_json": spannerNullableString(mustJSON(node.PreviousProperties)),
		"property_history_json":    spannerNullableString(mustJSON(node.PropertyHistory)),
	}
}

func spannerEdgeMutationMap(edge *Edge) map[string]any {
	if edge == nil {
		return nil
	}
	return map[string]any{
		"edge_id":         strings.TrimSpace(edge.ID),
		"source_node_id":  strings.TrimSpace(edge.Source),
		"target_node_id":  strings.TrimSpace(edge.Target),
		"kind":            strings.TrimSpace(string(edge.Kind)),
		"effect":          spannerNullableString(string(edge.Effect)),
		"priority":        int64(edge.Priority),
		"properties_json": spannerNullableString(mustJSON(edge.Properties)),
		"risk":            spannerNullableString(string(edge.Risk)),
		"created_at":      edge.CreatedAt.UTC(),
		"deleted_at":      spannerNullableTime(edge.DeletedAt),
		"version":         int64(edge.Version),
	}
}

func spannerRowToNode(row *spanner.Row) (*Node, error) {
	if row == nil {
		return nil, nil
	}
	var (
		id                    string
		kind                  string
		name                  spanner.NullString
		tenantID              spanner.NullString
		provider              spanner.NullString
		account               spanner.NullString
		region                spanner.NullString
		propertiesJSON        spanner.NullString
		tagsJSON              spanner.NullString
		risk                  spanner.NullString
		findingsJSON          spanner.NullString
		createdAt             time.Time
		updatedAt             time.Time
		deletedAt             spanner.NullTime
		version               int64
		previousPropertiesRaw spanner.NullString
		propertyHistoryRaw    spanner.NullString
	)
	if err := row.Columns(
		&id, &kind, &name, &tenantID, &provider, &account, &region, &propertiesJSON,
		&tagsJSON, &risk, &findingsJSON, &createdAt, &updatedAt, &deletedAt, &version,
		&previousPropertiesRaw, &propertyHistoryRaw,
	); err != nil {
		return nil, err
	}
	node := &Node{
		ID:        spannerNodeID(id),
		Kind:      NodeKind(kind),
		Name:      name.StringVal,
		TenantID:  tenantID.StringVal,
		Provider:  provider.StringVal,
		Account:   account.StringVal,
		Region:    region.StringVal,
		Risk:      RiskLevel(risk.StringVal),
		CreatedAt: createdAt.UTC(),
		UpdatedAt: updatedAt.UTC(),
		Version:   int(version),
	}
	if deletedAt.Valid {
		value := deletedAt.Time.UTC()
		node.DeletedAt = &value
	}
	if err := decodeJSONString(propertiesJSON.StringVal, &node.Properties); err != nil {
		return nil, fmt.Errorf("decode spanner node properties: %w", err)
	}
	if err := decodeJSONString(tagsJSON.StringVal, &node.Tags); err != nil {
		return nil, fmt.Errorf("decode spanner node tags: %w", err)
	}
	if err := decodeJSONString(findingsJSON.StringVal, &node.Findings); err != nil {
		return nil, fmt.Errorf("decode spanner node findings: %w", err)
	}
	if err := decodeJSONString(previousPropertiesRaw.StringVal, &node.PreviousProperties); err != nil {
		return nil, fmt.Errorf("decode spanner previous node properties: %w", err)
	}
	if err := decodeJSONString(propertyHistoryRaw.StringVal, &node.PropertyHistory); err != nil {
		return nil, fmt.Errorf("decode spanner node property history: %w", err)
	}
	normalizeNodeTenantID(node)
	return node, nil
}

func spannerRowToEdge(row *spanner.Row) (*Edge, error) {
	if row == nil {
		return nil, nil
	}
	var (
		id             string
		sourceID       string
		targetID       string
		kind           string
		effect         spanner.NullString
		priority       int64
		propertiesJSON spanner.NullString
		risk           spanner.NullString
		createdAt      time.Time
		deletedAt      spanner.NullTime
		version        int64
	)
	if err := row.Columns(&id, &sourceID, &targetID, &kind, &effect, &priority, &propertiesJSON, &risk, &createdAt, &deletedAt, &version); err != nil {
		return nil, err
	}
	edge := &Edge{
		ID:        spannerEdgeID(id),
		Source:    spannerNodeID(sourceID),
		Target:    spannerNodeID(targetID),
		Kind:      EdgeKind(kind),
		Effect:    EdgeEffect(effect.StringVal),
		Priority:  int(priority),
		Risk:      RiskLevel(risk.StringVal),
		CreatedAt: createdAt.UTC(),
		Version:   int(version),
	}
	if deletedAt.Valid {
		value := deletedAt.Time.UTC()
		edge.DeletedAt = &value
	}
	if err := decodeJSONString(propertiesJSON.StringVal, &edge.Properties); err != nil {
		return nil, fmt.Errorf("decode spanner edge properties: %w", err)
	}
	return edge, nil
}

func spannerNodeID(id string) string {
	return strings.TrimSpace(id)
}

func spannerEdgeID(id string) string {
	return strings.TrimSpace(id)
}

func spannerNullableString(value string) spanner.NullString {
	value = strings.TrimSpace(value)
	if value == "" {
		return spanner.NullString{}
	}
	return spanner.NullString{StringVal: value, Valid: true}
}

func spannerNullableTime(value *time.Time) spanner.NullTime {
	if value == nil || value.IsZero() {
		return spanner.NullTime{}
	}
	return spanner.NullTime{Time: value.UTC(), Valid: true}
}
