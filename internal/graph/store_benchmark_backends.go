package graph

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// NewBenchmarkMemoryBackedNeptuneStore returns a NeptuneGraphStore backed by an
// in-memory openCypher executor so benchmark runs can exercise the Neptune
// store code path without requiring a live Neptune cluster.
func NewBenchmarkMemoryBackedNeptuneStore(base *Graph) GraphStore {
	if base == nil {
		base = New()
	}
	return NewNeptuneGraphStore(&benchmarkNeptuneExecutor{graph: base.Clone()})
}

type benchmarkNeptuneExecutor struct {
	graph *Graph
}

func (b *benchmarkNeptuneExecutor) ExecuteOpenCypher(ctx context.Context, query string, params map[string]any) (any, error) {
	trimmed := strings.TrimSpace(query)

	switch trimmed {
	case strings.TrimSpace(neptuneUpsertNodeQuery):
		node, err := neptuneDecodeNode(params)
		if err != nil {
			return nil, err
		}
		if node != nil {
			b.graph.AddNode(node)
			return []any{map[string]any{"id": node.ID}}, nil
		}
		return nil, nil
	case strings.TrimSpace(neptuneUpsertNodesBatchQuery):
		rows := benchmarkNeptuneRowParams(params)
		for _, record := range rows {
			node, err := neptuneDecodeNode(record)
			if err != nil {
				return nil, err
			}
			if node != nil {
				b.graph.AddNode(node)
			}
		}
		return []any{map[string]any{"total": len(rows)}}, nil
	case strings.TrimSpace(neptuneUpsertEdgeQuery):
		edge, err := neptuneDecodeEdge(params)
		if err != nil {
			return nil, err
		}
		if edge != nil {
			b.graph.AddEdge(edge)
			return []any{map[string]any{"id": edge.ID}}, nil
		}
		return nil, nil
	case strings.TrimSpace(neptuneUpsertEdgesBatchQuery):
		rows := benchmarkNeptuneRowParams(params)
		for _, record := range rows {
			edge, err := neptuneDecodeEdge(record)
			if err != nil {
				return nil, err
			}
			if edge != nil {
				b.graph.AddEdge(edge)
			}
		}
		return []any{map[string]any{"total": len(rows)}}, nil
	case strings.TrimSpace(neptuneDeleteNodeQuery):
		id, _ := params["id"].(string)
		if err := GraphStore(b.graph).DeleteNode(ctx, strings.TrimSpace(id)); err != nil {
			return nil, err
		}
		return []any{map[string]any{"total": 1}}, nil
	case strings.TrimSpace(neptuneDeleteNodeEdgesQuery):
		return []any{map[string]any{"total": 0}}, nil
	case strings.TrimSpace(neptuneDeleteEdgeQuery):
		id, _ := params["id"].(string)
		if err := GraphStore(b.graph).DeleteEdge(ctx, strings.TrimSpace(id)); err != nil {
			return nil, err
		}
		return []any{map[string]any{"total": 1}}, nil
	case strings.TrimSpace(neptuneLookupNodeQuery):
		id, _ := params["id"].(string)
		if node, ok := b.graph.GetNode(strings.TrimSpace(id)); ok {
			return []any{map[string]any{"node": benchmarkNeptuneNodeRecord(node)}}, nil
		}
		return nil, nil
	case strings.TrimSpace(neptuneLookupEdgeQuery):
		id, _ := params["id"].(string)
		if edge := benchmarkLookupActiveEdge(b.graph, strings.TrimSpace(id)); edge != nil {
			return []any{map[string]any{"edge": benchmarkNeptuneEdgeRecord(edge)}}, nil
		}
		return nil, nil
	case strings.TrimSpace(neptuneLookupOutEdgesQuery):
		nodeID, _ := params["node_id"].(string)
		return benchmarkNeptuneEdgeRows(b.graph.GetOutEdges(strings.TrimSpace(nodeID))), nil
	case strings.TrimSpace(neptuneLookupInEdgesQuery):
		nodeID, _ := params["node_id"].(string)
		return benchmarkNeptuneEdgeRows(b.graph.GetInEdges(strings.TrimSpace(nodeID))), nil
	case strings.TrimSpace(neptuneLookupNodesByKindQuery):
		return benchmarkNeptuneLookupNodesByKindRows(b.graph, params["kinds"]), nil
	case strings.TrimSpace(neptuneCountNodesQuery):
		return []any{map[string]any{"total": b.graph.NodeCount()}}, nil
	case strings.TrimSpace(neptuneCountEdgesQuery):
		return []any{map[string]any{"total": b.graph.EdgeCount()}}, nil
	case strings.TrimSpace(neptuneSnapshotNodesQuery):
		return benchmarkNeptuneNodeRows(b.graph.GetAllNodes()), nil
	case strings.TrimSpace(neptuneSnapshotEdgesQuery):
		return benchmarkNeptuneEdgeRows(benchmarkAllActiveEdges(b.graph)), nil
	}

	if strings.Contains(trimmed, "CREATE INDEX") {
		return []any{map[string]any{"total": 0}}, nil
	}
	if strings.Contains(trimmed, "UNWIND nodes(p) AS n") || strings.Contains(trimmed, "UNWIND relationships(p) AS r") {
		view, err := benchmarkNeptuneSubgraphForQuery(b.graph, trimmed, params)
		if err != nil {
			return nil, err
		}
		if strings.Contains(trimmed, "UNWIND nodes(p) AS n") {
			return benchmarkTraversalNodeRows(view), nil
		}
		return benchmarkTraversalEdgeRows(view), nil
	}

	return nil, fmt.Errorf("unexpected benchmark neptune query: %s", trimmed)
}

func benchmarkNeptuneRowParams(params map[string]any) []map[string]any {
	rows, _ := params["rows"].([]map[string]any)
	if rows != nil {
		return rows
	}
	rawRows, _ := params["rows"].([]any)
	out := make([]map[string]any, 0, len(rawRows))
	for _, raw := range rawRows {
		record, ok := raw.(map[string]any)
		if ok {
			out = append(out, record)
		}
	}
	return out
}

func benchmarkAllActiveEdges(g *Graph) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edges := make([]*Edge, 0, len(g.edgeByID))
	for _, edge := range g.edgeByID {
		if g.activeEdgeLocked(edge) {
			edges = append(edges, edge)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})
	return edges
}

func benchmarkLookupActiveEdge(g *Graph, id string) *Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	edge := g.edgeByID[id]
	if !g.activeEdgeLocked(edge) {
		return nil
	}
	return edge
}

func benchmarkNeptuneNodeRows(nodes []*Node) []any {
	sorted := append([]*Node(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	rows := make([]any, 0, len(sorted))
	for _, node := range sorted {
		rows = append(rows, map[string]any{"node": benchmarkNeptuneNodeRecord(node)})
	}
	return rows
}

func benchmarkNeptuneEdgeRows(edges []*Edge) []any {
	sorted := append([]*Edge(nil), edges...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	rows := make([]any, 0, len(sorted))
	for _, edge := range sorted {
		rows = append(rows, map[string]any{"edge": benchmarkNeptuneEdgeRecord(edge)})
	}
	return rows
}

func benchmarkNeptuneLookupNodesByKindRows(g *Graph, rawKinds any) []any {
	var kinds []NodeKind
	switch typed := rawKinds.(type) {
	case []string:
		for _, kind := range typed {
			kinds = append(kinds, NodeKind(kind))
		}
	case []any:
		for _, kind := range typed {
			text, _ := kind.(string)
			if strings.TrimSpace(text) != "" {
				kinds = append(kinds, NodeKind(text))
			}
		}
	}
	return benchmarkNeptuneNodeRows(g.GetNodesByKind(kinds...))
}

func benchmarkNeptuneSubgraphForQuery(g *Graph, query string, params map[string]any) (*Graph, error) {
	rootID, _ := params["root_id"].(string)
	if strings.TrimSpace(rootID) == "" {
		return New(), nil
	}
	maxDepth, err := benchmarkTraversalDepthFromQuery(query)
	if err != nil {
		return nil, err
	}
	direction, err := benchmarkTraversalDirectionFromQuery(query)
	if err != nil {
		return nil, err
	}
	return ExtractSubgraph(g, rootID, ExtractSubgraphOptions{
		MaxDepth:  maxDepth,
		Direction: direction,
	}), nil
}

func benchmarkTraversalNodeRows(g *Graph) []any {
	nodes := append([]*Node(nil), g.GetAllNodes()...)
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	rows := make([]any, 0, len(nodes))
	for _, node := range nodes {
		rows = append(rows, map[string]any{"node": benchmarkNeptuneNodeRecord(node)})
	}
	return rows
}

func benchmarkTraversalEdgeRows(g *Graph) []any {
	edges := make([]*Edge, 0)
	for _, edgeList := range g.GetAllEdges() {
		edges = append(edges, edgeList...)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})
	rows := make([]any, 0, len(edges))
	for _, edge := range edges {
		rows = append(rows, map[string]any{"edge": benchmarkNeptuneEdgeRecord(edge)})
	}
	return rows
}

func benchmarkNeptuneNodeRecord(node *Node) map[string]any {
	params := neptuneNodeParams(cloneNode(node))
	return map[string]any{
		"id":                       params["id"],
		"kind":                     params["kind"],
		"name":                     params["name"],
		"tenant_id":                params["tenant_id"],
		"provider":                 params["provider"],
		"account":                  params["account"],
		"region":                   params["region"],
		"properties_json":          params["properties_json"],
		"tags_json":                params["tags_json"],
		"risk":                     params["risk"],
		"findings_json":            params["findings_json"],
		"created_at":               params["created_at"],
		"updated_at":               params["updated_at"],
		"deleted_at":               params["deleted_at"],
		"version":                  params["version"],
		"previous_properties_json": params["previous_properties_json"],
		"property_history_json":    params["property_history_json"],
	}
}

func benchmarkNeptuneEdgeRecord(edge *Edge) map[string]any {
	params := neptuneEdgeParams(cloneEdge(edge))
	return map[string]any{
		"id":              params["id"],
		"source":          params["source"],
		"target":          params["target"],
		"kind":            params["kind"],
		"effect":          params["effect"],
		"priority":        params["priority"],
		"properties_json": params["properties_json"],
		"risk":            params["risk"],
		"created_at":      params["created_at"],
		"deleted_at":      params["deleted_at"],
		"version":         params["version"],
	}
}

var benchmarkTraversalDepthPattern = regexp.MustCompile(`\*0\.\.(\d+)`)

func benchmarkTraversalDepthFromQuery(query string) (int, error) {
	matches := benchmarkTraversalDepthPattern.FindStringSubmatch(query)
	if len(matches) != 2 {
		return 0, fmt.Errorf("missing traversal depth in query: %s", query)
	}
	var depth int
	if _, err := fmt.Sscanf(matches[1], "%d", &depth); err != nil {
		return 0, fmt.Errorf("parse traversal depth %q: %w", matches[1], err)
	}
	return depth, nil
}

func benchmarkTraversalDirectionFromQuery(query string) (ExtractSubgraphDirection, error) {
	switch {
	case strings.Contains(query, "<-[:"+neptuneEdgeType+"*0.."):
		return ExtractSubgraphDirectionIncoming, nil
	case strings.Contains(query, "-[:"+neptuneEdgeType+"*0..") && strings.Contains(query, "]->"):
		return ExtractSubgraphDirectionOutgoing, nil
	case strings.Contains(query, "-[:"+neptuneEdgeType+"*0..") && strings.Contains(query, "]-("):
		return ExtractSubgraphDirectionBoth, nil
	default:
		return 0, fmt.Errorf("unknown traversal direction for query: %s", query)
	}
}
