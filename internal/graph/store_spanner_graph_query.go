package graph

import (
	"fmt"
	"strings"

	"cloud.google.com/go/spanner"
)

const spannerGraphStorePropertyGraphName = "cerebro_graph_store"

func spannerGraphTraversalEdgesStatement(rootID string, direction spannerTraversalDirection, maxDepth int) (spanner.Statement, error) {
	rootID = strings.TrimSpace(rootID)
	if rootID == "" {
		return spanner.Statement{}, fmt.Errorf("spanner graph traversal root id is required")
	}
	if direction != spannerTraversalDirectionOutgoing && direction != spannerTraversalDirectionIncoming {
		return spanner.Statement{}, fmt.Errorf("spanner graph traversal direction %d is not supported by the native query builder", direction)
	}

	maxHops := spannerNativeTraversalMaxHops(maxDepth)
	subqueries := make([]string, 0, maxHops*(maxHops+1)/2)
	for length := 1; length <= maxHops; length++ {
		pattern := spannerGraphTraversalPattern(direction, length)
		whereClause := spannerGraphTraversalWhereClause(length)
		for edgeIndex := 1; edgeIndex <= length; edgeIndex++ {
			subqueries = append(subqueries, fmt.Sprintf(`SELECT edge
FROM GRAPH_TABLE(
  %s
  MATCH TRAIL %s
  WHERE %s
  RETURN DISTINCT e%d AS edge
)`, spannerGraphStorePropertyGraphName, pattern, whereClause, edgeIndex))
		}
	}

	sql := fmt.Sprintf(`SELECT DISTINCT
  gt.edge.edge_id AS edge_id,
  gt.edge.source_node_id AS source_node_id,
  gt.edge.target_node_id AS target_node_id,
  gt.edge.kind AS kind,
  gt.edge.effect AS effect,
  gt.edge.priority AS priority,
  gt.edge.properties_json AS properties_json,
  gt.edge.risk AS risk,
  gt.edge.created_at AS created_at,
  gt.edge.deleted_at AS deleted_at,
  gt.edge.version AS version
FROM (
  %s
) AS gt
WHERE gt.edge.deleted_at IS NULL`, strings.Join(subqueries, "\n  UNION DISTINCT\n  "))

	return spanner.Statement{
		SQL:    sql,
		Params: map[string]any{"root_id": rootID},
	}, nil
}

func spannerNativeTraversalMaxHops(maxDepth int) int {
	return normalizeTraversalDepth(maxDepth) + 1
}

func spannerGraphTraversalPattern(direction spannerTraversalDirection, length int) string {
	segments := make([]string, 0, length*2+1)
	if direction == spannerTraversalDirectionOutgoing {
		segments = append(segments, "(n0 {node_id: @root_id})")
		for i := 1; i <= length; i++ {
			segments = append(segments, fmt.Sprintf("-[e%d]->", i))
			segments = append(segments, fmt.Sprintf("(n%d)", i))
		}
		return strings.Join(segments, "")
	}

	for i := 0; i < length; i++ {
		segments = append(segments, fmt.Sprintf("(n%d)", i))
		segments = append(segments, fmt.Sprintf("-[e%d]->", i+1))
	}
	segments = append(segments, fmt.Sprintf("(n%d {node_id: @root_id})", length))
	return strings.Join(segments, "")
}

func spannerGraphTraversalWhereClause(length int) string {
	predicates := make([]string, 0, length*2+1)
	for i := 0; i <= length; i++ {
		predicates = append(predicates, fmt.Sprintf("n%d.deleted_at IS NULL", i))
	}
	for i := 1; i <= length; i++ {
		predicates = append(predicates, fmt.Sprintf("e%d.deleted_at IS NULL", i))
	}
	return strings.Join(predicates, " AND ")
}
