package policycandidate

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

const groundingNodesQuery = `MATCH (e:Entity {tenant_id: $tenant_id})
WHERE e.urn IN $entity_urns
RETURN e.urn AS urn, e.entity_type AS entity_type, e.source_id AS source_id, coalesce(e.attributes_json, '{}') AS attributes_json
ORDER BY urn
LIMIT $row_limit`

const groundingEdgesQuery = `MATCH (source:Entity {tenant_id: $tenant_id})-[edge:RELATION]->(target:Entity {tenant_id: $tenant_id})
WHERE source.urn IN $entity_urns AND target.urn IN $entity_urns
RETURN source.urn AS from_urn, target.urn AS to_urn, edge.relation AS relation, edge.source_id AS source_id, coalesce(edge.attributes_json, '{}') AS attributes_json
ORDER BY from_urn, relation, to_urn
LIMIT $row_limit`

func groundGraphEvidence(ctx context.Context, graph ports.GraphQueryStore, tenantID string, evidence policyauthor.GraphEvidence, request GroundingRequest, now func() time.Time) (*GroundingReceipt, error) {
	if err := validateMultiHopEvidence(evidence); err != nil {
		return nil, err
	}
	if graph == nil {
		return nil, ErrGraphUnavailable
	}
	bindings, urns, err := validateGroundingBindings(tenantID, evidence, request)
	if err != nil {
		return nil, err
	}
	nodeRows, err := graph.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: groundingNodesQuery, Params: map[string]any{
		"tenant_id": tenantID, "entity_urns": urns, "row_limit": MaxGroundingNodes + 1,
	}, RowLimit: MaxGroundingNodes + 1})
	if err != nil {
		return nil, fmt.Errorf("ground policy candidate nodes: %w", err)
	}
	actualNodes, err := currentGroundingNodes(nodeRows)
	if err != nil {
		return nil, err
	}
	if len(actualNodes) != len(evidence.Nodes) {
		return nil, fmt.Errorf("%w: current graph resolved %d of %d declared nodes", ErrInvalidRequest, len(actualNodes), len(evidence.Nodes))
	}
	for index, node := range evidence.Nodes {
		actual, ok := actualNodes[bindings[node.ID]]
		if !ok {
			return nil, fmt.Errorf("%w: graph evidence nodes[%d] is absent from current graph", ErrInvalidRequest, index)
		}
		if actual.entityType != strings.TrimSpace(node.EntityType) || actual.sourceID != strings.TrimSpace(node.SourceID) {
			return nil, fmt.Errorf("%w: graph evidence nodes[%d] type or source does not match current graph", ErrInvalidRequest, index)
		}
		if err := requireGroundedAttributes(node.Attributes, actual.attributes); err != nil {
			return nil, fmt.Errorf("%w: graph evidence nodes[%d]: %v", ErrInvalidRequest, index, err)
		}
	}
	edgeRows, err := graph.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: groundingEdgesQuery, Params: map[string]any{
		"tenant_id": tenantID, "entity_urns": urns, "row_limit": MaxGroundingRows,
	}, RowLimit: MaxGroundingRows})
	if err != nil {
		return nil, fmt.Errorf("ground policy candidate edges: %w", err)
	}
	if len(edgeRows) >= MaxGroundingRows {
		return nil, fmt.Errorf("%w: current graph edge grounding reached its bounded row limit", ErrInvalidRequest)
	}
	actualEdges, err := currentGroundingEdges(edgeRows)
	if err != nil {
		return nil, err
	}
	for index, edge := range evidence.Edges {
		key := groundingEdgeKey(bindings[edge.FromID], bindings[edge.ToID], edge.Relation)
		actual, ok := actualEdges[key]
		if !ok {
			return nil, fmt.Errorf("%w: graph evidence edges[%d] is absent from current graph", ErrInvalidRequest, index)
		}
		if actual.sourceID != strings.TrimSpace(edge.SourceID) {
			return nil, fmt.Errorf("%w: graph evidence edges[%d] source does not match current graph", ErrInvalidRequest, index)
		}
		if err := requireGroundedAttributes(edge.Attributes, actual.attributes); err != nil {
			return nil, fmt.Errorf("%w: graph evidence edges[%d]: %v", ErrInvalidRequest, index, err)
		}
	}
	receiptID, err := newID()
	if err != nil {
		return nil, fmt.Errorf("create grounding receipt id: %w", err)
	}
	return &GroundingReceipt{
		Execution: "graph_store", NodeCount: len(evidence.Nodes), EdgeCount: len(evidence.Edges),
		ReceiptID: "ground_" + strings.TrimPrefix(receiptID, "pc_"), ObservedAt: now(),
	}, nil
}

func validateMultiHopEvidence(evidence policyauthor.GraphEvidence) error {
	if len(evidence.Nodes) < 3 || len(evidence.Nodes) > MaxGroundingNodes || len(evidence.Edges) < 2 || len(evidence.Edges) > MaxGroundingEdges {
		return fmt.Errorf("%w: graph evidence must contain 3-%d distinct nodes and 2-%d connected edges", ErrInvalidRequest, MaxGroundingNodes, MaxGroundingEdges)
	}
	nodes := make(map[string]struct{}, len(evidence.Nodes))
	for _, node := range evidence.Nodes {
		id := strings.TrimSpace(node.ID)
		if id == "" {
			return fmt.Errorf("%w: graph evidence node IDs are required", ErrInvalidRequest)
		}
		if _, exists := nodes[id]; exists {
			return fmt.Errorf("%w: graph evidence node %q is duplicated", ErrInvalidRequest, id)
		}
		nodes[id] = struct{}{}
	}
	criticalFrom := strings.TrimSpace(evidence.CriticalEdge.FromID)
	criticalTo := strings.TrimSpace(evidence.CriticalEdge.ToID)
	criticalRelation := strings.TrimSpace(evidence.CriticalEdge.Relation)
	criticalFound := false
	pathIncludesCritical := false
	for _, edge := range evidence.Edges {
		fromID := strings.TrimSpace(edge.FromID)
		toID := strings.TrimSpace(edge.ToID)
		if fromID == toID {
			return fmt.Errorf("%w: graph evidence self-edges are not causal hops", ErrInvalidRequest)
		}
		if _, ok := nodes[fromID]; !ok {
			return fmt.Errorf("%w: graph evidence edge references an undeclared source node", ErrInvalidRequest)
		}
		if _, ok := nodes[toID]; !ok {
			return fmt.Errorf("%w: graph evidence edge references an undeclared target node", ErrInvalidRequest)
		}
		if fromID == criticalFrom && toID == criticalTo && strings.TrimSpace(edge.Relation) == criticalRelation {
			criticalFound = true
		}
	}
	if !criticalFound {
		return fmt.Errorf("%w: critical edge must identify one declared evidence edge", ErrInvalidRequest)
	}
	for _, edge := range evidence.Edges {
		fromID := strings.TrimSpace(edge.FromID)
		toID := strings.TrimSpace(edge.ToID)
		if (toID == criticalFrom && fromID != criticalTo) || (fromID == criticalTo && toID != criticalFrom) {
			pathIncludesCritical = true
			break
		}
	}
	if !pathIncludesCritical {
		return fmt.Errorf("%w: graph evidence must contain a directed path of at least two hops including the critical edge", ErrInvalidRequest)
	}
	return nil
}

func validateGroundingBindings(tenantID string, evidence policyauthor.GraphEvidence, request GroundingRequest) (map[string]string, []string, error) {
	if len(request.Bindings) != len(evidence.Nodes) {
		return nil, nil, fmt.Errorf("%w: grounding requires exactly one binding per graph evidence node", ErrInvalidRequest)
	}
	declared := make(map[string]struct{}, len(evidence.Nodes))
	for _, node := range evidence.Nodes {
		declared[strings.TrimSpace(node.ID)] = struct{}{}
	}
	bindings := make(map[string]string, len(request.Bindings))
	seenURNs := make(map[string]struct{}, len(request.Bindings))
	urns := make([]string, 0, len(request.Bindings))
	prefix := "urn:cerebro:" + strings.TrimSpace(tenantID) + ":"
	for index, binding := range request.Bindings {
		nodeID := strings.TrimSpace(binding.NodeID)
		entityURN := strings.TrimSpace(binding.EntityURN)
		if _, ok := declared[nodeID]; !ok || !strings.HasPrefix(entityURN, prefix) {
			return nil, nil, fmt.Errorf("%w: grounding bindings[%d] must map a declared node to a tenant-scoped Cerebro URN", ErrInvalidRequest, index)
		}
		if _, exists := bindings[nodeID]; exists {
			return nil, nil, fmt.Errorf("%w: grounding node %q is bound more than once", ErrInvalidRequest, nodeID)
		}
		if _, exists := seenURNs[entityURN]; exists {
			return nil, nil, fmt.Errorf("%w: grounding entity URN is bound more than once", ErrInvalidRequest)
		}
		bindings[nodeID] = entityURN
		seenURNs[entityURN] = struct{}{}
		urns = append(urns, entityURN)
	}
	return bindings, urns, nil
}

type currentGroundingObject struct {
	entityType string
	sourceID   string
	attributes map[string]any
}

func currentGroundingNodes(rows []ports.CypherRow) (map[string]currentGroundingObject, error) {
	result := make(map[string]currentGroundingObject, len(rows))
	for _, row := range rows {
		urn := groundingRowString(row, "urn")
		if urn == "" {
			return nil, fmt.Errorf("%w: current graph node row omitted urn", ErrInvalidRequest)
		}
		attributes, err := groundingAttributes(row.Values["attributes_json"])
		if err != nil {
			return nil, fmt.Errorf("%w: current graph node attributes: %v", ErrInvalidRequest, err)
		}
		result[urn] = currentGroundingObject{entityType: groundingRowString(row, "entity_type"), sourceID: groundingRowString(row, "source_id"), attributes: attributes}
	}
	return result, nil
}

func currentGroundingEdges(rows []ports.CypherRow) (map[string]currentGroundingObject, error) {
	result := make(map[string]currentGroundingObject, len(rows))
	for _, row := range rows {
		fromURN := groundingRowString(row, "from_urn")
		toURN := groundingRowString(row, "to_urn")
		relation := groundingRowString(row, "relation")
		if fromURN == "" || toURN == "" || relation == "" {
			return nil, fmt.Errorf("%w: current graph edge row omitted identity fields", ErrInvalidRequest)
		}
		attributes, err := groundingAttributes(row.Values["attributes_json"])
		if err != nil {
			return nil, fmt.Errorf("%w: current graph edge attributes: %v", ErrInvalidRequest, err)
		}
		result[groundingEdgeKey(fromURN, toURN, relation)] = currentGroundingObject{sourceID: groundingRowString(row, "source_id"), attributes: attributes}
	}
	return result, nil
}

func groundingAttributes(value any) (map[string]any, error) {
	switch typed := value.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return typed, nil
	case string:
		var result map[string]any
		if err := json.Unmarshal([]byte(typed), &result); err != nil {
			return nil, err
		}
		return result, nil
	case []byte:
		var result map[string]any
		if err := json.Unmarshal(typed, &result); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, fmt.Errorf("attributes_json has unsupported type %T", value)
	}
}

func requireGroundedAttributes(expected map[string]string, actual map[string]any) error {
	for key, expectedValue := range expected {
		actualValue, ok := actual[key]
		if !ok || semanticGroundingString(actualValue) != strings.TrimSpace(expectedValue) {
			return fmt.Errorf("attribute %q does not match current graph", key)
		}
	}
	return nil
}

func semanticGroundingString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	case nil:
		return ""
	default:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	}
}

func groundingRowString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	switch value := row.Values[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case []byte:
		return strings.TrimSpace(string(value))
	default:
		return ""
	}
}

func groundingEdgeKey(fromURN string, toURN string, relation string) string {
	return strings.TrimSpace(fromURN) + "\x00" + strings.TrimSpace(relation) + "\x00" + strings.TrimSpace(toURN)
}
