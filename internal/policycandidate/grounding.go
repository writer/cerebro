package policycandidate

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

func groundGraphEvidence(ctx context.Context, graph ports.EntityCatalogStore, tenantID string, evidence policyauthor.GraphEvidence, request GroundingRequest, now func() time.Time) (*GroundingReceipt, error) {
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
	actualNodes, graphRevision, err := currentGroundingNodes(ctx, graph, tenantID, urns)
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
			return nil, fmt.Errorf("%w: graph evidence nodes[%d]: %w", ErrInvalidRequest, index, err)
		}
	}
	actualEdges, err := currentGroundingEdges(ctx, graph, tenantID, urns, graphRevision)
	if err != nil {
		return nil, fmt.Errorf("ground policy candidate edges: %w", err)
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
			return nil, fmt.Errorf("%w: graph evidence edges[%d]: %w", ErrInvalidRequest, index, err)
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

func currentGroundingNodes(ctx context.Context, graph ports.EntityCatalogStore, tenantID string, urns []string) (map[string]currentGroundingObject, uint64, error) {
	result := make(map[string]currentGroundingObject, len(urns))
	var graphRevision uint64
	for _, urn := range urns {
		page, err := graph.ListEntities(ctx, ports.EntityCatalogPageRequest{
			Filter: ports.EntityCatalogFilter{TenantID: tenantID, ExactAgentKey: urn, ExpectedRevision: graphRevision},
			Limit:  1,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("ground policy candidate node %q: %w", urn, err)
		}
		if page == nil || page.TenantID != tenantID || page.GraphRevision == 0 || page.Truncated || len(page.Entities) != 1 || page.Entities[0].URN != urn || page.Entities[0].TenantID != tenantID {
			return nil, 0, fmt.Errorf("%w: current graph did not resolve exactly one bound node", ErrInvalidRequest)
		}
		if graphRevision == 0 {
			graphRevision = page.GraphRevision
		} else if page.GraphRevision != graphRevision {
			return nil, 0, fmt.Errorf("%w: current graph revision changed during grounding", ErrInvalidRequest)
		}
		entity := page.Entities[0]
		attributes := make(map[string]any, len(entity.Attributes))
		for key, value := range entity.Attributes {
			attributes[key] = value
		}
		result[urn] = currentGroundingObject{entityType: strings.TrimSpace(entity.EntityType), sourceID: strings.TrimSpace(entity.SourceID), attributes: attributes}
	}
	return result, graphRevision, nil
}

func currentGroundingEdges(ctx context.Context, graph ports.EntityCatalogStore, tenantID string, urns []string, graphRevision uint64) (map[string]currentGroundingObject, error) {
	result := make(map[string]currentGroundingObject)
	boundURNs := make(map[string]struct{}, len(urns))
	for _, urn := range urns {
		boundURNs[urn] = struct{}{}
	}
	rowCount := 0
	for _, fromURN := range urns {
		request := ports.EntityRelationPageRequest{
			TenantID: tenantID, AgentKey: fromURN, Directions: []ports.EntityRelationDirection{ports.EntityRelationOutgoing},
			NeighborAgentKeys: append([]string(nil), urns...), ExpectedRevision: graphRevision,
		}
		for {
			request.Limit = min(500, MaxGroundingRows-rowCount)
			page, err := graph.ListEntityRelations(ctx, request)
			if err != nil {
				return nil, err
			}
			if page == nil || page.TenantID != tenantID || page.GraphRevision != graphRevision || len(page.Relations) > request.Limit {
				return nil, fmt.Errorf("%w: current graph returned an invalid relation page", ErrInvalidRequest)
			}
			for _, relation := range page.Relations {
				if relation.Direction != ports.EntityRelationOutgoing || relation.Entity.TenantID != tenantID || strings.TrimSpace(relation.Relation) == "" {
					return nil, fmt.Errorf("%w: current graph relation omitted identity fields", ErrInvalidRequest)
				}
				if _, ok := boundURNs[relation.Entity.URN]; !ok {
					return nil, fmt.Errorf("%w: current graph relation escaped the bound evidence set", ErrInvalidRequest)
				}
				attributes, err := groundingAttributes(relation.AttributesJSON)
				if err != nil {
					return nil, fmt.Errorf("%w: current graph edge attributes: %w", ErrInvalidRequest, err)
				}
				key := groundingEdgeKey(fromURN, relation.Entity.URN, relation.Relation)
				current := currentGroundingObject{sourceID: strings.TrimSpace(relation.SourceID), attributes: attributes}
				if previous, exists := result[key]; exists && (previous.sourceID != current.sourceID || !reflect.DeepEqual(previous.attributes, current.attributes)) {
					return nil, fmt.Errorf("%w: current graph returned conflicting duplicate relation identities", ErrInvalidRequest)
				}
				result[key] = current
			}
			rowCount += len(page.Relations)
			if rowCount >= MaxGroundingRows {
				return nil, fmt.Errorf("%w: current graph edge grounding reached its bounded row limit", ErrInvalidRequest)
			}
			if !page.Truncated {
				break
			}
			if page.NextAfterAgentKey == "" || page.NextAfterRelation == "" || page.NextAfterDirection == "" {
				return nil, fmt.Errorf("%w: current graph relation continuation is incomplete", ErrInvalidRequest)
			}
			request.AfterAgentKey = page.NextAfterAgentKey
			request.AfterRelation = page.NextAfterRelation
			request.AfterDirection = page.NextAfterDirection
		}
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

func groundingEdgeKey(fromURN string, toURN string, relation string) string {
	return strings.TrimSpace(fromURN) + "\x00" + strings.TrimSpace(relation) + "\x00" + strings.TrimSpace(toURN)
}
