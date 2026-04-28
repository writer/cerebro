package neo4j

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

// GetEntityNeighborhood returns one bounded root-centered graph neighborhood.
func (s *Store) GetEntityNeighborhood(ctx context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	normalizedRootURN := strings.TrimSpace(rootURN)
	if normalizedRootURN == "" {
		return nil, errors.New("root urn is required")
	}
	if err := s.requireDriver(); err != nil {
		return nil, err
	}
	root, err := s.lookupNeighborhoodNode(ctx, normalizedRootURN)
	if err != nil {
		return nil, err
	}
	neighborhood := &ports.EntityNeighborhood{
		Root:      root,
		Neighbors: []*ports.NeighborhoodNode{},
		Relations: []*ports.NeighborhoodRelation{},
	}
	if limit <= 0 {
		return neighborhood, nil
	}
	neighbors := make(map[string]*ports.NeighborhoodNode)
	relations := make(map[string]*ports.NeighborhoodRelation)
	remaining, err := s.collectNeighborhoodRows(ctx,
		"MATCH (root:entity {urn: $root_urn})-[r:relation]->(neighbor:entity) "+
			"RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label, root.urn AS from_urn, r.relation AS relation_type, neighbor.urn AS to_urn "+
			"ORDER BY neighbor.urn, r.relation LIMIT $limit",
		map[string]any{"root_urn": normalizedRootURN, "limit": limit},
		limit,
		neighbors,
		relations,
	)
	if err != nil {
		return nil, err
	}
	if remaining > 0 {
		if _, err := s.collectNeighborhoodRows(ctx,
			"MATCH (neighbor:entity)-[r:relation]->(root:entity {urn: $root_urn}) "+
				"RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label, neighbor.urn AS from_urn, r.relation AS relation_type, root.urn AS to_urn "+
				"ORDER BY neighbor.urn, r.relation LIMIT $limit",
			map[string]any{"root_urn": normalizedRootURN, "limit": remaining},
			remaining,
			neighbors,
			relations,
		); err != nil {
			return nil, err
		}
	}
	neighborhood.Neighbors = neighborhoodNodes(neighbors)
	neighborhood.Relations = neighborhoodRelations(relations)
	return neighborhood, nil
}

func (s *Store) lookupNeighborhoodNode(ctx context.Context, rootURN string) (*ports.NeighborhoodNode, error) {
	records, err := s.readRecords(ctx,
		"MATCH (e:entity {urn: $root_urn}) RETURN e.urn AS urn, e.entity_type AS entity_type, e.label AS label",
		map[string]any{"root_urn": rootURN},
	)
	if err != nil {
		return nil, fmt.Errorf("query graph root %q: %w", rootURN, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: %s", ports.ErrGraphEntityNotFound, rootURN)
	}
	return &ports.NeighborhoodNode{
		URN:        recordString(records[0], "urn"),
		EntityType: recordString(records[0], "entity_type"),
		Label:      recordString(records[0], "label"),
	}, nil
}

func (s *Store) collectNeighborhoodRows(ctx context.Context, query string, params map[string]any, remaining int, neighbors map[string]*ports.NeighborhoodNode, relations map[string]*ports.NeighborhoodRelation) (int, error) {
	records, err := s.readRecords(ctx, query, params)
	if err != nil {
		return remaining, fmt.Errorf("query graph neighborhood: %w", err)
	}
	for _, record := range records {
		neighbor := &ports.NeighborhoodNode{
			URN:        recordString(record, "neighbor_urn"),
			EntityType: recordString(record, "neighbor_type"),
			Label:      recordString(record, "neighbor_label"),
		}
		relation := &ports.NeighborhoodRelation{
			FromURN:  recordString(record, "from_urn"),
			Relation: recordString(record, "relation_type"),
			ToURN:    recordString(record, "to_urn"),
		}
		neighbors[neighbor.URN] = neighbor
		relations[relation.FromURN+"|"+relation.Relation+"|"+relation.ToURN] = relation
		remaining--
		if remaining == 0 {
			break
		}
	}
	return remaining, nil
}

func neighborhoodNodes(values map[string]*ports.NeighborhoodNode) []*ports.NeighborhoodNode {
	nodes := make([]*ports.NeighborhoodNode, 0, len(values))
	for _, node := range values {
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(left *ports.NeighborhoodNode, right *ports.NeighborhoodNode) int {
		switch {
		case left.URN < right.URN:
			return -1
		case left.URN > right.URN:
			return 1
		default:
			return 0
		}
	})
	return nodes
}

func neighborhoodRelations(values map[string]*ports.NeighborhoodRelation) []*ports.NeighborhoodRelation {
	relations := make([]*ports.NeighborhoodRelation, 0, len(values))
	for _, relation := range values {
		relations = append(relations, relation)
	}
	slices.SortFunc(relations, func(left *ports.NeighborhoodRelation, right *ports.NeighborhoodRelation) int {
		leftKey := left.FromURN + "|" + left.Relation + "|" + left.ToURN
		rightKey := right.FromURN + "|" + right.Relation + "|" + right.ToURN
		switch {
		case leftKey < rightKey:
			return -1
		case leftKey > rightKey:
			return 1
		default:
			return 0
		}
	})
	return relations
}
