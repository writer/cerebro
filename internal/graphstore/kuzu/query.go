package kuzu

import (
	"context"
	"database/sql"
	"encoding/json"
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
	if s == nil || s.db == nil {
		return nil, errors.New("kuzu is not configured")
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return nil, err
	}
	if !tables["entity"] {
		return nil, fmt.Errorf("%w: %s", ports.ErrGraphEntityNotFound, normalizedRootURN)
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
	if !tables["relation"] || limit <= 0 {
		return neighborhood, nil
	}
	neighbors := make(map[string]*ports.NeighborhoodNode)
	relations := make(map[string]*ports.NeighborhoodRelation)
	remaining, err := s.collectNeighborhoodRows(ctx, fmt.Sprintf(
		"MATCH (root:entity {urn: %s})-[r:relation]->(neighbor:entity) "+
			"RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label, root.urn AS from_urn, r.relation AS relation_type, neighbor.urn AS to_urn, r.attributes_json AS attributes_json "+
			"ORDER BY neighbor.urn, r.relation LIMIT %d",
		cypherString(normalizedRootURN),
		limit,
	), limit, neighbors, relations)
	if err != nil {
		return nil, err
	}
	if remaining > 0 {
		if _, err := s.collectNeighborhoodRows(ctx, fmt.Sprintf(
			"MATCH (neighbor:entity)-[r:relation]->(root:entity {urn: %s}) "+
				"RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label, neighbor.urn AS from_urn, r.relation AS relation_type, root.urn AS to_urn, r.attributes_json AS attributes_json "+
				"ORDER BY neighbor.urn, r.relation LIMIT %d",
			cypherString(normalizedRootURN),
			remaining,
		), remaining, neighbors, relations); err != nil {
			return nil, err
		}
	}
	neighborhood.Neighbors = neighborhoodNodes(neighbors)
	neighborhood.Relations = neighborhoodRelations(relations)
	return neighborhood, nil
}

func (s *Store) lookupNeighborhoodNode(ctx context.Context, rootURN string) (*ports.NeighborhoodNode, error) {
	node := &ports.NeighborhoodNode{}
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		"MATCH (e:entity {urn: %s}) RETURN e.urn, e.entity_type, e.label",
		cypherString(rootURN),
	)).Scan(&node.URN, &node.EntityType, &node.Label); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrGraphEntityNotFound, rootURN)
		}
		return nil, fmt.Errorf("query graph root %q: %w", rootURN, err)
	}
	return node, nil
}

func (s *Store) collectNeighborhoodRows(ctx context.Context, query string, remaining int, neighbors map[string]*ports.NeighborhoodNode, relations map[string]*ports.NeighborhoodRelation) (_ int, err error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return remaining, fmt.Errorf("query graph neighborhood: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close graph neighborhood rows: %w", closeErr)
		}
	}()
	for rows.Next() {
		var neighbor ports.NeighborhoodNode
		var relation ports.NeighborhoodRelation
		var attributesJSON string
		if err := rows.Scan(
			&neighbor.URN,
			&neighbor.EntityType,
			&neighbor.Label,
			&relation.FromURN,
			&relation.Relation,
			&relation.ToURN,
			&attributesJSON,
		); err != nil {
			return remaining, fmt.Errorf("scan graph neighborhood row: %w", err)
		}
		attributes, err := decodeGraphAttributes(attributesJSON)
		if err != nil {
			return remaining, fmt.Errorf("decode graph neighborhood relation attributes: %w", err)
		}
		relation.Attributes = attributes
		neighbors[neighbor.URN] = &neighbor
		relations[relation.FromURN+"|"+relation.Relation+"|"+relation.ToURN] = &relation
		remaining--
		if remaining == 0 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return remaining, fmt.Errorf("iterate graph neighborhood rows: %w", err)
	}
	return remaining, nil
}

func decodeGraphAttributes(payload string) (map[string]string, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" || trimmed == "{}" {
		return nil, nil
	}
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(trimmed), &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
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
