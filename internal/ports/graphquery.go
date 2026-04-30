package ports

import (
	"context"
	"errors"
)

// ErrGraphEntityNotFound indicates that the requested graph root entity does not exist.
var ErrGraphEntityNotFound = errors.New("graph entity not found")

// NeighborhoodNode is the normalized graph node shape returned by bounded neighborhood queries.
type NeighborhoodNode struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

// NeighborhoodRelation is the normalized graph edge shape returned by bounded neighborhood queries.
type NeighborhoodRelation struct {
	FromURN    string            `json:"from_urn"`
	Relation   string            `json:"relation"`
	ToURN      string            `json:"to_urn"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// EntityNeighborhood is one bounded graph neighborhood centered on a root entity.
type EntityNeighborhood struct {
	Root      *NeighborhoodNode       `json:"root,omitempty"`
	Neighbors []*NeighborhoodNode     `json:"neighbors"`
	Relations []*NeighborhoodRelation `json:"relations"`
}

// GraphQueryStore exposes bounded graph neighborhood reads.
type GraphQueryStore interface {
	GraphStore
	GetEntityNeighborhood(context.Context, string, int) (*EntityNeighborhood, error)
}
